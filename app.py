import os
import time
import json
import logging
import traceback
from functools import wraps
from datetime import datetime
from io import BytesIO

import numpy as np
import pandas as pd
from dotenv import load_dotenv
from bson import json_util
from flask import Flask, jsonify, request, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import requests
from requests.auth import HTTPBasicAuth
from pymongo import MongoClient
from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.chains import LLMChain
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.callbacks import get_openai_callback

# Load environment variables
load_dotenv()

# Flask app configuration
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log',
    filemode='a'
)
logger = logging.getLogger(__name__)

# Rate limiting configuration
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.getenv('REDIS_URL', 'memory://')
)

# SonarQube configuration
SONAR_URL = os.getenv('SONAR_URL')
SONAR_TOKEN = os.getenv('SONAR_TOKEN')
SONAR_PROJECT_KEY = os.getenv('SONAR_PROJECT_KEY')

# OpenAI configuration
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

# MongoDB configuration
MONGO_URI = os.getenv('MONGO_URI')
MONGO_DB = os.getenv('MONGO_DB')
MONGO_COLLECTION = os.getenv('MONGO_COLLECTION')

# Initialize MongoDB client
mongo_client = MongoClient(MONGO_URI)
db = mongo_client[MONGO_DB]
collection = db[MONGO_COLLECTION]

def timing_decorator(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        ts = time.time()
        result = f(*args, **kwargs)
        te = time.time()
        logger.info(f'Function: {f.__name__}, Time: {te-ts:2.4f} sec')
        return result
    return wrap

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super().default(obj)

app.json_encoder = CustomJSONEncoder

class SonarClient:
    def __init__(self):
        self.auth = HTTPBasicAuth(SONAR_TOKEN, '')
        self.base_url = SONAR_URL

    @timing_decorator
    def fetch_issues(self, project_key, additional_params={}):
        all_issues = []
        page = 1
        page_size = 500
        max_results = 10000

        while len(all_issues) < max_results:
            try:
                response = requests.get(
                    f"{self.base_url}/api/issues/search",
                    params={
                        "componentKeys": project_key,
                        "types": "BUG,VULNERABILITY,CODE_SMELL",
                        "resolved": "false",
                        "p": page,
                        "ps": page_size,
                        **additional_params
                    },
                    auth=self.auth
                )
                response.raise_for_status()
                data = response.json()
                issues = data['issues']
                all_issues.extend(issues)

                if len(issues) < page_size or len(all_issues) >= data['total']:
                    break

                page += 1
            except requests.RequestException as e:
                logger.error(f"Error fetching issues: {str(e)}")
                break

        return all_issues

    @timing_decorator
    def fetch_code_snippet(self, component, start_line, end_line):
        try:
            response = requests.get(
                f"{self.base_url}/api/sources/raw",
                params={
                    "key": component,
                    "from": start_line,
                    "to": end_line
                },
                auth=self.auth
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.error(f"Error fetching code snippet: {str(e)}")
            return None

sonar_client = SonarClient()

@timing_decorator
def get_ai_suggestion(issue, code_snippet):
    llm = ChatOpenAI(model_name="gpt-4", temperature=0.7, openai_api_key=OPENAI_API_KEY)
    
    template = """
    Given the following SonarQube issue and related code snippet:

    Issue:
    {issue}

    Code Snippet:
    {code_snippet}

    Provide a detailed analysis and suggestion to address this issue. Your response should include:

    1. ADJUSTED_CODE: The complete adjusted code that resolves the issue. This should be the full, corrected version of the original code snippet.

    2. EXPLANATION: A brief explanation of why this is an issue and the potential risks associated with it.

    3. STEPS_TO_FIX: A step-by-step guide on how the code was fixed.

    4. BEST_PRACTICES: Best practices to prevent similar issues in the future.

    Format your response as follows:

    ADJUSTED_CODE:
    ```
    [Place the full adjusted code here]
    ```

    EXPLANATION:
    [Your explanation here]

    STEPS_TO_FIX:
    1. [Step 1]
    2. [Step 2]
    ...

    BEST_PRACTICES:
    - [Practice 1]
    - [Practice 2]
    ...

    Your response should be thorough yet concise, suitable for a professional development team.
    """

    prompt = ChatPromptTemplate.from_template(template)

    chain = LLMChain(llm=llm, prompt=prompt)

    # Use a text splitter to divide the input into smaller chunks
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=2000,
        chunk_overlap=200,
        length_function=len,
    )

    issue_chunks = text_splitter.split_text(json.dumps(issue))
    code_chunks = text_splitter.split_text(code_snippet) if code_snippet else [""]

    suggestions = []
    total_tokens = 0
    max_tokens = 8000  # Set a maximum token limit

    with get_openai_callback() as cb:
        for i, (issue_chunk, code_chunk) in enumerate(zip(issue_chunks, code_chunks)):
            if total_tokens >= max_tokens:
                break
            chunk_suggestion = chain.run(issue=issue_chunk, code_snippet=code_chunk)
            suggestions.append(chunk_suggestion)
            total_tokens += cb.total_tokens
            logger.info(f"AI Suggestion generated for chunk {i+1} of issue: {issue.get('key', 'Unknown')}. Tokens used: {cb.total_tokens}")

    final_suggestion = " ".join(suggestions)
    logger.info(f"Total tokens used: {total_tokens}")
    return final_suggestion

@app.route('/api/issues', methods=['GET'])
@limiter.limit("10 per minute")
@timing_decorator
def get_issues():
    try:
        file = request.args.get('file')
        priority = request.args.get('priority')
        
        additional_params = {}
        if file:
            additional_params['files'] = file
        if priority:
            additional_params['severities'] = priority

        issues = sonar_client.fetch_issues(SONAR_PROJECT_KEY, additional_params)
        
        # Group by file
        issues_by_file = {}
        for issue in issues:
            file = issue['component']
            if file not in issues_by_file:
                issues_by_file[file] = []
            issues_by_file[file].append(issue)
        
        # Sort by priority within each file
        for file in issues_by_file:
            issues_by_file[file] = sorted(issues_by_file[file], key=lambda x: x.get('severity', ''), reverse=True)
        
        return jsonify(issues_by_file)
    except Exception as e:
        logger.error(f"Error in get_issues: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error", "message": str(e)}), 500

@app.route('/api/export', methods=['GET'])
@limiter.limit("5 per hour")
@timing_decorator
def export_issues():
    try:
        issues = sonar_client.fetch_issues(SONAR_PROJECT_KEY)
        
        # Convert to DataFrame
        df = pd.DataFrame(issues)
        
        # Create in-memory buffer for Excel file
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Issues', index=False)
        
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='sonarqube_issues.xlsx'
        )
    except Exception as e:
        logger.error(f"Error in export_issues: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Failed to export issues", "message": str(e)}), 500

@app.route('/api/summary', methods=['GET'])
@limiter.limit("20 per minute")
@timing_decorator
def get_summary():
    try:
        issues = sonar_client.fetch_issues(SONAR_PROJECT_KEY)
        
        summary = {
            'total': len(issues),
            'by_severity': {},
            'by_type': {}
        }

        for issue in issues:
            severity = issue.get('severity', 'UNKNOWN')
            issue_type = issue.get('type', 'UNKNOWN')
            
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            summary['by_type'][issue_type] = summary['by_type'].get(issue_type, 0) + 1

        return jsonify(summary)
    except Exception as e:
        logger.error(f"Error in get_summary: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Failed to generate summary", "message": str(e)}), 500

@app.route('/api/ai_suggest', methods=['POST'])
@limiter.limit("10 per minute")
@timing_decorator
def ai_suggest():
    try:
        issue = request.json.get('issue')
        if not issue:
            return jsonify({"error": "No issue provided"}), 400

        code_snippet = None
        if 'component' in issue and 'textRange' in issue:
            code_snippet = sonar_client.fetch_code_snippet(
                issue['component'],
                issue['textRange']['startLine'],
                issue['textRange']['endLine']
            )

        suggestion = get_ai_suggestion(issue, code_snippet)

        # Parse the suggestion to extract different parts
        parts = {}
        current_part = None
        for line in suggestion.split('\n'):
            if line.strip() in ['ADJUSTED_CODE:', 'EXPLANATION:', 'STEPS_TO_FIX:', 'BEST_PRACTICES:']:
                current_part = line.strip()[:-1]  # Remove the colon
                parts[current_part] = []
            elif current_part:
                parts[current_part].append(line)

        # Join the lines for each part
        for key in parts:
            parts[key] = '\n'.join(parts[key]).strip()

        # Extract the code from between the backticks
        if 'ADJUSTED_CODE' in parts:
            parts['ADJUSTED_CODE'] = parts['ADJUSTED_CODE'].split('```')[1].strip()

        # Store suggestion in MongoDB
        suggestion_doc = {
            "issue_key": issue.get('key'),
            "suggestion": parts,
            "timestamp": datetime.utcnow()
        }
        collection.insert_one(suggestion_doc)

        return jsonify(parts)
    except Exception as e:
        logger.error(f"Error in ai_suggest: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Failed to generate AI suggestion", "message": str(e)}), 500

@app.route('/api/suggestions/<issue_key>', methods=['GET'])
@limiter.limit("20 per minute")
@timing_decorator
def get_suggestions(issue_key):
    try:
        suggestions = list(collection.find({"issue_key": issue_key}))
        return json_util.dumps(suggestions)
    except Exception as e:
        logger.error(f"Error in get_suggestions: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Failed to retrieve suggestions", "message": str(e)}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded", "message": str(e)}), 429

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}")
    logger.error(traceback.format_exc())
    return jsonify({"error": "Internal server error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')