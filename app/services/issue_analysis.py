import pandas as pd
import numpy as np
from scipy import stats
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler
from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.chains import LLMChain
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.callbacks import get_openai_callback
from config import Config

def get_issues_over_time(issues):
    df = pd.DataFrame(issues)
    df['creationDate'] = pd.to_datetime(df['creationDate'])
    issues_per_day = df.groupby(df['creationDate'].dt.date).size().reset_index(name='count')
    issues_per_day['creationDate'] = issues_per_day['creationDate'].astype(str)
    return issues_per_day.to_dict(orient='records')

def get_component_hotspots(issues):
    df = pd.DataFrame(issues)
    component_issues = df['component'].value_counts().head(10)
    return [{'component': comp, 'issues': int(count)} for comp, count in component_issues.items()]

def get_severity_correlation(issues):
    df = pd.DataFrame(issues)
    severity_order = ['INFO', 'MINOR', 'MAJOR', 'CRITICAL', 'BLOCKER']
    df['severity_num'] = pd.Categorical(df['severity'], categories=severity_order, ordered=True).codes

    if 'effort' not in df.columns or df['effort'].isnull().all():
        return {'error': 'No effort data available'}

    df['effort_minutes'] = df['effort'].apply(lambda x: int(x.split('min')[0]) if isinstance(x, str) and 'min' in x else np.nan)

    if df['effort_minutes'].isnull().all():
        return {'error': 'Could not parse effort data'}

    correlation = stats.spearmanr(df['severity_num'], df['effort_minutes'], nan_policy='omit')
    return {'correlation_coefficient': correlation.correlation, 'p_value': correlation.pvalue}

def predict_issue_resolution(issues):
    df = pd.DataFrame(issues)
    df['creationDate'] = pd.to_datetime(df['creationDate'])
    df['updateDate'] = pd.to_datetime(df['updateDate'])
    df['resolution_time'] = (df['updateDate'] - df['creationDate']).dt.total_seconds() / 3600  # in hours

    features = pd.get_dummies(df[['type', 'severity']])
    target = df['resolution_time'].fillna(df['resolution_time'].mean())

    if len(features) == 0 or len(target) == 0:
        return {'error': 'Not enough data for prediction'}

    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)

    model = LinearRegression()
    model.fit(features_scaled, target)

    feature_importance = pd.DataFrame({
        'feature': features.columns,
        'importance': model.coef_
    }).sort_values('importance', ascending=False)

    return feature_importance.head(10).to_dict(orient='records')

def get_code_quality_trend(issues):
    df = pd.DataFrame(issues)
    df['creationDate'] = pd.to_datetime(df['creationDate'])
    weekly_issues = df.groupby(df['creationDate'].dt.to_period('W')).size().reset_index(name='count')
    weekly_issues['week'] = weekly_issues['creationDate'].dt.start_time.astype(str)

    if len(weekly_issues) < 2:
        return {'error': 'Not enough data for trend analysis'}

    x = range(len(weekly_issues))
    y = weekly_issues['count']
    trend = stats.linregress(x, y)

    return {
        'slope': trend.slope,
        'intercept': trend.intercept,
        'r_value': trend.rvalue,
        'p_value': trend.pvalue,
        'trend': 'Improving' if trend.slope < 0 else 'Deteriorating',
        'weekly_data': weekly_issues[['week', 'count']].to_dict(orient='records')
    }

def get_ai_suggestion(issue, code_snippet):
    llm = ChatOpenAI(model_name="gpt-4", temperature=0.7, openai_api_key=Config.OPENAI_API_KEY)

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

    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=2000,
        chunk_overlap=200,
        length_function=len,
    )

    issue_chunks = text_splitter.split_text(str(issue))
    code_chunks = text_splitter.split_text(code_snippet) if code_snippet else [""]

    suggestions = []
    total_tokens = 0
    max_tokens = 8000

    with get_openai_callback() as cb:
        for i, (issue_chunk, code_chunk) in enumerate(zip(issue_chunks, code_chunks)):
            if total_tokens >= max_tokens:
                break
            chunk_suggestion = chain.run(issue=issue_chunk, code_snippet=code_chunk)
            suggestions.append(chunk_suggestion)
            total_tokens += cb.total_tokens

    final_suggestion = " ".join(suggestions)
    return final_suggestion