from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import User, Project, Suggestion
from app.auth import project_access_required
from app.sonar_client import sonar_client
from app.services.issue_analysis import get_ai_suggestion

bp = Blueprint('suggestions', __name__, url_prefix='/api/suggestions')

@bp.route('/', methods=['POST'])
@jwt_required()
@project_access_required('write')
def create_suggestion(project_id):
    project = Project.objects.get(id=project_id)
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

    suggestion_doc = Suggestion(
        issue_key=issue.get('key'),
        suggestion=suggestion,
        project=project
    ).save()

    return jsonify(suggestion_doc), 201

@bp.route('/<issue_key>', methods=['GET'])
@jwt_required()
@project_access_required('read')
def get_suggestions(project_id, issue_key):
    project = Project.objects.get(id=project_id)
    suggestions = Suggestion.objects(project=project, issue_key=issue_key)
    return jsonify(suggestions), 200

@bp.route('/stats', methods=['GET'])
@jwt_required()
@project_access_required('read')
def get_suggestion_stats(project_id):
    project = Project.objects.get(id=project_id)
    stats = Suggestion.objects(project=project).aggregate([
        {
            "$group": {
                "_id": None,
                "total_suggestions": {"$sum": 1},
                "unique_issues": {"$addToSet": "$issue_key"},
                "latest_suggestion": {"$max": "$created_at"}
            }
        },
        {
            "$project": {
                "_id": 0,
                "total_suggestions": 1,
                "unique_issues_count": {"$size": "$unique_issues"},
                "latest_suggestion": 1
            }
        }
    ])
    return jsonify(list(stats)[0] if stats else {}), 200

@bp.route('/recent', methods=['GET'])
@jwt_required()
@project_access_required('read')
def get_recent_suggestions(project_id):
    project = Project.objects.get(id=project_id)
    limit = int(request.args.get('limit', 10))
    recent_suggestions = Suggestion.objects(project=project).order_by('-created_at').limit(limit)
    return jsonify(recent_suggestions), 200

@bp.route('/search', methods=['GET'])
@jwt_required()
@project_access_required('read')
def search_suggestions(project_id):
    project = Project.objects.get(id=project_id)
    query = request.args.get('q', '')
    if not query:
        return jsonify({"error": "No search query provided"}), 400

    suggestions = Suggestion.objects(project=project, suggestion__icontains=query)
    return jsonify(suggestions), 200