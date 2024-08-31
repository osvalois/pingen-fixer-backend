from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import User, Project, UserProjectAccess
from app.auth import project_access_required
from app.sonar_client import sonar_client
from app.services.issue_analysis import get_issues_over_time, get_component_hotspots, get_severity_correlation, predict_issue_resolution, get_code_quality_trend
from io import BytesIO
import pandas as pd

bp = Blueprint('issues', __name__, url_prefix='/api/issues')

@bp.route('/', methods=['GET'])
@jwt_required()
@project_access_required('read')
def get_issues(project_id):
    project = Project.objects.get(id=project_id)
    file = request.args.get('file')
    priority = request.args.get('priority')

    additional_params = {}
    if file:
        additional_params['files'] = file
    if priority:
        additional_params['severities'] = priority

    issues = sonar_client.fetch_issues(project.sonar_project_key, additional_params)

    issues_by_file = {}
    for issue in issues:
        file = issue['component']
        if file not in issues_by_file:
            issues_by_file[file] = []
        issues_by_file[file].append(issue)

    for file in issues_by_file:
        issues_by_file[file] = sorted(issues_by_file[file], key=lambda x: x.get('severity', ''), reverse=True)

    return jsonify(issues_by_file)

@bp.route('/export', methods=['GET'])
@jwt_required()
@project_access_required('read')
def export_issues(project_id):
    project = Project.objects.get(id=project_id)
    issues = sonar_client.fetch_issues(project.sonar_project_key)

    df = pd.DataFrame(issues)

    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Issues', index=False)

    output.seek(0)

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'{project.name}_sonarqube_issues.xlsx'
    )

@bp.route('/summary', methods=['GET'])
@jwt_required()
@project_access_required('read')
def get_summary(project_id):
    project = Project.objects.get(id=project_id)
    issues = sonar_client.fetch_issues(project.sonar_project_key)

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

@bp.route('/advanced_summary', methods=['GET'])
@jwt_required()
@project_access_required('read')
def get_advanced_summary(project_id):
    project = Project.objects.get(id=project_id)
    issues = sonar_client.fetch_issues(project.sonar_project_key)

    if not issues:
        return jsonify({"error": "No issues found"}), 404

    df = pd.DataFrame(issues)

    summary = {
        'total_issues': len(issues),
        'by_severity': df['severity'].value_counts().to_dict(),
        'by_type': df['type'].value_counts().to_dict(),
        'by_status': df.get('status', pd.Series()).value_counts().to_dict(),
        'top_10_rules': df['rule'].value_counts().head(10).to_dict(),
        'issues_over_time': get_issues_over_time(issues),
        'component_hotspots': get_component_hotspots(issues),
        'severity_correlation': get_severity_correlation(issues),
        'issue_resolution_prediction': predict_issue_resolution(issues),
        'code_quality_trend': get_code_quality_trend(issues),
    }

    return jsonify(summary)