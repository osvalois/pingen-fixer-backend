from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from mongoengine.errors import DoesNotExist, ValidationError, NotUniqueError
from bson import ObjectId
from datetime import datetime
import logging
from flask_babel import _

from ..models import User, Project, UserProjectAccess, Company, AuditLog, Suggestion, Notification
from ..auth import admin_required, project_access_required
from .utils.pagination import paginate

bp = Blueprint('projects', __name__, url_prefix='/api/projects')
logger = logging.getLogger(__name__)

@bp.before_request
def before_request():
    user = User.objects.get(id=get_jwt_identity())
    if user and user.preferred_language:
        current_app.babel.locale = user.preferred_language

def notify_users(users, message, notification_type):
    for user in users:
        Notification(user=user, message=message, type=notification_type).save()

@bp.route('/', methods=['POST'])
@jwt_required()
def create_project():
    try:
        current_user = User.objects.get(id=get_jwt_identity())
        data = request.json

        if not all(key in data for key in ['name', 'description']):
            return jsonify({"message": _("Missing required fields")}), 400

        project = Project(
            name=data['name'],
            description=data['description'],
            company=current_user.company,
            status='Planning',
            start_date=datetime.utcnow()
        ).save()

        UserProjectAccess(user=current_user, project=project, access_level='admin').save()

        AuditLog(user=current_user, action="create_project", details={"project_id": str(project.id)}).save()

        logger.info(f"Project created: {project.name} by user {current_user.username}")
        return jsonify(project.to_dict()), 201
    except NotUniqueError:
        return jsonify({"message": _("A project with this name already exists in your company")}), 400
    except ValidationError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        logger.error(f"Error creating project: {str(e)}")
        return jsonify({"message": _("An error occurred while creating the project")}), 500

@bp.route('/', methods=['GET'])
@jwt_required()
def get_projects():
    try:
        current_user = User.objects.get(id=get_jwt_identity())
        
        if current_user.role == 'admin':
            projects = Project.objects(company=current_user.company)
        else:
            project_accesses = UserProjectAccess.objects(user=current_user)
            projects = [access.project for access in project_accesses]

        return paginate(projects, Project.to_dict)
    except Exception as e:
        logger.error(f"Error retrieving projects: {str(e)}")
        return jsonify({"message": _("An error occurred while retrieving projects")}), 500

@bp.route('/<id>', methods=['GET'])
@jwt_required()
@project_access_required('read')
def get_project(id):
    try:
        project = Project.objects.get(id=id)
        return jsonify(project.to_dict()), 200
    except DoesNotExist:
        return jsonify({"message": _("Project not found")}), 404
    except Exception as e:
        logger.error(f"Error retrieving project: {str(e)}")
        return jsonify({"message": _("An error occurred while retrieving the project")}), 500

@bp.route('/<id>', methods=['PUT'])
@jwt_required()
@project_access_required('write')
def update_project(id):
    try:
        data = request.json
        project = Project.objects.get(id=id)
        
        allowed_fields = ['name', 'description', 'status', 'end_date']
        for field in allowed_fields:
            if field in data:
                setattr(project, field, data[field])
        
        project.save()

        current_user = User.objects.get(id=get_jwt_identity())
        AuditLog(user=current_user, action="update_project", details={"project_id": str(project.id)}).save()

        logger.info(f"Project updated: {project.name}")
        return jsonify({"message": _("Project updated successfully"), "project": project.to_dict()}), 200
    except DoesNotExist:
        return jsonify({"message": _("Project not found")}), 404
    except ValidationError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        logger.error(f"Error updating project: {str(e)}")
        return jsonify({"message": _("An error occurred while updating the project")}), 500

@bp.route('/<id>', methods=['DELETE'])
@jwt_required()
@project_access_required('admin')
def delete_project(id):
    try:
        project = Project.objects.get(id=id)
        project_name = project.name
        project.delete()

        current_user = User.objects.get(id=get_jwt_identity())
        AuditLog(user=current_user, action="delete_project", details={"project_name": project_name}).save()

        logger.info(f"Project deleted: {project_name}")
        return jsonify({"message": _("Project deleted successfully")}), 200
    except DoesNotExist:
        return jsonify({"message": _("Project not found")}), 404
    except Exception as e:
        logger.error(f"Error deleting project: {str(e)}")
        return jsonify({"message": _("An error occurred while deleting the project")}), 500

@bp.route('/<id>/users', methods=['POST'])
@jwt_required()
@project_access_required('admin')
def add_user_to_project(id):
    try:
        data = request.json
        project = Project.objects.get(id=id)
        user = User.objects.get(id=data['user_id'])
        
        if UserProjectAccess.objects(user=user, project=project).first():
            return jsonify({"message": _("User already has access to this project")}), 400
        
        UserProjectAccess(user=user, project=project, access_level=data['access_level']).save()

        current_user = User.objects.get(id=get_jwt_identity())
        AuditLog(user=current_user, action="add_user_to_project", 
                 details={"project_id": str(project.id), "user_id": str(user.id), "access_level": data['access_level']}).save()

        notify_users([user], f"You have been added to the project: {project.name}", "project_access")

        logger.info(f"User {user.username} added to project {project.name} with access level {data['access_level']}")
        return jsonify({"message": _("User added to project successfully")}), 201
    except DoesNotExist:
        return jsonify({"message": _("Project or user not found")}), 404
    except ValidationError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        logger.error(f"Error adding user to project: {str(e)}")
        return jsonify({"message": _("An error occurred while adding the user to the project")}), 500

@bp.route('/<id>/users', methods=['GET'])
@jwt_required()
@project_access_required('read')
def get_project_users(id):
    try:
        project = Project.objects.get(id=id)
        accesses = UserProjectAccess.objects(project=project)
        users = [{"user": access.user.to_dict(), "access_level": access.access_level} for access in accesses]
        return jsonify(users), 200
    except DoesNotExist:
        return jsonify({"message": _("Project not found")}), 404
    except Exception as e:
        logger.error(f"Error retrieving project users: {str(e)}")
        return jsonify({"message": _("An error occurred while retrieving project users")}), 500

@bp.route('/<id>/users/<user_id>', methods=['DELETE'])
@jwt_required()
@project_access_required('admin')
def remove_user_from_project(id, user_id):
    try:
        project = Project.objects.get(id=id)
        user = User.objects.get(id=user_id)
        
        access = UserProjectAccess.objects(user=user, project=project).first()
        if not access:
            return jsonify({"message": _("User does not have access to this project")}), 404
        
        access.delete()

        current_user = User.objects.get(id=get_jwt_identity())
        AuditLog(user=current_user, action="remove_user_from_project", 
                 details={"project_id": str(project.id), "user_id": str(user.id)}).save()

        notify_users([user], f"You have been removed from the project: {project.name}", "project_access")

        logger.info(f"User {user.username} removed from project {project.name}")
        return jsonify({"message": _("User removed from project successfully")}), 200
    except DoesNotExist:
        return jsonify({"message": _("Project or user not found")}), 404
    except Exception as e:
        logger.error(f"Error removing user from project: {str(e)}")
        return jsonify({"message": _("An error occurred while removing the user from the project")}), 500

@bp.route('/<id>/suggestions', methods=['POST'])
@jwt_required()
@project_access_required('write')
def add_suggestion(id):
    try:
        data = request.json
        project = Project.objects.get(id=id)
        current_user = User.objects.get(id=get_jwt_identity())
        
        suggestion = Suggestion(
            issue_key=data['issue_key'],
            suggestion=data['suggestion'],
            project=project,
            created_by=current_user
        ).save()

        AuditLog(user=current_user, action="add_suggestion", 
                 details={"project_id": str(project.id), "suggestion_id": str(suggestion.id)}).save()

        notify_users([access.user for access in UserProjectAccess.objects(project=project, access_level='admin')],
                     f"New suggestion added to project: {project.name}", "new_suggestion")

        logger.info(f"Suggestion added to project {project.name}")
        return jsonify({"message": _("Suggestion added successfully"), "suggestion": suggestion.to_dict()}), 201
    except DoesNotExist:
        return jsonify({"message": _("Project not found")}), 404
    except ValidationError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        logger.error(f"Error adding suggestion: {str(e)}")
        return jsonify({"message": _("An error occurred while adding the suggestion")}), 500

@bp.route('/<id>/suggestions', methods=['GET'])
@jwt_required()
@project_access_required('read')
def get_project_suggestions(id):
    try:
        project = Project.objects.get(id=id)
        suggestions = Suggestion.objects(project=project)
        return paginate(suggestions, Suggestion.to_dict)
    except DoesNotExist:
        return jsonify({"message": _("Project not found")}), 404
    except Exception as e:
        logger.error(f"Error retrieving project suggestions: {str(e)}")
        return jsonify({"message": _("An error occurred while retrieving project suggestions")}), 500

@bp.route('/<id>/suggestions/<suggestion_id>', methods=['PUT'])
@jwt_required()
@project_access_required('admin')
def update_suggestion(id, suggestion_id):
    try:
        data = request.json
        project = Project.objects.get(id=id)
        suggestion = Suggestion.objects.get(id=suggestion_id, project=project)
        
        if 'status' in data:
            suggestion.status = data['status']
        if 'suggestion' in data:
            suggestion.suggestion = data['suggestion']
        
        suggestion.save()

        current_user = User.objects.get(id=get_jwt_identity())
        AuditLog(user=current_user, action="update_suggestion", 
                 details={"project_id": str(project.id), "suggestion_id": str(suggestion.id)}).save()

        notify_users([suggestion.created_by], 
                     f"Your suggestion for project {project.name} has been updated", "suggestion_update")

        logger.info(f"Suggestion updated in project {project.name}")
        return jsonify({"message": _("Suggestion updated successfully"), "suggestion": suggestion.to_dict()}), 200
    except DoesNotExist:
        return jsonify({"message": _("Project or suggestion not found")}), 404
    except ValidationError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        logger.error(f"Error updating suggestion: {str(e)}")
        return jsonify({"message": _("An error occurred while updating the suggestion")}), 500

@bp.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception in projects blueprint: {str(e)}")
    return jsonify({"message": _("An unexpected error occurred")}), 500