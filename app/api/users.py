##users.py
from flask import Blueprint, request, jsonify, url_for, g
from flask_jwt_extended import (
    jwt_required, get_jwt_identity, create_access_token,
    create_refresh_token, get_jwt
)
from ..models import User, RefreshToken, PasswordResetToken, Company, AuditLog
from ..auth import create_token, admin_required, rate_limit
from mongoengine.errors import NotUniqueError, ValidationError, DoesNotExist
from werkzeug.security import generate_password_hash
import datetime
from bson.objectid import ObjectId
from .utils.email_service import send_reset_password_email, send_verification_email
from .utils.google_auth import verify_google_token
from .utils.biometric_auth import verify_biometric_data
from .utils.password_strength import check_password_strength
from .utils.ip_info import get_ip_info
from .utils.internationalization import get_localized_message
import secrets
import logging
from flask_babel import _
from flask import current_app as app
bp = Blueprint('users', __name__, url_prefix='/api/users')
logger = logging.getLogger(__name__)

@bp.before_request
def before_request():
    g.start_time = datetime.datetime.utcnow()

@bp.after_request
def after_request(response):
    if hasattr(g, 'user_id'):
        duration = datetime.datetime.utcnow() - g.start_time
        AuditLog(
            user=g.user_id,
            action=request.endpoint,
            details={
                'method': request.method,
                'path': request.path,
                'status_code': response.status_code,
                'duration': duration.total_seconds()
            },
            ip_address=request.remote_addr
        ).save()
    return response

@bp.route('/login', methods=['POST'])
@rate_limit(limit=5, per=60)
def login():
    try:
        data = request.json
        identifier = data.get('identifier')
        password = data.get('password')
        remember_me = data.get('rememberMe', False)

        if not identifier or not password:
            return jsonify({"message": _("Identifier and password are required")}), 400

        logger.info(f"Login attempt for identifier: {identifier}")

        user = None
        try:
            user = User.objects.get(username=identifier)
        except DoesNotExist:
            try:
                user = User.objects.get(email=identifier)
            except DoesNotExist:
                logger.warning(f"User not found: {identifier}")
                return jsonify({"message": _("Invalid identifier or password")}), 401

        if not user:
            return jsonify({"message": _("Invalid identifier or password")}), 401

        if not user.check_password(password):
            logger.warning(f"Invalid password for identifier: {identifier}")
            return jsonify({"message": _("Invalid identifier or password")}), 401

        if not user.is_active:
            logger.warning(f"Inactive user attempted to log in: {identifier}")
            return jsonify({"message": _("Account is inactive. Please contact support.")}), 403

        if not user.is_verified:
            logger.warning(f"Unverified user attempted to log in: {identifier}")
            return jsonify({"message": _("Please verify your email before logging in.")}), 403

        access_token_expires = datetime.timedelta(days=30 if remember_me else 1)
        refresh_token_expires = datetime.timedelta(days=60 if remember_me else 30)

        access_token = create_access_token(identity=str(user.id), expires_delta=access_token_expires)
        refresh_token = create_refresh_token(identity=str(user.id), expires_delta=refresh_token_expires)

        RefreshToken(user=user, token=refresh_token, expires_at=datetime.datetime.utcnow() + refresh_token_expires).save()

        user.last_login = datetime.datetime.utcnow()
        user.save()

        ip_info = get_ip_info(request.remote_addr)
        AuditLog(user=user, action="login", details=ip_info).save()

        logger.info(f"User logged in successfully: {user.username}")
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.to_dict()
        }), 200
    except Exception as e:
        app.logger.error(f"Unexpected error during login: {str(e)}", exc_info=True)
        return jsonify({"message": _("An unexpected error occurred during login. Please try again later.")}), 500

@bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    refresh_token = get_jwt()['jti']

    stored_token = RefreshToken.objects(token=refresh_token, user=ObjectId(current_user_id)).first()
    if not stored_token:
        return jsonify({"message": _("Invalid refresh token")}), 401

    new_access_token = create_access_token(identity=current_user_id)
    return jsonify({"access_token": new_access_token}), 200

@bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    RefreshToken.objects(token=jti).delete()
    return jsonify({"message": _("Successfully logged out")}), 200

@bp.route('/forgot-password', methods=['POST'])
@rate_limit(limit=3, per=3600)
def forgot_password():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({"message": _("Email is required")}), 400

    user = User.objects(email=email).first()
    if not user:
        logger.info(f"Password reset requested for non-existent email: {email}")
        return jsonify({"message": _("If this email is registered, you will receive reset instructions shortly")}), 200

    token = secrets.token_urlsafe(32)
    reset_token = PasswordResetToken(user=user, token=token)
    reset_token.save()

    reset_link = url_for('users.reset_password', token=token, _external=True)
    send_reset_password_email(user.email, reset_link)

    logger.info(f"Password reset email sent to: {email}")
    return jsonify({"message": _("If this email is registered, you will receive reset instructions shortly")}), 200

@bp.route('/reset-password/<token>', methods=['POST'])
@rate_limit(limit=3, per=3600)
def reset_password(token):
    data = request.json
    new_password = data.get('new_password')

    if not new_password:
        return jsonify({"message": _("New password is required")}), 400

    reset_token = PasswordResetToken.objects(token=token).first()
    if not reset_token or reset_token.is_expired():
        return jsonify({"message": _("Invalid or expired reset token")}), 400

    password_strength = check_password_strength(new_password)
    if password_strength['score'] < 3:
        return jsonify({"message": _("Password is too weak"), "suggestions": password_strength['suggestions']}), 400

    user = reset_token.user
    user.set_password(new_password)
    user.save()

    reset_token.delete()

    logger.info(f"Password reset successfully for user: {user.username}")
    return jsonify({"message": _("Password reset successfully")}), 200

@bp.route('/google-login', methods=['POST'])
@rate_limit(limit=10, per=60)
def google_login():
    token = request.json.get('token')

    if not token:
        return jsonify({"message": _("Google token is required")}), 400

    try:
        google_user = verify_google_token(token)
    except ValueError as e:
        logger.warning(f"Invalid Google token: {str(e)}")
        return jsonify({"message": _("Invalid Google token")}), 401

    user = User.objects(email=google_user['email']).first()

    if not user:
        user = User(
            email=google_user['email'],
            username=google_user['email'].split('@')[0],
            name=google_user['name'],
            is_active=True,
            is_verified=True
        )
        user.save()
        logger.info(f"New user created via Google login: {user.email}")
    else:
        logger.info(f"Existing user logged in via Google: {user.email}")

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    return jsonify({
        "message": _("Google login successful"),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user.to_dict()
    }), 200

@bp.route('/biometric-login', methods=['POST'])
@rate_limit(limit=5, per=60)
def biometric_login():
    biometric_data = request.json.get('biometricData')
    user_id = request.json.get('userId')

    if not biometric_data or not user_id:
        return jsonify({"message": _("Biometric data and user ID are required")}), 400

    try:
        user = User.objects.get(id=user_id)
    except DoesNotExist:
        logger.warning(f"Biometric login attempted for non-existent user: {user_id}")
        return jsonify({"message": _("User not found")}), 404

    if not user.is_active:
        logger.warning(f"Biometric login attempted for inactive user: {user_id}")
        return jsonify({"message": _("Account is inactive")}), 403

    if verify_biometric_data(user, biometric_data):
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        logger.info(f"Biometric login successful for user: {user.username}")
        return jsonify({
            "message": _("Biometric login successful"),
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.to_dict()
        }), 200
    else:
        logger.warning(f"Failed biometric login attempt for user: {user.username}")
        return jsonify({"message": _("Biometric authentication failed")}), 401

@bp.route('/register', methods=['POST'])
@rate_limit(limit=3, per=3600)
def register():
    data = request.json
    required_fields = ['username', 'email', 'password', 'name']

    if not all(field in data for field in required_fields):
        return jsonify({"message": _("All fields are required")}), 400

    password_strength = check_password_strength(data['password'])
    if password_strength['score'] < 3:
        return jsonify({"message": _("Password is too weak"), "suggestions": password_strength['suggestions']}), 400

    try:
        verification_token = secrets.token_urlsafe(32)
        user = User(
            username=data['username'],
            email=data['email'],
            name=data['name'],
            is_active=True,
            is_verified=False,
            verification_token=verification_token,
            preferred_language=data.get('preferred_language', 'en'),
            timezone=data.get('timezone', 'UTC')
        )
        user.set_password(data['password'])
        user.save()

        send_verification_email(user.email, verification_token)

        logger.info(f"New user registered: {user.username}")
        return jsonify({"message": _("User registered successfully. Please check your email to verify your account.")}), 201
    except NotUniqueError:
        return jsonify({"message": _("Username or email already exists")}), 409
    except ValidationError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        logger.error(f"Error during user registration: {str(e)}")
        return jsonify({"message": _("An error occurred during registration")}), 500

@bp.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    try:
        print(token)
        user = User.objects(verification_token=token).first()
        print(user)
        if not user:
            return jsonify({"message": "Invalid verification token"}), 400

        if user.is_verified:
            return jsonify({"message": "Email already verified"}), 200

        user.is_verified = True
        user.verification_token = None
        user.save()

        return jsonify({"message": "Email verified successfully"}), 200
    except Exception as e:
        return jsonify({"message": "An error occurred during email verification"}), 500

@bp.route('/change-password', methods=['POST'])
@jwt_required()
@rate_limit(limit=5, per=3600)
def change_password():
    current_user_id = get_jwt_identity()
    data = request.json

    if 'current_password' not in data or 'new_password' not in data:
        return jsonify({"message": _("Current password and new password are required")}), 400

    try:
        user = User.objects.get(id=current_user_id)
    except DoesNotExist:
        return jsonify({"message": _("User not found")}), 404

    if not user.check_password(data['current_password']):
        logger.warning(f"Failed password change attempt for user: {user.username}")
        return jsonify({"message": _("Current password is incorrect")}), 401

    password_strength = check_password_strength(data['new_password'])
    if password_strength['score'] < 3:
        return jsonify({"message": _("New password is too weak"), "suggestions": password_strength['suggestions']}), 400

    user.set_password(data['new_password'])
    user.save()

    logger.info(f"Password changed successfully for user: {user.username}")
    return jsonify({"message": _("Password changed successfully")}), 200

@bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user_id = get_jwt_identity()
    try:
        user = User.objects.get(id=current_user_id)
        return jsonify(user.to_dict()), 200
    except DoesNotExist:
        return jsonify({"message": _("User not found")}), 404

@bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    data = request.json

    try:
        user = User.objects.get(id=current_user_id)
        allowed_fields = ['name', 'preferred_language', 'timezone']
        for key, value in data.items():
            if key in allowed_fields:
                setattr(user, key, value)
        user.save()
        logger.info(f"Profile updated for user: {user.username}")
        return jsonify({"message": _("Profile updated successfully"), "user": user.to_dict()}), 200
    except DoesNotExist:
        return jsonify({"message": _("User not found")}), 404
    except ValidationError as e:
        return jsonify({"message": str(e)}), 400

@bp.route('/verify-token', methods=['GET'])
@jwt_required()
def verify_token():
    try:
        raw_token = request.headers.get('Authorization').replace('Bearer ', '')
        current_user_id = get_jwt_identity()
        user = User.objects.get(id=current_user_id)
        return jsonify({"message": _("Token is valid"), "user": user.to_dict()}), 200
    except DoesNotExist:
        return jsonify({"message": _("Invalid token")}), 401

@bp.route('/', methods=['GET'])
@jwt_required()
@admin_required
def get_users():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    users = User.objects.paginate(page=page, per_page=per_page)
    return jsonify({
        "users": [user.to_dict() for user in users.items],
        "total": users.total,
        "pages": users.pages,
        "page": page
    }), 200

@bp.route('/<id>', methods=['GET'])
@jwt_required()
def get_user(id):
    try:
        user = User.objects.get(id=id)
        current_user_id = get_jwt_identity()
        if str(current_user_id) != str(user.id) and not User.objects.get(id=current_user_id).role == 'admin':
            return jsonify({"message": _("Unauthorized")}), 403
        return jsonify(user.to_dict()), 200
    except DoesNotExist:
        return jsonify({"message": _("User not found")}), 404

@bp.route('/<id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    current_user_id = get_jwt_identity()
    try:
        user = User.objects.get(id=id)
        if str(current_user_id) != str(user.id) and not User.objects.get(id=current_user_id).role == 'admin':
            return jsonify({"message": _("Unauthorized")}), 403
        data = request.json
        allowed_fields = ['name', 'email', 'username', 'role', 'is_active', 'preferred_language', 'timezone']
        for key, value in data.items():
            if key in allowed_fields:
                setattr(user, key, value)
        user.save()
        logger.info(f"User updated: {user.username}")
        return jsonify({"message": _("User updated successfully"), "user": user.to_dict()}), 200
    except DoesNotExist:
        return jsonify({"message": _("User not found")}), 404
    except ValidationError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        logger.error(f"Update user error: {str(e)}")
        return jsonify({"message": _("An error occurred while updating the user")}), 500

@bp.route('/<id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_user(id):
    try:
        user = User.objects.get(id=id)
        username = user.username
        user.delete()
        logger.info(f"User deleted: {username}")
        return jsonify({"message": _("User deleted successfully")}), 200
    except DoesNotExist:
        return jsonify({"message": _("User not found")}), 404
    except Exception as e:
        logger.error(f"Delete user error: {str(e)}")
        return jsonify({"message": _("An error occurred while deleting the user")}), 500

@bp.route('/change-role/<id>', methods=['PUT'])
@jwt_required()
@admin_required
def change_user_role(id):
    data = request.json
    new_role = data.get('role')
    
    if new_role not in ['admin', 'manager', 'user']:
        return jsonify({"message": _("Invalid role")}), 400

    try:
        user = User.objects.get(id=id)
        user.role = new_role
        user.save()
        logger.info(f"Role changed for user {user.username} to {new_role}")
        return jsonify({"message": _("User role updated successfully"), "user": user.to_dict()}), 200
    except DoesNotExist:
        return jsonify({"message": _("User not found")}), 404
    except Exception as e:
        logger.error(f"Change user role error: {str(e)}")
        return jsonify({"message": _("An error occurred while changing the user role")}), 500

@bp.route('/activity-log/<id>', methods=['GET'])
@jwt_required()
@admin_required
def get_user_activity_log(id):
    try:
        user = User.objects.get(id=id)
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        logs = AuditLog.objects(user=user).order_by('-timestamp').paginate(page=page, per_page=per_page)
        return jsonify({
            "logs": [log.to_dict() for log in logs.items],
            "total": logs.total,
            "pages": logs.pages,
            "page": page
        }), 200
    except DoesNotExist:
        return jsonify({"message": _("User not found")}), 404
    except Exception as e:
        logger.error(f"Get user activity log error: {str(e)}")
        return jsonify({"message": _("An error occurred while retrieving the user activity log")}), 500

@bp.errorhandler(Exception)
def handle_exception(e):
    import traceback
    error_traceback = traceback.format_exc()
    
    print("=== Unhandled Exception ===")
    print(f"Error type: {type(e).__name__}")
    print(f"Error message: {str(e)}")
    print("Traceback:")
    print(error_traceback)
    print("============================")
    
    logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    
    return jsonify({
        "message": _("An unexpected error occurred"),
        "error": str(e),
        "error_type": type(e).__name__
    }), 500