# app.py
from flask import Flask, jsonify, request, current_app
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, get_jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from mongoengine import connect
from flask_babel import Babel, _
import redis
from config import Config
from functools import wraps
from .models import User, UserProjectAccess, Project
from mongoengine.errors import DoesNotExist
import logging
from redis.exceptions import RedisError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize extensions
limiter = Limiter(key_func=get_remote_address)
babel = Babel()
jwt = JWTManager()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    CORS(app)
    jwt.init_app(app)
    babel.init_app(app)

    # Configure Redis
    try:
        app.redis = redis.Redis.from_url(
            app.config['REDIS_URL'],
            db=app.config['REDIS_DB'],
            decode_responses=True
        )
        app.redis.ping()  # Test the connection
        logger.info("Successfully connected to Redis")
    except RedisError as e:
        logger.error(f"Failed to connect to Redis: {str(e)}")
        raise

    # Configure Limiter
    limiter.init_app(app)
    limiter.storage_uri = app.config['REDIS_URL']

    # Configure Babel
    app.config['BABEL_DEFAULT_LOCALE'] = app.config['DEFAULT_LANGUAGE']
    babel.localeselector(get_locale)

    # Configure MongoDB
    try:
        connect(**app.config['MONGODB_SETTINGS'])
        logger.info("Successfully connected to MongoDB")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)}")
        raise

    # Register blueprints
    from .api import users, companies, projects, issues, suggestions

    blueprints = [users.bp, companies.bp, projects.bp, issues.bp, suggestions.bp]
    for blueprint in blueprints:
        app.register_blueprint(blueprint)
        logger.info(f"Registered blueprint: {blueprint.name}")

    # Error handlers
    @app.errorhandler(429)
    def ratelimit_handler(e):
        logger.warning(f"Rate limit exceeded: {str(e)}")
        return jsonify({"error": "Rate limit exceeded", "message": str(e)}), 429

    @app.errorhandler(RedisError)
    def handle_redis_error(e):
        logger.error(f"Redis error: {str(e)}")
        return jsonify({"error": "Redis service unavailable", "message": "Unable to access rate limiting service"}), 503

    @app.errorhandler(Exception)
    def handle_exception(e):
        logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error", "message": "An unexpected error occurred"}), 500

    return app

# Authentication functions
def create_token(user):
    additional_claims = {
        "username": user.username,
        "role": user.role,
        "company_id": str(user.company.id) if user.company else None
    }
    access_token = create_access_token(identity=str(user.id), additional_claims=additional_claims)
    return access_token

def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user_id = get_jwt_identity()
        try:
            user = User.objects.get(id=current_user_id)
            if user.role != 'admin':
                logger.warning(f"Non-admin user {user.username} attempted to access admin-only resource")
                return jsonify({"message": _("Admin access required")}), 403
            return fn(*args, **kwargs)
        except DoesNotExist:
            logger.error(f"User not found for ID: {current_user_id}")
            return jsonify({"message": _("User not found")}), 404
    return wrapper

def project_access_required(required_access_level):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            current_user_id = get_jwt_identity()
            project_id = kwargs.get('id')  # Assuming the project ID is passed as 'id' in the URL
            if not project_id:
                return jsonify({"message": _("Project ID is required")}), 400

            try:
                user = User.objects.get(id=current_user_id)
                project = Project.objects.get(id=project_id)

                # Check if user is admin of the company
                if user.role == 'admin' and user.company == project.company:
                    return fn(*args, **kwargs)

                access = UserProjectAccess.objects(user=user, project=project).first()
                if not access:
                    logger.warning(f"User {user.username} attempted to access project {project_id} without permission")
                    return jsonify({"message": _("You do not have access to this project")}), 403

                access_levels = ['read', 'write', 'admin']
                if access_levels.index(access.access_level) < access_levels.index(required_access_level):
                    logger.warning(f"User {user.username} attempted to perform {required_access_level} action on project {project_id} with only {access.access_level} permission")
                    return jsonify({"message": _("Insufficient project access")}), 403

                return fn(*args, **kwargs)
            except DoesNotExist:
                logger.error(f"User or Project not found. User ID: {current_user_id}, Project ID: {project_id}")
                return jsonify({"message": _("User or Project not found")}), 404
        return wrapper
    return decorator

def rate_limit(limit, per):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = f"rate_limit_{request.endpoint}_{request.remote_addr}"
            try:
                redis_client = current_app.redis
                current = redis_client.get(key)
                if current is not None and int(current) >= limit:
                    logger.warning(f"Rate limit exceeded for {request.endpoint} from {request.remote_addr}")
                    return jsonify({"message": _("Rate limit exceeded. Please try again later.")}), 429

                pipe = redis_client.pipeline()
                pipe.incr(key)
                pipe.expire(key, per)
                pipe.execute()
            except RedisError as e:
                logger.error(f"Redis error in rate limiting: {str(e)}")
                # Continue execution without rate limiting if Redis is unavailable
                pass

            return fn(*args, **kwargs)
        return wrapper
    return decorator

def company_match_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user_id = get_jwt_identity()
        claims = get_jwt()
        try:
            user = User.objects.get(id=current_user_id)
            if 'company_id' in kwargs:
                if str(user.company.id) != kwargs['company_id'] and user.role != 'admin':
                    logger.warning(f"User {user.username} attempted to access resource of different company")
                    return jsonify({"message": _("You do not have access to this company's resources")}), 403
            return fn(*args, **kwargs)
        except DoesNotExist:
            logger.error(f"User not found for ID: {current_user_id}")
            return jsonify({"message": _("User not found")}), 404
    return wrapper

# Internationalization
def get_locale():
    return request.accept_languages.best_match(current_app.config['LANGUAGES'])