from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from mongoengine import connect
from flask_babel import Babel
from redis import Redis
from config import Config
from .api.utils.internationalization import get_locale
import logging

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
    redis_client = Redis.from_url(app.config['REDIS_URL'])
    app.redis = redis_client
    
    # Configure Limiter
    limiter.init_app(app)
    limiter.storage_uri = app.config['REDIS_URL']
    
    # Configure Babel
    app.config['BABEL_DEFAULT_LOCALE'] = 'en'
    babel.localeselector(get_locale)

    # Configure MongoDB
    try:
        connect(host=app.config['MONGO_URI'])
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
        return {"error": "Rate limit exceeded", "message": str(e)}, 429

    @app.errorhandler(Exception)
    def handle_exception(e):
        logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
        return {"error": "Internal server error", "message": "An unexpected error occurred"}, 500

    return app