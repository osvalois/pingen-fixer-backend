from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from mongoengine import connect
from flask_babel import Babel
from config import Config
from .api.utils.internationalization import get_locale

limiter = Limiter(key_func=get_remote_address)
babel = Babel()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    CORS(app)
    JWTManager(app)
    limiter.init_app(app)
    
    # Inicialización de Babel
    babel.init_app(app)
    app.config['BABEL_DEFAULT_LOCALE'] = 'en'
    babel.localeselector(get_locale)

    # Use mongoengine's connect function instead of Flask-MongoEngine
    connect(host=app.config['MONGO_URI'])

    from .api import users, companies, projects, issues, suggestions
    
    app.register_blueprint(users.bp)
    app.register_blueprint(companies.bp)
    app.register_blueprint(projects.bp)
    app.register_blueprint(issues.bp)
    app.register_blueprint(suggestions.bp)

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return {"error": "Rate limit exceeded", "message": str(e)}, 429

    @app.errorhandler(Exception)
    def handle_exception(e):
        app.logger.error(f"Unhandled exception: {str(e)}")
        return {"error": "Internal server error", "message": str(e)}, 500

    return app