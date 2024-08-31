import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

class Config:
    # Existing configurations
    SECRET_KEY = os.getenv('SECRET_KEY')
    MONGO_URI = os.getenv('MONGO_URI')
    SONAR_URL = os.getenv('SONAR_URL')
    SONAR_TOKEN = os.getenv('SONAR_TOKEN')
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    LANGUAGES = ['en', 'es', 'fr']  # lista de idiomas soportados
    DEFAULT_LANGUAGE = 'en'
    ITEMS_PER_PAGE = 20
    MAX_ITEMS_PER_PAGE = 100
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_DB = int(os.getenv('REDIS_DB', 0))
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')
    # Additional configurations
    MONGODB_SETTINGS = {
        'host': MONGO_URI,
        'db': os.getenv('MONGO_DB', 'sonarailysis'),
    }

    # SonarQube configurations
    SONAR_PROJECT_KEY = os.getenv('SONAR_PROJECT_KEY')
    SONAR_USER_NAME = os.getenv('SONAR_USER_NAME')

    # Project configurations
    PROJECT_ROOT = os.getenv('PROJECT_ROOT')

    # OpenAI configurations
    OPENAI_PROJECT_ID = os.getenv('OPENAI_PROJECT_ID')
    OPENAI_MODEL = os.getenv('OPENAI_MODEL')

    # Anthropic configurations
    ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
    ANTHROPIC_MODEL = os.getenv('ANTHROPIC_MODEL')

    # Flask configurations
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = FLASK_ENV == 'development'

    # AI model selection
    AI_MODEL = os.getenv('AI_MODEL', 'openai')

    # JWT settings
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

    # Babel settings
    BABEL_DEFAULT_LOCALE = DEFAULT_LANGUAGE

    # Email configuration (if you're using email services)
    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')

    # Additional security settings
    CSRF_ENABLED = True
    CSRF_SECRET_KEY = os.getenv('CSRF_SECRET_KEY', SECRET_KEY)

    FRONTEND_URL= os.getenv('FRONTEND_URL', 'http://localhost:3000')