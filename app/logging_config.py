import os
import logging
from logging.handlers import RotatingFileHandler

def configure_logging(app):
    # Asegúrate de que el directorio de logs existe
    if not os.path.exists('logs'):
        os.mkdir('logs')

    # Configura el logging básico
    logging.basicConfig(level=logging.INFO)

    # Crea un manejador de archivo que rota los logs
    file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)

    # Añade el manejador al logger de la aplicación
    app.logger.addHandler(file_handler)

    # Configura también el logger para werkzeug (logs de desarrollo del servidor)
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.addHandler(file_handler)

    # Configura el nivel de logging basado en la configuración de la app
    if app.config['DEBUG']:
        app.logger.setLevel(logging.DEBUG)
        werkzeug_logger.setLevel(logging.DEBUG)
    else:
        app.logger.setLevel(logging.INFO)
        werkzeug_logger.setLevel(logging.INFO)

    app.logger.info('Logging configurado')