from google.oauth2 import id_token
from google.auth.transport import requests
from flask import current_app
import logging

logger = logging.getLogger(__name__)

def verify_google_token(token):
    try:
        idinfo = id_token.verify_oauth2_token(
            token, requests.Request(), current_app.config['GOOGLE_CLIENT_ID'])

        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')

        return {
            'google_id': idinfo['sub'],
            'email': idinfo['email'],
            'name': idinfo.get('name'),
            'picture': idinfo.get('picture')
        }
    except ValueError as e:
        logger.error(f"Invalid Google token: {str(e)}")
        raise