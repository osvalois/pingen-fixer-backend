from flask import request, current_app
from flask_babel import _
import logging

logger = logging.getLogger(__name__)

def get_locale():
    """
    Determine the best language for the user.
    This function is used by Flask-Babel to choose which translations to use.
    """
    # Try to get the language from the request headers
    best_match = request.accept_languages.best_match(current_app.config['LANGUAGES'])
    
    # If no match found, use the default language
    if not best_match:
        best_match = current_app.config['DEFAULT_LANGUAGE']
    
    logger.info(f"Selected language: {best_match}")
    return best_match

def get_localized_message(message_key, **kwargs):
    """
    Get a localized message based on the current locale.
    
    :param message_key: The key for the message in the translations
    :param kwargs: Any formatting arguments for the message
    :return: The localized message
    """
    try:
        return _(message_key, **kwargs)
    except Exception as e:
        logger.error(f"Error getting localized message for key '{message_key}': {str(e)}")
        return message_key  # Return the key itself if translation fails

def set_user_language(user, language):
    """
    Set the preferred language for a user.
    
    :param user: The user object
    :param language: The language code (e.g., 'en', 'es', 'fr')
    """
    if language in current_app.config['LANGUAGES']:
        user.preferred_language = language
        user.save()
        logger.info(f"Updated preferred language for user {user.id} to {language}")
    else:
        logger.warning(f"Attempted to set unsupported language {language} for user {user.id}")
        raise ValueError(f"Unsupported language: {language}")

def get_supported_languages():
    """
    Get a list of all supported languages in the application.
    
    :return: A list of language codes
    """
    return current_app.config['LANGUAGES']

def format_number(number, locale):
    """
    Format a number according to the locale's conventions.
    
    :param number: The number to format
    :param locale: The locale to use for formatting
    :return: Formatted number as a string
    """
    import babel.numbers
    try:
        return babel.numbers.format_number(number, locale=locale)
    except Exception as e:
        logger.error(f"Error formatting number {number} for locale {locale}: {str(e)}")
        return str(number)  # Return the original number as a string if formatting fails

def format_currency(amount, currency, locale):
    """
    Format a currency amount according to the locale's conventions.
    
    :param amount: The amount to format
    :param currency: The currency code (e.g., 'USD', 'EUR')
    :param locale: The locale to use for formatting
    :return: Formatted currency as a string
    """
    import babel.numbers
    try:
        return babel.numbers.format_currency(amount, currency, locale=locale)
    except Exception as e:
        logger.error(f"Error formatting currency {amount} {currency} for locale {locale}: {str(e)}")
        return f"{amount} {currency}"  # Return a basic format if formatting fails