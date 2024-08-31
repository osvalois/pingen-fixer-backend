import re
import logging

logger = logging.getLogger(__name__)

def check_password_strength(password):
    # Inicializar puntuación y sugerencias
    score = 0
    suggestions = []

    # Verificar longitud
    if len(password) < 8:
        suggestions.append("Make the password at least 8 characters long.")
    else:
        score += 1

    # Verificar mayúsculas
    if not re.search(r"[A-Z]", password):
        suggestions.append("Include at least one uppercase letter.")
    else:
        score += 1

    # Verificar minúsculas
    if not re.search(r"[a-z]", password):
        suggestions.append("Include at least one lowercase letter.")
    else:
        score += 1

    # Verificar números
    if not re.search(r"\d", password):
        suggestions.append("Include at least one number.")
    else:
        score += 1

    # Verificar caracteres especiales
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        suggestions.append("Include at least one special character.")
    else:
        score += 1

    logger.info(f"Password strength check completed. Score: {score}")

    return {
        "score": score,
        "suggestions": suggestions
    }