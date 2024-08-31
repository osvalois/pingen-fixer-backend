from flask import current_app
from flask_mail import Message
from threading import Thread

def send_async_email(app, msg):
    with app.app_context():
        try:
            current_app.mail.send(msg)
        except Exception as e:
            current_app.logger.error(f"Error sending email: {str(e)}")

def send_email(subject, recipient, text_body, html_body):
    msg = Message(subject, recipients=[recipient])
    msg.body = text_body
    msg.html = html_body
    Thread(target=send_async_email, args=(current_app._get_current_object(), msg)).start()

def send_reset_password_email(user_email, reset_link):
    subject = "Password Reset Request"
    text_body = f"""
    Dear User,

    To reset your password, please visit the following link:
    {reset_link}

    If you did not request a password reset, please ignore this email.

    Sincerely,
    Your App Team
    """
    html_body = f"""
    <p>Dear User,</p>
    <p>To reset your password, please <a href="{reset_link}">click here</a>.</p>
    <p>If you did not request a password reset, please ignore this email.</p>
    <p>Sincerely,<br>Your App Team</p>
    """
    send_email(subject, user_email, text_body, html_body)