import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app, render_template_string
import logging

logger = logging.getLogger(__name__)

def send_email(to_email, subject, template, context):
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = current_app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = to_email
        msg['Subject'] = subject

        # Render HTML template
        html_content = render_template_string(template, **context)
        msg.attach(MIMEText(html_content, 'html'))

        with smtplib.SMTP(current_app.config['MAIL_SERVER'], current_app.config['MAIL_PORT']) as smtp_server:
            smtp_server.starttls()
            smtp_server.login(current_app.config['MAIL_USERNAME'], current_app.config['MAIL_PASSWORD'])
            smtp_server.send_message(msg)

        logger.info(f"Email sent successfully to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}. Error: {str(e)}")
        raise

def send_reset_password_email(email, reset_link):
    subject = "Reset Your Password"
    template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Your Password</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }
            .container {
                background-color: #f9f9f9;
                border-radius: 5px;
                padding: 20px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            .button {
                display: inline-block;
                padding: 10px 20px;
                background-color: #007bff;
                color: #ffffff;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Reset Your Password</h1>
            <p>You have requested to reset your password. Click the button below to reset it:</p>
            <p>
                <a href="{{ reset_link }}" class="button">Reset Password</a>
            </p>
            <p>If you did not request this, please ignore this email.</p>
            <p>This link will expire in 24 hours.</p>
        </div>
    </body>
    </html>
    """
    context = {'reset_link': reset_link}
    send_email(email, subject, template, context)

def send_verification_email(email, verification_token):
    verification_link = f"{current_app.config['FRONTEND_URL']}/authentication/verify-email?token={verification_token}"
    subject = "Verify Your Email"
    template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verify Your Email</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }
            .container {
                background-color: #f9f9f9;
                border-radius: 5px;
                padding: 20px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            .button {
                display: inline-block;
                padding: 10px 20px;
                background-color: #28a745;
                color: #ffffff;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Verify Your Email</h1>
            <p>Thank you for registering. Please click the button below to verify your email:</p>
            <p>
                <a href="{{ verification_link }}" class="button">Verify Email</a>
            </p>
            <p>If you did not register for this service, please ignore this email.</p>
        </div>
    </body>
    </html>
    """
    context = {'verification_link': verification_link}
    send_email(email, subject, template, context)