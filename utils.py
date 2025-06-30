from flask import current_app as app
from flask import flash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message\

mail = Mail()

def send_reset_email(to_email, reset_url):
    msg = Message("Password Reset Request", recipients=[to_email])
    msg.body = f"""To reset your password, click the following link:
    {reset_url}

    If you did not make this request, simply ignore this email
    """
    try:
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Failed to send reset email to {to_email}: {e}")
        flash("An error occured while sending the password reset email, please try again later", "danger")


def generate_reset_token(user_email, expires_sec=3600):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return s.dumps(user_email, salt="password-reset-salt")

def verify_reset_token(token, expires_sec=3600):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = s.loads(token, salt="password-reset-salt", max_age=expires_sec)
    except Exception:
        return None
    return email