import uuid
import os
from flask import abort, current_app, flash, render_template, url_for
from flask_login import current_user
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
from cryptography.fernet import Fernet
from flask_mail import Message
from extensions import mail
from premailer import transform

ALLOWED_EXTENSIONS = {"png", "jpg","jpeg", "pdf"}

def allowed_extensions(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Handle intergrity error to make sure that there are no duplicate username, email, phone number
def handle_intergrity_error(error):
    msg = str(error)

    if "username" in msg:
        return "The username you entered already exists"
    if "contact_email" in msg:
        return "The email you entered already exists"
    if "contact_phone" in msg:
        return "The phone number you entered already exists"
    if "national_id_fast" in msg:
        return "The National ID number you entered already exists"
    return "Duplicate data detected"


# Generate filename
def generate_new_filename(original_filename):
    extension = original_filename.rsplit(".", 1)[1]
    unique_name = uuid.uuid4().hex
    return f"{unique_name}.{extension}"

# Abort if user accessed a forbidden page
def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401) # login required
            if current_user.role not in roles:
                abort(403) # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Generate email verification token
def generate_email_verification_token(user_id):
    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    return s.dumps(
        user_id,
        salt = "email-verification"
    )  

# Generate password token
def generate_password_token(user_id):
    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    return s.dumps(
        user_id,
        salt = "password-set-salt"
    )    

# Get the encrytion key
def get_fernet():
    return Fernet(current_app.config["NATIONAL_ID_ENCRYPTION_KEY"])

# Encrypt the national id
def encrypt_national_id(national_id):
    f = get_fernet()

    # Encrypt
    return f.encrypt(national_id.encode()).decode()

# Decrypt the national id
def decrypt_national_id(encrypted_national_id):
    f = get_fernet()

    # Decrypt
    return f.decrypt(encrypted_national_id.encode()).decode()

# Send email
def send_mail(subject, recipients, template, **kwargs):
    try:
        from datetime import datetime
        html_body = render_template(template, year=datetime.now().year, **kwargs)
        sender = ("SudaGuardian","noreply@sudaguardian.com")

        inlined_html = transform(html_body)

        msg = Message(
            subject=subject,
            recipients=recipients,
            sender=sender,
            html=inlined_html
        ) 

        mail.send(msg)
        return True
    
    except Exception as e:
        current_app.logger.error(f"Mail Error: {str(e)}", exc_info=True)
        return False
    
# send set password email
def send_set_password_email(user):
        
    # Generate password token & the url
        token = generate_password_token(user.id)
        set_password_url = url_for("set_password", token=token, _external=True)

        # Send email to user to set their password
        subject = "Final Step: Set your account password for SudaGuardian"
        recepients = [user.contact_email]
        template = "set_password_email.html"

        email_success = send_mail(
            subject=subject,
            recipients=recepients, 
            template=template,
            set_password_url=set_password_url,
            name=user.full_name
        )
        if email_success:
            return True
        else: 
            return False
        
def send_email_verification_email(user):
        
    # create token
        token = generate_email_verification_token(user.id)
        verify_url = url_for("verify_email", token=token, _external=True)

        # send email to verify user's email
        subject = "SudaGuardian: Verify your email to complete the registeration process"
        recipients = [user.contact_email]
        
        template = "verify_email.html"

        email_success = send_mail(
            subject=subject, 
            recipients=recipients, 
            template=template,
            name=user.full_name,
            verify_url=verify_url
        )

        if email_success:
            return True
        else:
            return False



    