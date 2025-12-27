import uuid

from flask import abort, current_app
from flask_login import current_user
from functools import wraps
from itsdangerous import URLSafeTimedSerializer

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
def generate_email_verification_token(email):
    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    return s.dumps(
        email,
        salt = "email-verification"
    )    


    