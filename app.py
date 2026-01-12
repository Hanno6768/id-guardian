import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for, current_app
from datetime import datetime
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from models import User, PendingUser, EncryptedNationalID
from helpers import allowed_extensions, generate_new_filename, handle_intergrity_error, roles_required, generate_email_verification_token, decrypt_national_id
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from flask_mail import Mail, Message
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["NATIONAL_ID_ENCRYPTION_KEY"] = os.getenv("NATIONAL_ID_ENCRYPTION_KEY")
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH"))

# Ensure that the upload folder exists
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, os.getenv("UPLOAD_FOLDER"))
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Enable debug mode
app.config["DEBUG"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

# configuring the mail
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT"))
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS") == "True"
app.config["MAIL_USE_SSL"] = os.getenv("MAIL_USE_SSL") == "True"

mail = Mail(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///idguardian.db")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    # model method that returns user by their id
    return User.get_by_id(int(user_id))

# ------- Error Handlers --------------------------------------------

@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    flash("File too large. Maximum allowed size is 5 MB.", "danger")
    return redirect("/register")

# ------- Routes ----------------------------------------------------

# Home page
@app.route('/')
@app.route("/home")
def home():
    return render_template("home.html")

# log user in
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        logout_user()
        return render_template("login.html")
    else:
        identifier = request.form.get("identifier")
        password = request.form.get("password")

        # Check if identifier or password weren't provided
        if not identifier:
            flash("You must provide your username or national id", "warning")
            return redirect("/login")
        elif not password:
            flash("You must provide your password", "warning")
            return redirect("/login")
        else:

            # Try username
            user = User.get_by_username(identifier)
            # If no user was found, try national id
            if not user:
                user = User.get_by_national_id(identifier)
            if not user:
                flash("Invalid credentials", "danger")
                return redirect("/login")
            if user.verify_password(password):
                login_user(user)
                flash("You have successfully logged in!", "success")
                if user.role == "admin":
                    return redirect("/admin_dashboard")
                elif user.role == "reviewer":
                    return redirect("/reviewer_dashboard")
                else:
                    return redirect("user_dashboard")
            else:
                flash("Invalid credentials", "danger")
                return redirect("/login")

# log user out           
@app.route("/logout")
def logout():
    logout_user()
    flash("You have been logged out", "success")
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():

    # if user is already logged in they can't register
    if current_user.is_authenticated:
        return redirect(url_for("user_dashboard"))
    
    if request.method == "GET":
        return render_template("register.html")
    else:
        full_name = request.form.get("name", "").strip().upper()
        birthdate = request.form.get("birthdate")
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip().replace(" ", "")
        username = request.form.get("username", "").strip()
        national_id = request.form.get("id-num", "").strip().replace(" ", "")
        document = request.files.get("document")

        # Placing the required field in a dictionary in oreder to iterate
        required_fields = {
            "Full name" : full_name,
            "Birthdate" : birthdate,
            "Email" : email,
            "Phone number" : phone,
            "Username" : username,
            "National ID number" : national_id
        }

        # Iterate over the required fields to make sure they are provide
        for key, value in required_fields.items():
            if not value:
                flash(f"Please fill in your {key} field", "warning")
                return redirect("/register")
        
        # Check if there is a document uploaded
        if not document or document.filename == "":
            flash("Please upload your ID document file", "warning")
            return redirect("/register")

        # Check if the document type supported
        if not allowed_extensions(document.filename):
            flash("The Document formate you uploaded is not supported", "warning")
            return redirect("/register")
            
        # Validate the national_id
        if not national_id.isdigit() or len(national_id) != 11:
            flash ("National ID Number must be exactly 11 digits", "warning")
            return redirect("/register")

        # Insert information in identities table and check if data is unique
        user = PendingUser()

        user.full_name = full_name
        user.national_id = national_id
        user.contact_email = email
        user.contact_phone = phone
        user.birthdate = birthdate
        user.username = username
        user.status = "pending"

        try:
            user.insert_to_identities()
        except Exception as e:
            flash(handle_intergrity_error(e), "warning")
            return redirect("/register")

        # Secure and generate filename
        filename = secure_filename(document.filename)
        new_filename = generate_new_filename(filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)

        # Save the uploaded file
        document.save(file_path)

        # Insert the relative path of the file in the user object
        user.file_path = f"uploads/{new_filename}"

        # Insert Object into pending_verifications table
        pending_id = user.insert_to_pending()
        
        # Encrypt national id and insert into national_id_encrypted
        encrypted = EncryptedNationalID(pending_id=pending_id, user_id=None, national_id_plain=national_id)
        encrypted.encrypt()
        encrypted.insert()

        # Email verification
        # create token
        token = generate_email_verification_token(user.contact_email)
        verify_url = url_for("verify_email", token=token, _external=True)

        # send email to verify user's email
        msg = Message(
            subject = "SudaGuardian: Verify your email to complete the registeration process",
            sender = "noreply@sudaguardian.com",
            recipients = [user.contact_email],
            body = f"""
            SudaGuardian Identity Portal

            Hello {user.full_name}, 

            Verify your email to complete the registeration process by clicking on te link below:
            {verify_url}

            This link expires in 30 minutes

            If you think this is a mistake, ignore this email
            """
        )

        msg.html =  render_template("verify.html", verify_url=verify_url, full_name=user.full_name)

        try:
            mail.send(msg)
        except Exception as e:
            current_app.logger.error(
                "Email verification failed for : %s: %s",
                user.contact_email,
                str(e),
                exc_info = True
            )
            flash("We couldn't send the verification email. Please try again later")
            return redirect(url_for("register"))

        # set the registeration started session to true so user can only open the 
        # /check_inbox after submitting the register form
        session["registration_started"] = True

        # redirect user to /check_inbox route
        flash("A message was sent to your inbox", "info")
        return redirect(url_for("check_inbox"))

@app.route("/check_inbox")
def check_inbox():

    if not session.get("registration_started"):
        return redirect(url_for("register"))
    return render_template("check_inbox.html")

@app.route("/verify_email/<token>")
def verify_email(token):

    # redirect logged in users
    if current_user.is_authenticated:
        return redirect(url_for("user_dashboard"))
    
    # make sure registration in progress
    elif not session.get("registration_started"):
        return redirect(url_for("register"))
    
    # validate the token
    else:
        s = URLSafeTimedSerializer(app.config["SECRET_KEY"])

        try :
            email = s.loads(
                token,
                salt = "email-verification",
                max_age = 1800
            )
        except SignatureExpired:
            flash("Verification link has expired", "danger")
            return redirect(url_for("register"))
        except BadSignature:
            flash("Invalid verification link", "danger")
            return redirect(url_for("register"))
        
        # see if user's email exist in the database
        user = PendingUser.get_by_email(email)

        if not user:
            flash("Invalid verification request", "error")
            return redirect(url_for("register"))
        else: 
            user.update_email_status(email)
            session.pop("registeration_started", None)
            flash("Request recieved successfully.Please wait for a reviewer approval before logging in", "success")
            return redirect(url_for("home"))
                
@app.route("/user_dashboard")
@login_required
@roles_required("user", "admin")
def user_dashboard():
    return render_template("user_dashboard.html", user=current_user)

@app.route("/reviewer_dashboard")
@login_required
@roles_required("admin", "reviewer")
def reviewer_dashboard():
    
    # Get all the pending users
    pending_users = PendingUser.get_verified_pending_users()

    # Decrypt the national ID number
    for user in pending_users:
        user["national_id"] = decrypt_national_id(user["national_id_ciphertext"])

    return render_template("reviewer_dashboard.html", current_user=current_user, pending_users=pending_users)

@app.route("/admin_dashboard")
@login_required
@roles_required("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html", user=current_user)       

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    return render_template("reset-password.html")

@app.route("/review_user/<int:user_id>", methods=["POST"])
@login_required
@roles_required("admin", "reviewer")
def reject_user(user_id):

    # Get action
    action = request.form.get("action")

    # Check which action was comitted
    if action == "request_correction":
        # Update database and switch the user to the users table
        
        # Send email to user

        flash("An email was sent to resubmit data", "success")
    elif action == "reject":
        # Get message from form

        # Make sure there is a message

        # Update database 

        # Send email to user

        flash("a rejection email was sent", "success")
    else:
        # Get message from form

        # Make sure there is a message

        # Update database 

        # Send email to user

        flash("user approved", "success")

    return redirect(url_for("reviewer_dashboard"))

    


if __name__ == "__main__":
    app.run(debug=True)


