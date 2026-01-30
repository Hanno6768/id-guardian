import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from datetime import datetime
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from models import User, PendingUser, EncryptedNationalID
from helpers import allowed_extensions, generate_new_filename, handle_intergrity_error, roles_required, decrypt_national_id, send_mail, send_set_password_email, send_email_verification_email
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from extensions import mail
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

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///idguardian.db")

app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT"))
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS") == "True"
app.config["MAIL_USE_SSL"] = os.getenv("MAIL_USE_SSL") == "True"

mail.init_app(app)

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
    # username = "reviewer1"
    # password_hash = generate_password_hash("test")
    # national_id = "00000000011"
    # national_id_hash = sha256(national_id.encode("utf-8")).hexdigest()
    # full_name = "reviewer1"
    # birthdate = "2000-07-08"
    # contact_email = "reviewer1@gmail.com"
    # contact_phone = "+249000000000"
    # verified_at = datetime.now()
    # national_id_fast = national_id_hash[-10:]
    # role = "reviewer"
    # db.execute("""
    #                 INSERT INTO users (username, 
    #            password_hash, national_id_hash, full_name, 
    #            birthdate, contact_email, contact_phone, verified_at, 
    #            national_id_fast, role) VALUES (?,?,?,?,?,?,?,?,?,?)
    #            """, username, password_hash, national_id_hash, full_name, birthdate,
    #            contact_email, contact_phone, verified_at, national_id_fast, role)
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
            if user.password is None:
                flash("Please set your password before logging in", "warning")
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
            flash("The Document format you uploaded is not supported", "warning")
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
            identities_id = user.insert_to_identities()
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

        # Assign the identities_id to the user object
        user.identities_id = identities_id

        # Insert Object into pending_verifications table
        pending_id = user.insert_to_pending()
        user.id = pending_id
        
        # Encrypt national id and insert into national_id_encrypted
        encrypted = EncryptedNationalID(pending_id=pending_id, user_id=None, national_id_plain=national_id)
        encrypted.encrypt()
        encrypted.insert()

        # Email verification
        email_success = send_email_verification_email(user)

        if email_success:
            # set the registeration started session to true so user can only open the 
            # /check_inbox after submitting the register form
            session["registration_started"] = True
            flash("A message was sent to your inbox", "info")
        else:
            flash("Something went wrong. Try again later", "error")
            return redirect(url_for("register"))

        # redirect user to /check_inbox route
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
            id = s.loads(
                token,
                salt = "email-verification",
                max_age = 1800
            )
        except SignatureExpired:
        # 1. Isolate the payload (the part before the first dot)
            payload_part = token.split('.')[0] 
        
            try:
                # 2. Decode ONLY that first part
                # Use .encode('utf-8') to satisfy the bytes requirement we saw earlier
                user_id = s.load_payload(payload_part.encode('utf-8'))
            except Exception:
                user_id = None

            # store data in a seesion to avoid manual url tampering
            session["expired_user_id"] = user_id
            session["expired_source"] = "verify_email"

            return redirect(url_for("link_expired"))
        except BadSignature:
            flash("Invalid verification request", "error")
            return redirect(url_for("register"))
        
        # see if user's email exist in the database
        user = PendingUser.get_by_id(id)

        if not user:
            flash("Invalid verification request", "error")
            return redirect(url_for("register"))
        else: 
            user.update_email_status(user.contact_email)
            session.pop("registration_started", None)
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

@app.route("/review_user/<int:pending_id>", methods=["POST"])
@login_required
@roles_required("admin", "reviewer")
def review_user(pending_id):

    # Get action
    action = request.form.get("action")

    # Check which action was comitted
    if action == "approve":
        
        # Update database
        pending_user = PendingUser()
        pending_user = PendingUser.get_by_id(pending_id)
        user = User()
        user_id = pending_user.verify_user(pending_id).id

        user = User.get_by_id(user_id)

        email_success = send_set_password_email(user)

        if email_success:
            # Delete the user from the pending_verifications & identities tables
            pending_user.delete_user()

            flash("user approved", "success")
        else:
            flash("We couldn't notify the user. Please try again later", "warning")
            return redirect(url_for("reviewer_dashboard"))

        return redirect(url_for("reviewer_dashboard"))
    
    elif action == "reject":

        # Get message from form
        message = request.form.get("message").strip()

        # Make sure there is a message
        if not message:
            flash("Please provide a reason for rejection", "warning")
            return redirect(url_for("reviewer_dashboard"))
        
        # Get user data before deletion
        pending_user = PendingUser.get_by_id(user_id)
        
        if not pending_user:
            flash("User not found", "danger")
            return redirect(url_for("reviewer_dashboard"))
        
        # Log the rejection reason in the registeration_reviews table
        PendingUser.log_rejection(
            user_id=user_id,
            reviewer_name=current_user.full_name,
            rejection_reason=message,
            file_path=pending_user.file_path
        )
        
        # Send rejection email to user
        subject = "Your SudaGuardian Application Status"
        recipients = [pending_user.contact_email]
        template = "rejection_email.html"
        
        email_success = send_mail(
            subject=subject,
            recipients=recipients,
            template=template,
            name=pending_user.full_name,
            reviewer_message=message
        )
        
        if email_success:
            # Delete the user from the pending_verifications table
            pending_user.delete_from_identities()
            flash("User rejected and notification email sent", "success")
        else:
            flash("We couldn't send the notification email, Please try again", "warning")
        
        return redirect(url_for("reviewer_dashboard"))
    
    elif action == "request_correction":

        # Get message from form
        message = request.form.get("message", "").strip()

        # Make sure there is a message
        if not message:
            flash("Please provide a reason for correction request", "warning")
            return redirect(url_for("reviewer_dashboard"))
        
        pending_user = PendingUser.get_by_id(user_id)
        
        if not pending_user:
            flash("User not found", "danger")
            return redirect(url_for("reviewer_dashboard"))
        
        # Log the correction request in the registeration_reviews table
        PendingUser.log_correction_request(
            user_id=user_id,
            reviewer_name=current_user.full_name,
            correction_reason=message,
            file_path=pending_user.file_path
        )
        
        # Send correction request email to user
        subject = "Action Required: Resubmit Information for SudaGuardian Application"
        recipients = [pending_user.contact_email]
        template = "correction_request_email.html"
        
        email_success = send_mail(
            subject=subject,
            recipients=recipients,
            template=template,
            name=pending_user.full_name,
            reviewer_message=message
        )
        
        if email_success:
            # TODO : get the data that needs correction from the pending_user object and prefill the registeration form with it
            pending_user.delete_from_identities()
            flash("Correction request sent to user", "success")
        else:
            flash("Correction request logged but we couldn't send the notification email", "warning")
        
        return redirect(url_for("reviewer_dashboard"))

    else:
        return redirect(url_for("reviewer_dashboard"))

@app.route("/set_password/<token>", methods=["GET", "POST"])
def set_password(token):
    # complete logic for setting the password
    if current_user.is_authenticated:
        return redirect(url_for("user_dashboard"))
    
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])

    try:
        # detokenize the token
        user_id = s.loads(
            token,
            salt = "password-set-salt",
            max_age = 86400
        )
    except SignatureExpired:
        payload_part = token.split('.')[0] 
    
        try:
            # 3. Decode only that first part
            user_id = s.load_payload(payload_part.encode('utf-8'))
        except Exception as e:
            print(f"Extraction Error: {e}")
            user_id = None # Fallback if even that fails

        if user_id:

        # store data in a seesion to avoid manual url tampering
            session["expired_user_id"] = user_id
            session["expired_source"] = "set_password"

            return redirect(url_for("link_expired"))

        else:
            flash("the link is expired and can not be recovered.", "error")
            return redirect(url_for("login"))
        
    except BadSignature:
            flash("Invalid password reset request", "error")
            return redirect(url_for("login"))
    
    # When user submits form
    if request.method == "POST":
        password = request.form.get("password")
        confirmation = request.form.get("confirm_password")

        if not password or not confirmation:
            flash("Please fill in both fields.", "warning")
            return redirect(url_for("set_password", token=token))
        
        if password != confirmation:
            flash("Passwords does not match.", "danger")
            return redirect(url_for("set_password", token=token))
        
        # hash the password and update the user record
        password_success = User.update_password(id, password)
        if password_success:
            user_to_login = User.get_by_id(id)

            if user_to_login:
                flash("Welcome! Your password has been set successfully.", "success")
                login_user(user_to_login)
                return redirect(url_for("user_dashboard"))
            else:
                flash("Something went wrong. Please try logging in.", "warning")
                return redirect(url_for("login"))
        else:
            flash("Something went wrong. Please try again later.","warning")
            return redirect(url_for("set_password", token=token))
        
    elif request.method == "GET":    

        # add a landing page for the user where the user submits a form

        user = User.get_by_id(user_id)
        if not user:
            flash("Invalid password reset request", "error")
            return redirect(url_for("login"))
        

        return render_template("set_password.html", full_name=user.full_name)
 
@app.route("/link_expired", methods=["GET", "POST"])
def link_expired():
    source = session.get("expired_source")
    user_id = session.get("expired_user_id")
    
    # Security check: if no session data, kick to home
    if not source or not user_id:
        return redirect(url_for("home"))

    if request.method == "GET":
        if source == "verify_email":
            button_text = "Resend Verification Link"
        elif source == "set_password":
            button_text = "Request New Link"
        else:
            return redirect(url_for("home"))
        
        return render_template("link_expired.html", button_text=button_text)

    # --- POST Logic ---
    email_success = False
    
    if source == "verify_email":
        user = PendingUser.get_by_id(user_id)
        if user:
            email_success = send_email_verification_email(user)
        else:
            flash("Account not found. Please register again.", "danger")
            return redirect(url_for("register"))

    elif source == "set_password":
        user = User.get_by_id(user_id)
        if user:
            email_success = send_set_password_email(user)
        else:
            flash("User not found.", "danger")
            return redirect(url_for("login"))

    # Final Outcome
    if email_success:
        session.pop("expired_source", None)
        session.pop("expired_user_id", None)
        flash("A new link has been sent to your inbox.", "info")
        
        return redirect(url_for("check_inbox")) 
    else:
        flash("We couldn't send the email. Please try again later.", "error")
        return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)