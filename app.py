import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from datetime import datetime
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from models import User, PendingUser, EncryptedNationalID, Document, PendingDocument, HistoryLog
from helpers import allowed_extensions, generate_new_filename, handle_intergrity_error, roles_required, decrypt_national_id, send_mail, send_set_password_email, send_email_verification_email, STANDARD_DOCUMENTS, generate_document_qr_token
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import generate_password_hash
import hashlib
from extensions import mail
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from dotenv import load_dotenv
import mimetypes

load_dotenv()

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["NATIONAL_ID_ENCRYPTION_KEY"] = os.getenv(
    "NATIONAL_ID_ENCRYPTION_KEY")
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH"))

# Ensure that the upload folder exists
app.config["UPLOAD_FOLDER"] = os.path.join(
    app.root_path, os.getenv("UPLOAD_FOLDER"))
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
                    return redirect("/admin-dashboard")
                elif user.role == "reviewer":
                    return redirect("/reviewer-dashboard")
                else:
                    return redirect("/user-dashboard")
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

        # Placing the required field in a dictionary in order to iterate
        required_fields = {
            "Full name": full_name,
            "Birthdate": birthdate,
            "Email": email,
            "Phone number": phone,
            "Username": username,
            "National ID number": national_id
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
            flash("National ID Number must be exactly 11 digits", "warning")
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
        encrypted = EncryptedNationalID(
            pending_id=pending_id, user_id=None, national_id_plain=national_id)
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


@app.route("/check-inbox")
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

        try:
            id = s.loads(
                token,
                salt="email-verification",
                max_age=1800
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
            flash(
                "Request recieved successfully.Please wait for a reviewer approval before logging in", "success")
            return redirect(url_for("home"))


@app.route("/user-dashboard")
@login_required
@roles_required("user", "admin")
def user_dashboard():
    return render_template("user_dashboard.html", user=current_user)


@app.route("/reviewer-dashboard")
@login_required
@roles_required("admin", "reviewer")
def reviewer_dashboard():

    # Get all the pending users
    pending_users = PendingUser.get_verified_pending_users()

    if pending_users:

        # Decrypt the national ID number
        for user in pending_users:
            user["national_id"] = decrypt_national_id(
                user["national_id_ciphertext"])

        return render_template("reviewer_dashboard.html", current_user=current_user, pending_users=pending_users)

    else:
        return render_template("reviewer_dashboard.html")


@app.route("/admin-dashboard")
@login_required
@roles_required("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html", user=current_user)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    return render_template("reset-password.html")


@app.route("/review-user/<int:pending_id>", methods=["POST"])
@login_required
@roles_required("admin", "reviewer")
def review_user(pending_id):

    # Get action
    action = request.form.get("action")

    # Check which action was comitted
    if action == "approve":
        # Create the user in the users table
        pending_user = PendingUser.get_by_id(pending_id)
        if not pending_user:
            flash("User not found", "danger")
            return redirect(url_for("review_queue"))

        created = PendingUser.verify_user(pending_id)
        if not created:
            flash("Failed to create user record.", "danger")
            return redirect(url_for("review_queue"))

        user = User.get_by_id(created.id)

        # Try sending set-password email, but proceed with cleanup regardless of email outcome
        email_success = False
        try:
            email_success = send_set_password_email(user)
        except Exception as e:
            app.logger.error(f"Error sending set-password email: {e}")

        # Remove pending records (pending_verifications row and associated encrypted national id)
        try:
            pending_user.delete_user()
            # also remove any encrypted national id entries for this pending id
            db.execute(
                "DELETE FROM national_id_encrypted WHERE pending_id = ?", pending_id)
        except Exception as e:
            app.logger.error(
                f"Error cleaning up pending records for id {pending_id}: {e}")

        if email_success:
            flash("User approved", "success")
        else:
            flash("User approved but we couldn't send the notification email. Please try resending manually.", "warning")

        return redirect(url_for("review_queue"))

    elif action == "reject":

        # Get message from form
        message = request.form.get("message").strip()

        # Make sure there is a message
        if not message:
            flash("Please provide a reason for rejection", "warning")
            return redirect(url_for("review_queue"))

        # Get user data before deletion
        pending_user = PendingUser.get_by_id(pending_id)

        if not pending_user:
            flash("User not found", "danger")
            return redirect(url_for("review_queue"))

        # Log the rejection reason in the registeration_reviews table
        PendingUser.log_rejection(
            user_id=pending_id,
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

        # Clean up identities, pending_verifications and encrypted national id regardless of email result
        try:
            pending_user.delete_from_identities()
        except Exception as e:
            app.logger.error(
                f"Error deleting identities for pending {pending_id}: {e}")

        try:
            pending_user.delete_user()
        except Exception as e:
            app.logger.error(
                f"Error deleting pending_verifications for pending {pending_id}: {e}")

        try:
            db.execute(
                "DELETE FROM national_id_encrypted WHERE pending_id = ?", pending_id)
        except Exception as e:
            app.logger.error(
                f"Error deleting encrypted national id for pending {pending_id}: {e}")

        if email_success:
            flash("User rejected and notification email sent", "success")
        else:
            flash("User rejected; notification email failed to send.", "warning")

        return redirect(url_for("review_queue"))

    elif action == "request_correction":

        # Get message from form
        message = request.form.get("message", "").strip()

        # Make sure there is a message
        if not message:
            flash("Please provide a reason for correction request", "warning")
            return redirect(url_for("review_queue"))

        pending_user = PendingUser.get_by_id(pending_id)

        if not pending_user:
            flash("User not found", "danger")
            return redirect(url_for("review_queue"))

        # Log the correction request in the registeration_reviews table
        PendingUser.log_correction_request(
            user_id=pending_id,
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

        # Remove identities and pending records so user can re-register (keep encrypted id as well)
        try:
            pending_user.delete_from_identities()
        except Exception as e:
            app.logger.error(
                f"Error deleting identities for pending {pending_id}: {e}")

        try:
            pending_user.delete_user()
        except Exception as e:
            app.logger.error(
                f"Error deleting pending_verifications for pending {pending_id}: {e}")

        try:
            db.execute(
                "DELETE FROM national_id_encrypted WHERE pending_id = ?", pending_id)
        except Exception as e:
            app.logger.error(
                f"Error deleting encrypted national id for pending {pending_id}: {e}")

        if email_success:
            flash("Correction request sent to user", "success")
        else:
            flash(
                "Correction request logged but we couldn't send the notification email", "warning")

        return redirect(url_for("review_queue"))

    else:
        return redirect(url_for("review_queue"))


@app.route("/set-password/<token>", methods=["GET", "POST"])
def set_password(token):

    if current_user.is_authenticated:
        return redirect(url_for("user_dashboard"))

    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])

    try:
        # detokenize the token
        user_id = s.loads(
            token,
            salt="password-set-salt",
            max_age=86400
        )
    except SignatureExpired:
        payload_part = token.split('.')[0]

        try:
            # 3. Decode only that first part
            user_id = s.load_payload(payload_part.encode('utf-8'))
        except Exception as e:
            print(f"Extraction Error: {e}")
            user_id = None  # Fallback if even that fails

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
        password_success = User.update_password(user_id, password)
        if password_success:
            user_to_login = User.get_by_id(user_id)

            if user_to_login:

                flash("Welcome! Your password has been set successfully.", "success")
                login_user(user_to_login)

                # initialize user documents placeholders
                Document.create_placeholders_for_user(current_user.id)

                return redirect(url_for("user_dashboard"))
            else:
                flash("Something went wrong. Please try logging in.", "warning")
                return redirect(url_for("login"))
        else:
            flash("Something went wrong. Please try again later.", "warning")
            return redirect(url_for("set_password", token=token))

    elif request.method == "GET":

        # add a landing page for the user where the user submits a form

        user = User.get_by_id(user_id)
        if not user:
            flash("Invalid password reset request", "error")
            return redirect(url_for("login"))

        return render_template("set_password.html", full_name=user.full_name, token=token)


@app.route("/link-expired", methods=["GET", "POST"])
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


@app.route("/about-sudan")
def about_sudan():
    return render_template("about_sudan.html")


@app.route("/my-documents")
@login_required
def my_documents():

    docs = {}

    for doc_type, doc_name in STANDARD_DOCUMENTS.items():
        docs[doc_type] = {
            "id": None,
            "name": doc_name,
            "type": doc_type,
            "status": "not_uploaded",
            "issued": "-",
            "has_file": False,
            "file_url": None,
            "qr_link": None
        }

    user_docs = Document.get_by_user(current_user.id)

    if user_docs:
        for row in user_docs:
            doc_type = row.document_type
            if doc_type in docs:
                docs[doc_type].update({
                    "id": row.id,
                    "status": row.status,
                    "issued": row.issued or "-",
                    "has_file": bool(row.has_file),
                    "file_url": url_for("static", filename=row.file_path) if row.file_path else None,
                    "qr_link": url_for("verify_document", token=row.qr_token, _external=True) if row.qr_token else None,

                })

    return render_template("my_documents.html", docs=list(docs.values()))


@app.route("/my-documents/verify_document/<token>")
@login_required
@roles_required("admin", "reviewer")
def verify_document(token):

    # Decode the token
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])

    try:

        payloads = s.loads(
            token,
            salt="document-qr"
        )

    except BadSignature:
        flash("Invalid verification request", "danger")
        return redirect(url_for("my_documents"))

    document_id = payloads.get("document_id")
    user_id = payloads.get("user_id")

    if not document_id or not user_id:
        flash("Invalid verification request", "danger")
        return redirect(url_for("my_documents"))

    document = Document.get_by_id(document_id)

    if not document or document.user_id != user_id or document.qr_token != token:
        flash("Invalid verification request", "error")
        return redirect(url_for("my_documents"))

    user = User.get_by_id(user_id)
    name = user.full_name
    birthdate = user.birthdate

    return render_template("verify_document.html", document=document, name=name, birthdate=birthdate)


@app.route("/my-documents/upload-document", methods=["GET", "POST"])
@login_required
def upload_document():

    doc_type = request.args.get("type")

    if not doc_type or doc_type not in STANDARD_DOCUMENTS.keys():
        return redirect(url_for("my_documents"))

    if request.method == "POST":

        # check if user is authenticated
        if not current_user.is_authenticated:
            return redirect(url_for("login"))

        # load the user's document row
        document_row = Document.get_by_user_and_type(current_user.id, doc_type)

        if not document_row:
            flash("Document record not founded", "danger")
            return redirect(url_for("my_documents"))

        # get fields
        file = request.files.get("document")
        notes = request.form.get("notes")
        declaration = request.form.get("declaration")

        # check fields
        if not file or file.filename == "":
            flash("Please select a document file to upload", "warning")
            return redirect(url_for("upload_document"))
        if not notes:
            notes = None
        if not declaration:
            flash("Please check the declaration", "warning")
            return redirect(url_for("my_documents"))

        # check filetype and size
        if not allowed_extensions(file.filename):
            flash("The Document format you uploaded is not supported", "warning")
            return redirect(url_for("upload_document"))

        # Secure and generate new filename
        filename = secure_filename(file.filename)
        new_filename = generate_new_filename(filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)

        # Save the uploaded file
        file.save(file_path)

        # Relative filepath
        relative_path = f"uploads/{new_filename}"

        # Mimetype
        mimetype, _ = mimetypes.guess_type(new_filename)

        # Size
        size = os.path.getsize(file_path)

        # insert record into the pending documents table
        pending_document_id = PendingDocument.insert_pending(
            user_id=current_user.id,
            document_id=document_row.id,
            document_type=doc_type,
            original_filename=filename,
            file_path=relative_path,
            mimetype=mimetype,
            size=size,
            notes=notes
        )

        Document.mark_pending(current_user.id, doc_type)

        # log into history
        HistoryLog.log_action(actor_user_id=current_user.id, target_user_id=current_user.id, action="Document upload",
                              entity_type="pending_document", entity_id=pending_document_id, status="pending", description=f"{doc_type} submitted for review")

        # flash success message
        flash("Document submitted for review", "success")

        # redirect user back
        return redirect(url_for("my_documents"))

    else:
        return render_template("upload_document.html", doc_type=doc_type)


@app.route("/history")
@login_required
def history():
    return render_template("history.html")


@app.route("/my-profile")
@login_required
def my_profile():
    return render_template("my_profile.html")


@app.route("/my-profile/update-contact", methods=["POST"])
@login_required
def update_contact():

    # get fields
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip().replace(" ", "")
    address = request.form.get("address", "").strip()

    # validate fields
    if not email:
        flash("Please provide an email address.", "warning")
        return redirect(url_for("my_profile"))

    if "@" not in email or "." not in email.split("@", 1)[1]:
        flash("Please provide a valid email address.", "warning")
        return redirect(url_for("my_profile"))

    if not phone:
        flash("Please provide a phone number.", "warning")
        return redirect(url_for("my_profile"))

    if not phone.startswith("+249") or len(phone) != 13 or not phone[4:].isdigit():
        flash("Phone number must use the format +249 followed by 9 digits.", "warning")
        return redirect(url_for("my_profile"))

    # compare the submitted email with the database
    email_changed = email != current_user.contact_email
    existing_user = User.get_by_email(email)
    if existing_user and existing_user.id != current_user.id:
        flash("That email address is already in use by another account.", "warning")
        return redirect(url_for("my_profile"))

    # if not equal
    if email_changed:

        # update databse(users) with new email
        update_success = User.update_contact_info(
            current_user.id,
            email,
            phone,
            address,
            email_verified=0
        )

        if not update_success:
            flash(
                "We could not update your contact details. Please try again later.", "danger")
            return redirect(url_for("my_profile"))

        # set email_verified = 0
        current_user.contact_email = email
        current_user.contact_phone = phone
        current_user.address = address
        current_user.email_verified = 0

        # generate token using itsdangerous
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        token = serializer.dumps(
            {"user_id": current_user.id, "new_email": email},
            salt="email-change"
        )
        verify_url = url_for("verify_new_email", token=token, _external=True)

        # send verification to new email
        email_success = send_mail(
            subject="Confirm your new email address",
            recipients=[email],
            template="verify_email.html",
            name=current_user.full_name,
            verify_url=verify_url
        )

        # log into history
        HistoryLog.log_action(
            actor_user_id=current_user.id,
            target_user_id=current_user.id,
            action="updated_contact_info",
            entity_type="user",
            entity_id=current_user.id,
            status="pending",
            description="Contact details updated and email verification pending"
        )

        if email_success:
            flash("Your contact details were updated. Please verify your new email address.", "info")
        else:
            flash("Your contact details were updated, but the verification email could not be sent. Please try again later.", "warning")

    # else email is same
    else:

        # create methode for updating the address and phone no. only
        update_success = User.update_contact_info(
            current_user.id,
            email,
            phone,
            address,
            email_verified=current_user.email_verified if current_user.email_verified is not None else 1
        )

        if not update_success:
            flash("We could not update your contact details. Please try again later.", "danger")
            return redirect(url_for("my_profile"))

        current_user.contact_email = email
        current_user.contact_phone = phone
        current_user.address = address

        # log to history
        HistoryLog.log_action(
            actor_user_id=current_user.id,
            target_user_id=current_user.id,
            action="updated_contact_info",
            entity_type="user",
            entity_id=current_user.id,
            status="success",
            description="Contact details updated successfully"
        )

        flash("Your contact details were updated successfully.", "success")

    return redirect(url_for("my_profile"))


@app.route("/verify_new_email/<token>", methods=["GET", "POST"])
@login_required
def verify_new_email(token):

    # validate token
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

    try:
        payload = serializer.loads(token, salt="email-change", max_age=86400)
    except SignatureExpired:
        flash("This email verification link has expired.", "warning")
        return redirect(url_for("my_profile"))
    except BadSignature:
        flash("This email verification link is invalid.", "danger")
        return redirect(url_for("my_profile"))

    # if valid set email verified to true
    user_id = payload.get("user_id")
    new_email = payload.get("new_email")

    if not user_id or not new_email:
        flash("This email verification link is invalid.", "danger")
        return redirect(url_for("my_profile"))

    if int(user_id) != current_user.id:
        flash("You are not authorized to use this verification link.", "danger")
        return redirect(url_for("my_profile"))

    if User.update_email_verification_status(current_user.id, True):
        current_user.email_verified = 1
        current_user.contact_email = new_email
        flash("Your new email address has been verified successfully.", "success")
    else:
        flash(
            "We could not verify your new email address. Please try again later.", "danger")

    return redirect(url_for("my_profile"))


@app.route("/my-profile/change-password", methods=["POST"])
@app.route("/profile/change-password", methods=["POST"])
@login_required
def change_password():

    # get fields
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    # validate fields
    if not current_password or not new_password or not confirm_password:
        flash("Please fill in all password fields.", "warning")
        return redirect(url_for("my_profile"))

    if len(new_password) < 8:
        flash("New password must be at least 8 characters long.", "warning")
        return redirect(url_for("my_profile"))

    # verify new and confirmation
    if new_password != confirm_password:
        flash("The new password and confirmation do not match.", "danger")
        return redirect(url_for("my_profile"))

    # identity verifiaction current_user.verify_password(current_password)
    if not current_user.verify_password(current_password):
        flash("Your current password is incorrect.", "danger")
        return redirect(url_for("my_profile"))

    # finalize by calling User.update_password()
    if not User.update_password(current_user.id, new_password):
        flash("We could not update your password. Please try again later.", "danger")
        return redirect(url_for("my_profile"))

    # log to history
    HistoryLog.log_action(
        actor_user_id=current_user.id,
        target_user_id=current_user.id,
        action="changed_password",
        entity_type="user",
        entity_id=current_user.id,
        status="success",
        description="Password updated successfully"
    )

    flash("Your password was updated successfully.", "success")
    return redirect(url_for("my_profile"))


@app.route("/my-profile/upload-picture", methods=["POST"])
@login_required
def upload_picture():

    # get the file
    file = request.files.get("avatar")

    # validate file and extension
    if not file or file.filename == "":
        flash("Please select a profile picture to upload.", "warning")
        return redirect(url_for("my_profile"))

    if not allowed_extensions(file.filename):
        flash("Only PNG, JPG, JPEG, and WEBP images are allowed.", "warning")
        return redirect(url_for("my_profile"))

    # save into uploads folder
    filename = secure_filename(file.filename)
    new_filename = generate_new_filename(filename)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)
    file.save(file_path)

    # update database with path
    relative_path = f"uploads/{new_filename}"
    if not User.update_profile_picture(current_user.id, relative_path):
        flash("We could not update your profile picture. Please try again later.", "danger")
        return redirect(url_for("my_profile"))

    current_user.profile_picture = relative_path

    # log to history
    HistoryLog.log_action(
        actor_user_id=current_user.id,
        target_user_id=current_user.id,
        action="updated_profile_picture",
        entity_type="user",
        entity_id=current_user.id,
        status="success",
        description="Profile picture updated successfully"
    )

    flash("Your profile picture was updated successfully.", "success")
    return redirect(url_for("my_profile"))


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


@app.route("/notifications")
@login_required
def notifications():
    return render_template("notifications.html")


@app.route("/help-and-support")
def help_and_support():
    return render_template("help_and_support.html")


@app.route("/review-queue")
@login_required
@roles_required("admin", "reviewer")
def review_queue():

    # Get all the pending users
    pending_users = PendingUser.get_verified_pending_users() or []

    # Decrypt the national ID number for users in the queue
    for user in pending_users:
        user["national_id"] = decrypt_national_id(
            user["national_id_ciphertext"])

    # Load pending documents regardless of whether there are pending users
    pending_documents = PendingDocument.get_queue() or []

    return render_template(
        "review_queue.html",
        current_user=current_user,
        pending_users=pending_users,
        pending_documents=pending_documents,
    )


@app.route("/review-document/<int:pending_document_id>", methods=["POST"])
@login_required
@roles_required("admin", "reviewer")
def review_document(pending_document_id):

    # Get actions
    action = request.form.get("action")

    # Get message
    message = request.form.get("message")

    # Load PendingDocument
    pending_document = PendingDocument.get_by_id(pending_document_id)

    if not pending_document:
        flash("Document not found", "danger")
        return redirect(url_for("review_queue"))

    # Load user info
    info = PendingDocument.get_user_info(pending_document_id)

    if not info:
        flash("User information not found", "danger")
        return redirect(url_for("review_queue"))

    email = info["contact_email"]
    name = info["full_name"]

    # If action is approve
    if action == "approve":

        # Generate a unique qr token
        qr_token = generate_document_qr_token(
            pending_document.document_id, pending_document.user_id)

        PendingDocument.approve(pending_document_id, current_user.id, message)

        Document.mark_verified(pending_document.document_id, pending_document.file_path,
                               pending_document.original_filename, pending_document.mimetype, pending_document.size, qr_token)

        subject = f"Status Update: {pending_document.original_filename} Approved"
        recipients = [email]
        template = "document_approved_email.html"

        email_success = send_mail(
            subject=subject,
            recipients=recipients,
            template=template,
            name=name
        )

        # Log to history
        HistoryLog.log_action(current_user.id, pending_document.user_id, "document_approved", "document",
                              pending_document.document_id, "approved", description=f"{pending_document.document_type} approved by reviewer")

        if email_success:
            PendingDocument.set_decision_email_status(pending_document_id)
            flash("Document approved and notification email sent successfully", "success")
        else:
            flash("Document approved and notification email failed", "warning")

        return redirect(url_for("review_queue"))

    # If action is reject | correction requested
    elif action == "reject" or action == "request_correction":

        # Require message
        if not message:
            flash("Please provide a reason for your action")
            return redirect(url_for("review_queue"))

        if action == "reject":

            # Mark rejected
            PendingDocument.reject(pending_document.id,
                                   current_user.id, message)

            Document.mark_rejected(
                pending_document.user_id, pending_document.document_type)

            # set email subject
            subject = f"Status Update: {pending_document.original_filename} Rejected"

            # Log history
            HistoryLog.log_action(current_user.id, pending_document.user_id, "document_rejected", "document",
                                  pending_document.document_id, "rejected", description=f"{pending_document.document_type} rejected by reviewer")

        else:

            # Mark correction requested
            PendingDocument.request_correction(
                pending_document.id, current_user.id, message)

            Document.mark_correction_requested(
                pending_document.user_id, pending_document.document_type)

            # set email subject
            subject = f"Status Update: {pending_document.original_filename} Action Needed"

            # Log history
            HistoryLog.log_action(current_user.id, pending_document.user_id, "correction_requested", "document", pending_document.document_id,
                                  "correction requested", description=f"correction requested for {pending_document.document_type} by reviewer")

        recipients = [email]
        template = "document_approved_email.html"

        email_success = send_mail(
            subject=subject,
            recipients=recipients,
            template=template,
            name=name,
            message=message
        )

        if email_success:
            PendingDocument.set_decision_email_status(pending_document_id)
            flash("Action taken and notification email sent successfully", "success")
        else:
            flash("Action taken and notification email failed", "warning")

        return redirect(url_for("review_queue"))

    else:

        flash("Invalid action", "danger")
        return redirect(url_for("review_queue"))


@app.route("/reviewed-documents")
@login_required
@roles_required("admin", "reviewer")
def reviewed_documents():
    return render_template("reviewed_documents.html")


@app.route("/privacy-policy")
def privacy_policy():
    return render_template("privacy_policy.html")


@app.route("/terms-and-conditions")
def terms_and_conditions():
    return render_template("terms_and_conditions.html")


@app.route("/report-bugs")
def report_bugs():
    return render_template("report-bugs.html")


@app.route("/system-settings")
@login_required
@roles_required("admin")
def system_settings():
    return render_template("system_settings.html")


@app.route("/manage-users")
@login_required
@roles_required("admin")
def manage_users():

    # Load pending users
    pending_users = PendingUser.get_verified_pending_users()

    # Load verified users
    users = User.load_users()

    return render_template("manage_users.html", pending_users=pending_users, users=users)


@app.route("/admin/users/save", methods=["POST"])
@login_required
@roles_required("admin")
def save_user():

    # check if id was provided
    user_id = request.form.get("user_id")

    name = request.form.get("full_name", "").strip()
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    role = request.form.get("role")
    birthdate = request.form.get("birthdate")

    required_fields = {
        "Full name": name,
        "Username": username,
        "Email": email,
        "Phone": phone,
        "Role": role,
        "Birthdate": birthdate
    }

    for label, value in required_fields.items():
        if not value:
            flash(f"Please fill in the {label} field.", "warning")
            return redirect(url_for("manage_users"))

    if role not in ["user", "admin", "reviewer"]:
        flash("Invalid role selected", "warning")
        return redirect(url_for("manage_users"))

    # creating a new user
    if not user_id:

        national_id = request.form.get("national_id")
        password = request.form.get("password")

        # Validate required fields
        create_required = {
            "National ID number": national_id,
            "Password": password
        }

        for label, value in create_required.items():
            if not value:
                flash(
                    f"Please fill in the {label} field in order to create a new user", "warning")
                return redirect(url_for("manage_users"))

        if not national_id.isdigit() or len(national_id) != 11:
            flash("National ID Number must be exactly 11 digits", "warning")
            return redirect(url_for("manage_users"))

        # use pending user object temporarily to insert into identities
        temp_user = PendingUser(full_name=name, national_id=national_id, birthdate=birthdate,
                                contact_email=email, contact_phone=phone, username=username, status="verified")

        try:
            temp_user.insert_to_identities()
        except Exception as e:
            flash(handle_intergrity_error(e), "warning")
            return redirect(url_for("manage_users"))

        user = User()

        user.full_name = name
        user.username = username
        user.national_id = national_id
        user.birthdate = birthdate
        user.contact_email = email
        user.contact_phone = phone
        user.role = role
        user.password = password

        user_id = user.insert()

        if user_id:

            Document.create_placeholders_for_user(user_id)

            # log into history
            HistoryLog.log_action(current_user.id, user_id, "admin_created_user",
                                  "user", user_id, "success", f"Admin created user account for {name}.")

            flash("User created", "success")
            return redirect(url_for("manage_users"))
        else:
            flash("User not created", "error")
            return redirect(url_for("manage_users"))

    # update user
    else:

        # load user details before updating
        original_user = User.get_by_id(user_id)
        original_username = original_user.username

        # update
        success = User.update(user_id, original_username,
                              username, name, birthdate, email, phone, role)

        if success:

            HistoryLog.log_action(current_user.id, user_id, "admin_edited_account",
                                  "user", user_id, "success", f"Admin edited user account for {name}.")

            flash("User information updated", "success")
            return redirect(url_for("manage_users"))


@app.route("/admin/users/delete", methods=["POST"])
@login_required
@roles_required("admin")
def delete_user():

    # get id
    user_id = request.form.get("user_id")

    # validate id
    if not user_id:
        flash("User not found", "warning")
        return redirect(url_for("manage_users"))

    # exit if the id is == to current user id
    if user_id == current_user.id:
        flash("Self-service account deletion is not available")
        return redirect(url_for("manage_users"))

    # verify target user exists
    user = User.get_by_id(user_id)

    if not user:
        flash("User not found", "warning")
        return redirect(url_for("manage_users"))

    username = user.username
    name = user.full_name

    # log action
    HistoryLog.log_action(current_user.id, user_id, "admin_deleted_user",
                          "user", user_id, "success", f"Admin deleted user account for {name}.")

    # delete user
    if User.delete_user(user_id, username):

        # flash
        flash("User account deleted", "success")
        return redirect(url_for("manage_users"))

    else:
        flash("Error deleting user", "error")
        return redirect(url_for("manage_users"))


@app.route("/services")
def services():
    return render_template("services.html")


@app.route("/agencies")
def agencies():
    return render_template("agencies.html")


if __name__ == "__main__":
    app.run(debug=True)
