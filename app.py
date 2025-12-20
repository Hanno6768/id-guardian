import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from datetime import datetime
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from models import User, PendingUser
from helpers import allowed_extensions, generate_new_filename, handle_intergrity_error, roles_required
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
# to be deleted
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config["SECRET_KEY"] = "secretkey"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Ensure that the upload folder exists
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Enable debug mode
app.config["DEBUG"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

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
    flash("File too large. Maximum allowed size is 5 MB.")
    return redirect("/register")

# ------- Routes ----------------------------------------------------

# Home page
@app.route('/')
def home():
    return render_template("home.html")

# log user in
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        logout_user()
    #     password1 = generate_password_hash("test")
    #     national_id1 = str(11111111111)
    #     national_id1 = hashlib.sha256(national_id1.encode("utf-8")).hexdigest()
    #     national_id1_fast = national_id1[-10:]
    #     db.execute(
    #     """
    #     INSERT INTO users (
    #         username,
    #         password_hash,
    #         national_id_hash,
    #         full_name,
    #         birthdate,
    #         contact_email,
    #         contact_phone,
    #         verification_status,
    #         verified_at,
    #         national_id_fast,
    #         role
    #     )
    #     VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
    #     """,
    #     "admin1",
    #     password1,
    #     national_id1,
    #     "Admin1",
    #     "2004-05-12",
    #     "admin1@example.com",
    #     "+201234567891",
    #     "verified",
    #     national_id1_fast,
    #     "admin"
    # )

        return render_template("login.html")
    else:
        identifier = request.form.get("identifier").strip().replace(" ", "")
        password = request.form.get("password").strip().replace(" ", "")

        # Check if identifier or password weren't provided
        if not identifier:
            flash("You must provide your username or national id", "error")
            return redirect("/login")
        elif not password:
            flash("You must provide your password", "error")
            return redirect("/login")
        else:

            # Try username
            user = User.get_by_username(identifier)
            # If no user was found, try national id
            if not user:
                user = User.get_by_national_id(identifier)
            if not user:
                flash("Invalid credentials", "error")
                return redirect("/login")
            if user.verify_password(password):
                login_user(user)
                if user.role == "admin":
                    return redirect("/admin_dashboard")
                elif user.role == "reviewer":
                    return redirect("/reviewer_dashboard")
                else:
                    return redirect("user_dashboard")
            else:
                flash("Invalid credentials", "error")
                return redirect("/login")

# log user out           
@app.route("/logout")
def logout():
    logout_user()
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        full_name = request.form.get("name", "").strip()
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
                flash(f"Please fill in your {key} field")
                return redirect("/register")
        
        # Check if there is a document uploaded
        if not document or document.filename == "":
            flash("Please upload your ID document file")
            return redirect("/register")

        # Check if the document type supported
        if not allowed_extensions(document.filename):
            flash("The Document formate you uploaded is not supported")
            return redirect("/register")
            
        # Validate the national_id
        if not national_id.isdigit() or len(national_id) != 11:
            flash ("National ID Number must be exactly 11 digits")
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
            flash(handle_intergrity_error(e))
            return redirect("/register")

        # Secure and generate filename
        filename = secure_filename(document.filename)
        new_filename = generate_new_filename(filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)

        # Save the uploaded file
        document.save(file_path)

        # Insert the path of the file in the user object
        user.file_path = file_path

        # Insert Object into pending_verifications table
        user.insert_to_pending()

        flash("Registration submitted successfully. Await verification.")
        return redirect("/register")


@app.route("/user_dashboard")
@login_required
@roles_required("user", "admin")
def user_dashboard():
    return render_template("user_dashboard.html", user=current_user)

@app.route("/reviewer_dashboard")
@login_required
@roles_required("admin", "reviewer")
def reviewer_dashboard():
    return render_template("reviewer_dashboard.html", user=current_user)

@app.route("/admin_dashboard")
@login_required
@roles_required("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html", user=current_user)
        

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    return render_template("reset-password.html")


if __name__ == "__main__":
    app.run(debug=True)


