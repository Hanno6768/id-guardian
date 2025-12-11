
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

app = Flask(__name__)
# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///idguardian.db")

@app.route("/")
def index():
    return render_template("layout.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # user reached here via POST
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # check for username and password
        if not username:
            flash("must provide username", "error")
            return render_template("login.html")
        elif not password:
            flash("must provide password", "error")
            return render_template("login.html")
        
        # username and password where provided
        else:

            # check if username and password match in database

            # if ussername and password doesn't match take user back to the login.html
            

    else:
        return render_template("login.html")

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)


