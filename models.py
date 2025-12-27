from cs50 import SQL
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from flask_login import UserMixin
from datetime import datetime

db = SQL("sqlite:///idguardian.db")

# created a user object using copilot to understand the structure 
class User(UserMixin):
    def __init__(self, id, username, password, national_id, full_name, birthdate, email, phone, verification_status, verified_at, national_id_fast, role):
        self.id = id
        self.username = username
        self.password = password
        self.national_id = national_id
        self.full_name = full_name
        self.birthdate = birthdate
        self.email = email
        self.phone = phone
        self.verification_status = verification_status
        self.verified_at = verified_at
        self.role = role
        self.national_id_fast = national_id_fast

    # Check if password match the database
    def verify_password(self, password):
        return check_password_hash(self.password, password)

    # Get the user by id
    @staticmethod
    def get_by_id(user_id):
        """Retrieve a user by ID"""
        result = db.execute("SELECT * FROM users WHERE id = ?", user_id)
        if result:
            row = result[0]
            return User(
                id=row["id"],
                username=row["username"],
                password=row["password_hash"],
                national_id=row["national_id_hash"],
                full_name=row["full_name"],
                birthdate=row["birthdate"],
                email=row["contact_email"],
                phone=row["contact_phone"],
                verification_status=row["verification_status"],
                verified_at=row["verified_at"],
                national_id_fast=row["national_id_fast"],
                role=row["role"]
            )
        return None

    # Get the user by username
    @staticmethod
    def get_by_username(username):
        """Retrieve a user by username"""
        result = db.execute("SELECT * FROM users WHERE username = ?", username)
        if result:
            row = result[0]
            return User(
                id=row["id"],
                username=row["username"],
                password=row["password_hash"],
                national_id=row["national_id_hash"],
                full_name=row["full_name"],
                birthdate=row["birthdate"],
                email=row["contact_email"],
                phone=row["contact_phone"],
                verification_status=row["verification_status"],
                verified_at=row["verified_at"],
                national_id_fast=row["national_id_fast"],
                role=row["role"]
            )
        return None

    @staticmethod
    def get_by_email(email):
        """Retrieve user by email"""
        result = db.execute("SELECT * FROM users WHERE email = ?", email)
        if result:
            row = result[0]
            return User(
                id=row["id"],
                username=row["username"],
                password=row["password_hash"],
                national_id=row["national_id_hash"],
                full_name=row["full_name"],
                birthdate=row["birthdate"],
                email=row["contact_email"],
                phone=row["contact_phone"],
                verification_status=row["verification_status"],
                verified_at=row["verified_at"],
                national_id_fast=row["national_id_fast"],
                role=row["role"]
            )
        return None
    
    # will be changed to a more efficient approach (for test)
    @staticmethod
    def get_by_national_id(national_id):
        """Retrieve user by national id"""
        national_id_hash = hashlib.sha256(national_id.encode("utf-8")).hexdigest()
        national_id_fast = national_id_hash[-10:]
        rows = db.execute("SELECT * FROM users WHERE national_id_fast = ?", national_id_fast)
        if rows:
            row = rows[0]
            return User(
                id=row["id"],
                username=row["username"],
                password=row["password_hash"],
                national_id=row["national_id_hash"],
                full_name=row["full_name"],
                birthdate=row["birthdate"],
                email=row["contact_email"],
                phone=row["contact_phone"],
                verification_status=row["verification_status"],
                verified_at=row["verified_at"],
                national_id_fast=row["national_id_fast"],
                role=row["role"]  
            )
        return None

    # insert a user into the database
    def insert(self):
        """Insert a user into the users table"""
        hashed_password = generate_password_hash(self.password)
        hashed_national_id = hashlib.sha256(self.national_id.encode("utf_8")).hexdigest()
        db.execute(
            "INSERT INTO users (username, password_hash, national_id_hash, full_name, birthdate, email, verification_status, verified_at, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self.username,
            hashed_password,
            hashed_national_id,
            self.full_name,
            self.birthdate,
            self.email,
            self.verification_status,
            self.verified_at,
            self.role
        )

class PendingUser():
    def __init__(self, id=None, full_name=None, national_id=None, birthdate=None, contact_email=None, contact_phone=None, username=None, file_path=None, submitted_at=None, status=None, national_id_fast=None, email_verified=None):
        self.id = id
        self.full_name = full_name
        self.national_id = national_id
        self.birthdate = birthdate
        self.contact_email = contact_email
        self.contact_phone = contact_phone
        self.file_path = file_path
        self.submitted_at = submitted_at
        self.status = status
        self.username = username
        self.national_id_fast = national_id_fast
        email_verified = email_verified

    @staticmethod
    def get_by_username(username):
        result = db.execute("SELECT * FROM pending_verifications WHERE username = ?", username)
        if result:
            row = result[0]
            return PendingUser(
                id = row["id"],
                full_name = row["full_name"],
                national_id = row["national_id_hash"],
                birthdate = row["birthdate"],
                contact_email = row["contact_email"],
                contact_phone = row["contact_phone"],
                username = row["username"],
                file_path = row["file_path"],
                submitted_at = row["submitted_at"],
                status = row["status"],
                national_id_fast = row["national_id_fast"],
                email_verified = row["email_verified"]
            )
        else:
            return None
    
    @staticmethod
    def get_email_by_username(username):
        """Get user's email by their username"""
        result = db.execute(
            "SELECT email FROM pending_verifications WHERE username = ?", 
            username)
        
        if result:
            row = result[0]
            return row["email"]
        else:
            return None

    @staticmethod    
    def get_by_email(email):
        """Returns user by their email"""

        email = email.lower()

        result = db.execute(
            "SELECT * FROM pending_verifications WHERE contact_email = ?",
            email
        )

        if result:
            row  = result[0]
            return PendingUser(
                id = row["id"],
                full_name = row["full_name"],
                national_id = row["national_id_hash"],
                birthdate = row["birthdate"],
                contact_email = row["contact_email"],
                contact_phone = row["contact_phone"],
                username = row["username"],
                file_path = row["file_path"],
                submitted_at = row["submitted_at"],
                status = row["status"],
                national_id_fast = row["national_id_fast"],
                email_verified = row["email_verified"]
            )
    @staticmethod
    def update_email_status(email):
        """Update the email_verified from true to false"""
        db.execute("UPDATE pending_verifications SET email_verified = ? WHERE contact_email = ?", 1, email) 

    def insert_to_pending(self):
        """Insert new user into the pending verifications table"""
        hashed_national_id = hashlib.sha256(self.national_id.encode("utf-8")).hexdigest()
        national_id_fast = hashed_national_id[-10:]
        submitted_at = datetime.now()
        db.execute(
            "INSERT INTO pending_verifications (full_name, national_id_hash, birthdate, contact_email, contact_phone, username, file_path, submitted_at, status, national_id_fast) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self.full_name,
            hashed_national_id,
            self.birthdate,
            self.contact_email,
            self.contact_phone,
            self.username,
            self.file_path,
            submitted_at,
            self.status,
            national_id_fast
        )
    
    def insert_to_identities(self):
        """Insert user into the identities table"""
        national_id_hash = hashlib.sha256(self.national_id.encode("utf-8")).hexdigest()
        national_id_fast = national_id_hash[-10:]
        created_at = datetime.now()
        db.execute(
            "INSERT INTO identities (full_name, national_id_hash, national_id_fast, birthdate, contact_email, contact_phone, username, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self.full_name,
            national_id_hash,
            national_id_fast,
            self.birthdate,
            self.contact_email,
            self.contact_phone,
            self.username,
            self.status,
            created_at
        )
