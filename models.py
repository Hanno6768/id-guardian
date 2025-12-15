from cs50 import SQL
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from flask_login import UserMixin

db = SQL("sqlite:///idguardian.db")

# created a user object using copilot to understand the structure 
class User(UserMixin):
    def __init__(self, id, username, password, national_id, full_name, birthdate, email, verification_status, verified_at):
        self.id = id
        self.username = username
        self.password = password
        self.national_id = national_id
        self.full_name = full_name
        self.birthdate = birthdate
        self.email = email
        self.verification_status = verification_status
        self.verified_at = verified_at

    # Check if password match the database
    def verify_password(self, password):
        return check_password_hash(self.password, password)
    
    # Check if national id matches the database
    def verify_national_id(self, national_id):
        return check_password_hash(self.national_id, national_id)

    # Get the user by id
    @staticmethod
    def get_by_id(user_id):
        """Retrieve a user by ID"""
        result = db.execute("SELECT id, username, password_hash, national_id_hash, full_name, birthdate, email, verification_status, verified_at FROM users WHERE id = ?", user_id)
        if result:
            row = result[0]
            return User(
                id=row["id"],
                username=row["username"],
                password=row["password_hash"],
                national_id=row["national_id_hash"],
                full_name=row["full_name"],
                birthdate=row["birthdate"],
                email=row["email"],
                verification_status=row["verification_status"],
                verified_at=row["verified_at"]
            )
        return None

    # Get the user by username
    @staticmethod
    def get_by_username(username):
        """Retrieve a user by username"""
        result = db.execute("SELECT id, username, password_hash, national_id_hash, full_name, birthdate, email, verification_status, verified_at FROM users WHERE username = ?", username)
        if result:
            row = result[0]
            return User(
                id=row["id"],
                username=row["username"],
                password=row["password_hash"],
                national_id=row["national_id_hash"],
                full_name=row["full_name"],
                birthdate=row["birthdate"],
                email=row["email"],
                verification_status=row["verification_status"],
                verified_at=row["verified_at"]
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
                email=row["email"],
                verification_status=row["verification_status"],
                verified_at=row["verified_at"]  
            )
        return None
    
    # will be changed to a more efficient approach (for test)
    @staticmethod
    def get_by_national_id(national_id):
        """Retrieve user by national id (naive, O(N), OK for tests)"""
        rows = db.execute("SELECT * FROM users")
        for row in rows:
            if check_password_hash(row["national_id_hash"], national_id):
                return User(
                    id=row["id"],
                    username=row["username"],
                    password=row["password_hash"],
                    national_id=row["national_id_hash"],
                    full_name=row["full_name"],
                    birthdate=row["birthdate"],
                    email=row["email"],
                    verification_status=row["verification_status"],
                    verified_at=row["verified_at"]  
                )
        return None

    # insert a user into the database
    def insert(self):
        """Insert a user into the users table"""
        hashed_password = generate_password_hash(self.password)
        hashed_national_id = generate_password_hash(self.national_id)
        db.execute(
            "INSERT INTO users (username, password_hash, national_id_hash, full_name, birthdate, email, verification_status, verified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            self.username,
            hashed_password,
            hashed_national_id,
            self.full_name,
            self.birthdate,
            self.email,
            self.verification_status,
            self.verified_at
        )

class PendingUser():
    def __init__(self, id=None, full_name=None, national_id=None, birthdate=None, contact_email=None, contact_phone=None, username=None, document_type=None, file_path=None, submitted_at=None, status=None, reviewer=None, review_notes=None, national_id_fast=None    ):
        self.id = id
        self.full_name = full_name
        self.national_id = national_id
        self.birthdate = birthdate
        self.contact_email = contact_email
        self.contact_phone = contact_phone
        self.document_type = document_type
        self.file_path = file_path
        self.submitted_at = submitted_at
        self.status = status
        self.reviewer = reviewer
        self.review_notes = review_notes
        self.username = username
        self.national_id_fast = national_id_fast

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
                    document_type = row["document_type"],
                    file_path = row["file_path"],
                    submitted_at = row["submitted_at"],
                    status = row["status"],
                    reviewer = row["reviewer"],
                    review_notes = row["review_notes"],
                    national_id_fast = row["national_id_fast"]
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
            
    def insert(self):
        """Insert new user into the pending verifications table"""
        hashed_national_id = generate_password_hash(self.national_id)
        national_id_fast = hashlib.sha256(self.national_id.encode("utf-8")).hexdigest()
        db.execute(
            "INSERT INTO pending_verifications (full_name, national_id_hash, birthdate, contact_email, contact_phone, username, document_type, file_path, submitted_at, status, reviewer, review_notes, national_id_fast) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self.full_name,
            hashed_national_id,
            self.birthdate,
            self.contact_email,
            self.contact_phone,
            self.username,
            self.document_type,
            self.file_path,
            self.submitted_at,
            self.status,
            self.reviewer,
            self.review_notes,
            national_id_fast
        )

