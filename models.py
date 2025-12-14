from cs50 import SQL
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQL("sqlite:///idguardian.db")

# created a user object using copilot to understand the structure 
class User(UserMixin):
    def __init__(self, id, username, password_hash, national_id_hash, full_name, birthdate, email, verification_status, verified_at):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.national_id_hash = national_id_hash
        self.full_name = full_name
        self.birthdate = birthdate
        self.email = email
        self.verification_status = verification_status
        self.verified_at = verified_at

    # Check if password match the database
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # Check if national id matches the database
    def verify_national_id(self, national_id):
        return check_password_hash(self.national_id_hash, national_id)

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
                password_hash=row["password_hash"],
                national_id_hash=row["national_id_hash"],
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
                password_hash=row["password_hash"],
                national_id_hash=row["national_id_hash"],
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
                password_hash=row["password_hash"],
                national_id_hash=row["national_id_hash"],
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
                    password_hash=row["password_hash"],
                    national_id_hash=row["national_id_hash"],
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
        hashed_password = generate_password_hash(self.password_hash)
        db.execute(
            "INSERT INTO users (username, password_hash, national_id_hash, full_name, birthdate, email, verification_status, verified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            self.username,
            hashed_password,
            self.national_id_hash,
            self.full_name,
            self.birthdate,
            self.email,
            self.verification_status,
            self.verified_at
        )