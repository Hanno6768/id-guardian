from cs50 import SQL
from werkzeug.security import generate_password_hash

db = SQL("sqlite:///idguardian.db")

# created a user object using copilot to understand the structure 
class User:
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
    def get_by_national_id_hash(national_id_hash):
        """Retrieve a user by national ID hash"""
        result = db.execute("SELECT id, username, password_hash, national_id_hash, full_name, birthdate, email, verification_status, verified_at FROM users WHERE national_id_hash = ?", national_id_hash)
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