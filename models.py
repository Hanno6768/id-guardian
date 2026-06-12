from cs50 import SQL
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from flask_login import UserMixin
from datetime import datetime
from helpers import encrypt_national_id, decrypt_national_id, STANDARD_DOCUMENTS

db = SQL("sqlite:///idguardian.db")

# created a user object using copilot to understand the structure


class User(UserMixin):
    def __init__(self, id=None, username=None, password=None, national_id=None, full_name=None, birthdate=None, contact_email=None, contact_phone=None, verification_status=None, verified_at=None, national_id_fast=None, role=None):
        self.id = id
        self.username = username
        self.password = password
        self.national_id = national_id
        self.full_name = full_name
        self.birthdate = birthdate
        self.contact_email = contact_email
        self.contact_phone = contact_phone
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
                contact_email=row["contact_email"],
                contact_phone=row["contact_phone"],
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
                contact_email=row["contact_email"],
                contact_phone=row["contact_phone"],
                verification_status=row["verification_status"],
                verified_at=row["verified_at"],
                national_id_fast=row["national_id_fast"],
                role=row["role"]
            )
        return None

    @staticmethod
    def get_by_email(email):
        """Retrieve user by email"""
        result = db.execute(
            "SELECT * FROM users WHERE contact_email = ?", email)
        if result:
            row = result[0]
            return User(
                id=row["id"],
                username=row["username"],
                password=row["password_hash"],
                national_id=row["national_id_hash"],
                full_name=row["full_name"],
                birthdate=row["birthdate"],
                contact_email=row["contact_email"],
                contact_phone=row["contact_phone"],
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
        national_id_hash = hashlib.sha256(
            national_id.encode("utf-8")).hexdigest()
        national_id_fast = national_id_hash[-10:]
        rows = db.execute(
            "SELECT * FROM users WHERE national_id_fast = ?", national_id_fast)
        if rows:
            row = rows[0]
            return User(
                id=row["id"],
                username=row["username"],
                password=row["password_hash"],
                national_id=row["national_id_hash"],
                full_name=row["full_name"],
                birthdate=row["birthdate"],
                contact_email=row["contact_email"],
                contact_phone=row["contact_phone"],
                verification_status=row["verification_status"],
                verified_at=row["verified_at"],
                national_id_fast=row["national_id_fast"],
                role=row["role"]
            )
        return None

    # insert a user into the database
    def insert(self):
        """Insert a user into the users table and returns its id"""
        hashed_password = generate_password_hash(self.password)
        hashed_national_id = hashlib.sha256(
            self.national_id.encode("utf_8")).hexdigest()
        return db.execute(
            "INSERT INTO users (username, password_hash, national_id_hash, full_name, birthdate, email, verification_status, verified_at, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self.username,
            hashed_password,
            hashed_national_id,
            self.full_name,
            self.birthdate,
            self.contact_email,
            self.verification_status,
            self.verified_at,
            self.role
        )

    # update user password
    @staticmethod
    def update_password(user_id, password):
        """Update user password by their id returns true if successfull, false otherwise"""
        hashed_password = generate_password_hash(password)
        try:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                hashed_password,
                user_id
            )
            return True
        except Exception as e:
            print(f"Error updating password: {e}")
            return False


class PendingUser():
    def __init__(self, id=None, full_name=None, national_id=None, birthdate=None, contact_email=None, contact_phone=None, username=None, file_path=None, submitted_at=None, status=None, national_id_fast=None, email_verified=None, identities_id=None):
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
        self.email_verified = email_verified
        self.identities_id = identities_id

    @staticmethod
    def get_by_id(user_id):
        """Returns user by their pending_verifications id"""

        result = db.execute(
            "SELECT * FROM pending_verifications WHERE id = ?",
            user_id
        )

        if result:
            row = result[0]
            return PendingUser(
                id=row["id"],
                full_name=row["full_name"],
                national_id=row["national_id_hash"],
                birthdate=row["birthdate"],
                contact_email=row["contact_email"],
                contact_phone=row["contact_phone"],
                username=row["username"],
                file_path=row["file_path"],
                submitted_at=row["submitted_at"],
                status=row["status"],
                national_id_fast=row["national_id_fast"],
                email_verified=row["email_verified"],
                identities_id=row["identities_id"]
            )
        else:
            return None

    @staticmethod
    def verify_user(user_id):
        """Verify user by moving the user from the pending_verifications table to the users table, 
        using the pending id. User will NOT be deleted from the pending_verifications table and returned 
        as a pendinguser object, the returned id is the id given to the user in the users table."""

        result = db.execute(
            """SELECT full_name, national_id_hash, birthdate, contact_email, contact_phone, 
            national_id_fast, username, identities_id FROM pending_verifications WHERE id = ?""", user_id
        )

        if result:
            row = result[0]
            full_name = row["full_name"]
            national_id = row["national_id_hash"]
            birthdate = row["birthdate"]
            contact_email = row["contact_email"]
            contact_phone = row["contact_phone"]
            username = row["username"]
            national_id_fast = row["national_id_fast"]
            identities_id = row["identities_id"]

            verified_at = datetime.now()
            role = "user"

            # Transfer user to the users table
            id = db.execute("""
                        INSERT INTO users (full_name, national_id_hash, birthdate, contact_email, contact_phone, 
                        national_id_fast, username, verified_at, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                            full_name, national_id, birthdate, contact_email, contact_phone, national_id_fast, username, verified_at, role
                            )
            return PendingUser(
                id=id,
                full_name=row["full_name"],
                national_id=row["national_id_hash"],
                birthdate=row["birthdate"],
                contact_email=row["contact_email"],
                contact_phone=row["contact_phone"],
                username=row["username"],
                national_id_fast=row["national_id_fast"],
                identities_id=identities_id,
            )

        else:
            return None

    def delete_user(self):
        """Deletes user from the pending_verifications using their identities id"""

        db.execute("""
                    DELETE FROM pending_verifications WHERE identities_id = ?
        """, self.identities_id)

    @staticmethod
    def log_rejection(user_id, reviewer_name, rejection_reason, file_path):
        """Log a rejection in the registeration_reviews table"""
        reviewed_at = datetime.now()
        db.execute("""
                    INSERT INTO registeration_reviews 
                    (document_type, document_number, reviewer_name, reviewed_at, reviewer_notes, file_path)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                   "rejection",
                   user_id,
                   reviewer_name,
                   reviewed_at,
                   rejection_reason,
                   file_path
                   )

    @staticmethod
    def log_correction_request(user_id, reviewer_name, correction_reason, file_path):
        """Log a correction request in the registeration_reviews table"""
        reviewed_at = datetime.now()
        db.execute("""
                    INSERT INTO registeration_reviews 
                    (document_type, document_number, reviewer_name, reviewed_at, reviewer_notes, file_path)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                   "correction_request",
                   user_id,
                   reviewer_name,
                   reviewed_at,
                   correction_reason,
                   file_path
                   )

    @staticmethod
    def get_by_username(username):
        result = db.execute(
            "SELECT * FROM pending_verifications WHERE username = ?", username)
        if result:
            row = result[0]
            return PendingUser(
                id=row["id"],
                full_name=row["full_name"],
                national_id=row["national_id_hash"],
                birthdate=row["birthdate"],
                contact_email=row["contact_email"],
                contact_phone=row["contact_phone"],
                username=row["username"],
                file_path=row["file_path"],
                submitted_at=row["submitted_at"],
                status=row["status"],
                national_id_fast=row["national_id_fast"],
                email_verified=row["email_verified"],
                identities_id=row["identities_id"]
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
            row = result[0]
            return PendingUser(
                id=row["id"],
                full_name=row["full_name"],
                national_id=row["national_id_hash"],
                birthdate=row["birthdate"],
                contact_email=row["contact_email"],
                contact_phone=row["contact_phone"],
                username=row["username"],
                file_path=row["file_path"],
                submitted_at=row["submitted_at"],
                status=row["status"],
                national_id_fast=row["national_id_fast"],
                email_verified=row["email_verified"],
                identities_id=row["identities_id"]
            )

    @staticmethod
    def update_email_status(email):
        """Update the email_verified from true to false"""
        db.execute(
            "UPDATE pending_verifications SET email_verified = ? WHERE contact_email = ?", 1, email)

    def insert_to_pending(self):
        """Insert new user into the pending verifications table and return its id"""
        hashed_national_id = hashlib.sha256(
            self.national_id.encode("utf-8")).hexdigest()
        national_id_fast = hashed_national_id[-10:]
        submitted_at = datetime.now()
        return db.execute(
            "INSERT INTO pending_verifications (full_name, national_id_hash, birthdate, contact_email, contact_phone, username, file_path, submitted_at, status, national_id_fast, identities_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self.full_name,
            hashed_national_id,
            self.birthdate,
            self.contact_email,
            self.contact_phone,
            self.username,
            self.file_path,
            submitted_at,
            self.status,
            national_id_fast,
            self.identities_id
        )

    def insert_to_identities(self):
        """Insert user into the identities table"""
        national_id_hash = hashlib.sha256(
            self.national_id.encode("utf-8")).hexdigest()
        national_id_fast = national_id_hash[-10:]
        created_at = datetime.now()
        id = db.execute(
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
        return id

    def delete_from_identities(self):
        """Deletes user from the identities & pending_verifications tables (beacuse they are linked by foreign key identities_id) 
        using there identities id"""

        db.execute("""
                    DELETE FROM identities WHERE id = ?
        """, self.identities_id)

    @staticmethod
    def get_verified_pending_users():
        """Gets all users from the pending_verifications table and the encrypted national_id number from 
        the national_id_encrypted table then returns them as a list of dictioanries in ascending order"""

        result = db.execute("""
                            SELECT p.id, p.full_name, p.birthdate, p.contact_email, p.contact_phone, p.file_path, p.submitted_at, p.status, p.username, p.identities_id, n.national_id_ciphertext
                            FROM pending_verifications AS p
                            JOIN national_id_encrypted AS n
                            ON p.id = n.pending_id
                            WHERE p.email_verified = 1
                            ORDER BY p.submitted_at ASC
                            """)
        if result:
            return result


class EncryptedNationalID():
    def __init__(self, id=None, pending_id=None, user_id=None, national_id_plain=None):
        self.id = id
        self.pending_id = pending_id
        self.user_id = user_id
        self.national_id_plain = national_id_plain
        self.national_id_ciphertext = None

    def encrypt(self):
        """Encryptes the plain national id and stores it in the object"""
        self.national_id_ciphertext = encrypt_national_id(
            self.national_id_plain)

    def decrypt(self):
        """Decrypts the stored cyphertext"""
        return decrypt_national_id(self.national_id_ciphertext)

    def insert(self):
        """Encrypt (if not already) and insert into national_id_encrypted table and returns it's id"""
        if not self.national_id_ciphertext:
            raise ValueError("Encrypted national ID is missing")

        return db.execute("""
                   INSERT INTO national_id_encrypted 
                   (pending_id, user_id, national_id_ciphertext) 
                   VALUES (?, ?, ?)
                   """,
                          self.pending_id,
                          self.user_id,
                          self.national_id_ciphertext
                          )

    @staticmethod
    def get_by_user_id(user_id):
        result = db.execute(
            "SELECT * FROM national_id_encrypted WHERE user_id = ?", user_id)
        if result:
            row = result[0]
            return EncryptedNationalID(
                id=row["id"],
                pending_id=row["pending_id"],
                user_id=row["user_id"],
                national_id_ciphertext=row["national_id_ciphertext"]
            )
        else:
            return None

    @staticmethod
    def get_by_pending_id(pending_id):
        result = db.execute(
            "SELECT * FROM national_id_encrypted WHERE user_id = ?", pending_id)
        if result:
            row = result[0]
            return EncryptedNationalID(
                id=row["id"],
                pending_id=row["pending_id"],
                user_id=row["user_id"],
                national_id_ciphertext=row["national_id_ciphertext"]
            )
        else:
            return None


class Document():
    def __init__(self, id=None, user_id=None, document_type=None, document_number=None, original_filename=None, file_path=None, mimetype=None, size=None, uploaded_at=None, has_file=None, status=None, approved_at=None, qr_token=None, updated_at=None, issued=None):
        self.id = id
        self.user_id = user_id
        self.document_type = document_type
        self.document_number = document_number
        self.original_filename = original_filename
        self.file_path = file_path
        self.mimetype = mimetype
        self.size = size
        self.uploaded_at = uploaded_at
        self.has_file = has_file
        self.status = status
        self.approved_at = approved_at
        self.qr_token = qr_token
        self.updated_at = updated_at
        self.issued = issued

    @staticmethod
    def get_by_user(user_id):
        """Retrives all documents of a user by their id and returns them as a list of Document objects"""
        result = db.execute(
            "SELECT * FROM documents WHERE user_id = ?", user_id)
        if result:
            documents = []
            for row in result:
                documents.append(Document(
                    id=row["id"],
                    user_id=row["user_id"],
                    document_type=row["document_type"],
                    document_number=row["document_number"],
                    original_filename=row["original_filename"],
                    file_path=row["file_path"],
                    mimetype=row["mimetype"],
                    size=row["size"],
                    uploaded_at=row["uploaded_at"],
                    has_file=row["has_file"],
                    status=row["status"],
                    approved_at=row["approved_at"],
                    qr_token=row["qr_token"],
                    updated_at=row["updated_at"],
                    issued=row["issued"]
                ))
            return documents
        else:
            return None

    @staticmethod
    def get_by_id(document_id):
        """Retrives a document by its id and returns it as a Document object"""
        result = db.execute(
            "SELECT * FROM documents WHERE id = ?", document_id)
        if result:
            row = result[0]
            return Document(
                id=row["id"],
                user_id=row["user_id"],
                document_type=row["document_type"],
                document_number=row["document_number"],
                original_filename=row["original_filename"],
                file_path=row["file_path"],
                mimetype=row["mimetype"],
                size=row["size"],
                uploaded_at=row["uploaded_at"],
                has_file=row["has_file"],
                status=row["status"],
                approved_at=row["approved_at"],
                qr_token=row["qr_token"],
                updated_at=row["updated_at"],
                issued=row["issued"]
            )
        else:
            return None

    @staticmethod
    def get_by_user_and_type(user_id, document_type):
        """Retrives a document by its user id and type and returns it as a Document object"""
        result = db.execute(
            "SELECT * FROM documents WHERE user_id = ? AND document_type = ?", user_id, document_type)
        if result:
            row = result[0]
            return Document(
                id=row["id"],
                user_id=row["user_id"],
                document_type=row["document_type"],
                document_number=row["document_number"],
                original_filename=row["original_filename"],
                file_path=row["file_path"],
                mimetype=row["mimetype"],
                size=row["size"],
                uploaded_at=row["uploaded_at"],
                has_file=row["has_file"],
                status=row["status"],
                approved_at=row["approved_at"],
                qr_token=row["qr_token"],
                updated_at=row["updated_at"],
                issued=row["issued"]
            )
        else:
            return None

    @staticmethod
    def create_placeholders_for_user(user_id):
        """Initializes a documents entry in the documents table with has_file = 0"""
        for doc_type in STANDARD_DOCUMENTS.keys():
            db.execute("INSERT INTO documents (user_id, document_type, has_file, status, updated_at) VALUES (?, ?, ?, ?, ?)",
                       user_id, doc_type, 0, "not_uploaded", datetime.now())

    @staticmethod
    def mark_pending(user_id, document_type):
        """Updates the document status to pending when user uploads a file"""
        return db.execute("UPDATE documents SET status = 'pending' WHERE user_id = ? AND document_type = ?", user_id, document_type)

    @staticmethod
    def mark_verified(user_id, document_type):
        """Updates the document status to verified once approved and sets has_file = 1"""
        return db.execute("UPDATE documents SET status = 'verified' WHERE user_id = ? AND document_type = ? AND has_file = 1", user_id, document_type)

    @staticmethod
    def mark_correction_requested(user_id, document_type):
        """Updates the document status to correction requested"""
        return db.execute("UPDATE documents SET status = 'correction_requsted' WHERE user_id = ? AND document_type = ?", user_id, document_type)

    @staticmethod
    def mark_rejected(user_id, document_type):
        """Updates the document status to rejected if approval is denied"""
        return db.execute("UPDATE documents SET status = 'rejected' WHERE user_id = ? AND document_type = ?", user_id, document_type)


class PendingDocument():
    def __init__(self, id=None, user_id=None, document_id=None, document_type=None, original_filename=None, file_path=None, mimetype=None, size=None, notes=None, status=None, reviewer_id=None, reviewer_notes=None, submitted_at=None, reviewed_at=None, decision_email_sent=None):
        self.id = id
        self.user_id = user_id
        self.document_id = document_id
        self.document_type = document_type
        self.original_filename = original_filename
        self.file_path = file_path
        self.mimetype = mimetype
        self.size = size
        self.notes = notes
        self.status = status
        self.reviewer_id = reviewer_id
        self.reviewer_notes = reviewer_notes
        self.submitted_at = submitted_at
        self.reviewed_at = reviewed_at
        self.decision_email_sent = decision_email_sent

    @staticmethod
    def insert_pending(user_id, document_id, document_type, original_filename, file_path, mimetype=None, size=None, notes=None):
        """Records a new submission in  the pending_documents table"""
        return db.execute("INSERT INTO pending_documents (user_id, document_id, document_type, original_filename, file_path, mimetype, size, notes, status, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", user_id, document_id, document_type, original_filename, file_path, mimetype, size, notes, 'pending', datetime.now())

    @staticmethod
    def get_queue():
        """Retieves all submissions with a pending stataus to populate the reviewer dashboard"""
        return db.execute("SELECT pd.id, pd.user_id, pd.document_type, pd.original_filename, pd.file_path, pd.mimetype, pd.size, pd.notes, pd.status, pd.submitted_at, u.full_name, u.contact_email FROM pending_documents JOIN users u ON pd.user_id = u.id WHERE pd.status = ? ORDER BY submitted_at ASC", 'pending')

    @staticmethod
    def get_by_id(id):
        """Retrieves a pending document by its id and returns it as a PendingDocument object"""
        result = db.execute(
            "SELECT * FROM pending_documents WHERE id = ?", id)
        if result:
            row = result[0]
            return PendingDocument(
                id=row["id"],
                user_id=row["user_id"],
                document_id=row["document_id"],
                document_type=row["document_type"],
                original_filename=row["original_filename"],
                file_path=row["filepath"],
                mimetype=row["mimetype"],
                size=row["size"],
                notes=row["notes"],
                status=row["status"],
                reviewer_id=row["reviewer_id"],
                reviewer_notes=row["reviewer_notes"],
                submitted_at=row["submitted_at"],
                reviewed_at=row["reviewed_at"],
                decision_email_sent=row["decision_email_sent"]
            )
        else:
            return None

    @staticmethod
    def approve(pending_document_id, reviewer_id, reviewer_notes=None):
        """Updates the pending document status to approved and records the reviewer id, notes, and reviewed at timestamp"""
        reviewed_at = datetime.now()
        return db.execute("UPDATE pending_documents SET status = ?, reviewer_id = ?, reviewer_notes = ?, reviewed_at = ? WHERE id = ?", 'approved', reviewer_id, reviewer_notes, reviewed_at, pending_document_id)

    @staticmethod
    def reject(pending_document_id, reviewer_id, reviewer_notes):
        """Updates the pending document status to rejected and records the reviewer id, notes, and reviewed at timestamp"""
        reviewed_at = datetime.now()
        return db.execute("UPDATE pending_documents SET status = ?, reviewer_id = ?, reviewer_notes = ?, reviewed_at = ? WHERE id = ?", 'rejected', reviewer_id, reviewer_notes, reviewed_at, pending_document_id)

    @staticmethod
    def reject(pending_document_id, reviewer_id, reviewer_notes):
        """Updates the pending document status to correction requested and records the reviewer id, notes, and reviewed at timestamp"""
        reviewed_at = datetime.now()
        return db.execute("UPDATE pending_documents SET status = ?, reviewer_id = ?, reviewer_notes = ?, reviewed_at = ? WHERE id = ?", 'correction_requested', reviewer_id, reviewer_notes, reviewed_at, pending_document_id)


class HistoryLog():
    def __init__(self, id=None, actor_user_id=None, target_user_id=None, action=None, entity_type=None, entity_id=None, status=None, description=None, created_at=None):
        self.id = id
        self.actor_user_id = actor_user_id
        self.target_user_id = target_user_id
        self.action = action
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.status = status
        self.description = description
        self.created_at = created_at

    @staticmethod
    def log_action(actor_user_id, target_user_id, action, entity_type, entity_id, status, description):
        """Logs an action in the history_logs table"""
        return db.execute("INSERT INTO history (actor_user_id, target_user_id, action, entity_type, entity_id, status, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", actor_user_id, target_user_id, action, entity_type, entity_id, status, description, datetime.now())
