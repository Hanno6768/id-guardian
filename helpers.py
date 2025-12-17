from bisect import bisect_left
import uuid

ALLOWED_EXTENSIONS = {"png", "jpg","jpeg", "pdf"}

def allowed_extensions(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Binary search algorithm to check if user exists in the users/pending_verifications tables
def binary_search_field(value_to_find, data_list, field_name):
    sorted_values = [row[field_name] for row in data_list]

    index = bisect_left(sorted_values, value_to_find)
    if index < len(sorted_values) and sorted_values[index] == value_to_find:
        return True
    return False

# Handle intergrity error to make sure that there are no duplicate username, email, phone number
def handle_intergrity_error(error):
    msg = str(error)

    if "username" in msg:
        return "The username you entered already exists"
    if "contact_email" in msg:
        return "The email you entered already exists"
    if "contact_phone" in msg:
        return "The phone number you entered already exists"
    if "national_id_fast" in msg:
        return "The National ID number you entered already exists"
    return "Duplicate data detected"


# Generate filename
def generate_new_filename(original_filename):
    extension = original_filename.rsplit(".", 1)[1]
    unique_name = uuid.uuid4().hex
    return f"{unique_name}.{extension}"

    