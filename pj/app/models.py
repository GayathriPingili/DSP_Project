from app import db
from cryptography.fernet import Fernet, InvalidToken
from flask_login import UserMixin
import os

# Path to the file storing the encryption key
encryption_file_path = "encryption.txt"

# Check if the encryption key file exists
if not os.path.exists(encryption_file_path):
    # Generate a new encryption key
    key = Fernet.generate_key().decode()
    
    # Write the key to the file
    with open(encryption_file_path, "w") as file:
        file.write(key)
        
    print('Encryption key generated and saved to file')
    print(key)
else:
    # Read the encryption key from the file
    with open(encryption_file_path, "r") as file:
        key = file.read().strip()
        
    print('Encryption key loaded from file')
    print(key)

# Initialize the cipher suite using the encryption key
cipher_suite = Fernet(key)

def encrypt_data(data):
    """
    Encrypts the given data using the cipher suite.
    """
    data_str = str(data)  # Convert the data to a string
    encrypted_data = cipher_suite.encrypt(data_str.encode())
    return encrypted_data

def decrypt_data(data):
    """
    Decrypts the given data using the cipher suite.
    """
    try:
        decrypted_data = cipher_suite.decrypt(data)
        return decrypted_data.decode('utf-8')  # Assuming the data is stored as UTF-8
    except (InvalidToken, UnicodeDecodeError):
        return None

class HealthRecord(db.Model):
    __tablename__ = 'HealthRecord'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    age = db.Column(db.Integer)
    gender = db.Column(db.String(20))
    weight = db.Column(db.LargeBinary)  # Store encrypted weight
    height = db.Column(db.Float)
    health_history = db.Column(db.LargeBinary)  # Store encrypted health history

    # Property for weight
    @property
    def weight_value(self):
        if self.weight:
            decrypted_weight = decrypt_data(self.weight)
            return float(decrypted_weight) if decrypted_weight else None
        return None

    @weight_value.setter
    def weight_value(self, value):
        self.weight = encrypt_data(str(value)) if value else None

    # Property for health_history
    @property
    def health_history_value(self):
        if self.health_history:
            return decrypt_data(self.health_history)
        return None

    @health_history_value.setter
    def health_history_value(self, value):
        self.health_history = encrypt_data(value) if value else None

class User(db.Model, UserMixin):
    __tablename__ = 'User'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.LargeBinary)  # Store encrypted password
    group = db.Column(db.String(1))  # Assuming 'H' or 'R' as the group values

    def set_password(self, password):
        """
        Encrypts and sets the user's password.
        """
        encrypted_password = encrypt_data(password)
        self.password = encrypted_password

    def check_password(self, password):
        """
        Checks the given password against the stored encrypted password.
        """
        decrypted_password = decrypt_data(self.password)
        return password == decrypted_password
