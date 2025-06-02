import os
import secrets

# Flask Configuration
SECRET_KEY = secrets.token_hex(16)  # Generate a random secret key
DEBUG = True

# Database Configuration
SQLALCHEMY_DATABASE_URI = 'sqlite:///edi5.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Blockchain Configuration
GANACHE_URL = "http://127.0.0.1:7545"
try:
    with open('i:\\Blockchain\\edi5\\contract_address.txt', 'r') as f:
        CONTRACT_ADDRESS = f.read().strip()
except FileNotFoundError:
    CONTRACT_ADDRESS = "0x5dCDbBba739d62c7c7d932caf361EB3d25e25F98"  # Default value if file not found

CHAIN_ID = 1337  # Default for Ganache
GAS_PRICE = 20000000000  # 20 gwei

# Admin account for initial setup
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"
DEFAULT_ADMIN_EMAIL = "admin@example.com"

# Upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size
