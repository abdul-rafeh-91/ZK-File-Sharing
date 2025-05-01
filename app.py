from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import random
import string
import time
from pymongo import MongoClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import logging
from urllib.parse import quote_plus
import traceback
import boto3
from botocore.exceptions import NoCredentialsError

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Add logging for app initialization
logging.info("Starting Flask app...")

# Log environment variables for debugging
logging.debug(f"MONGO_URI: {os.getenv('MONGO_URI')}")
logging.debug(f"S3_BUCKET: {os.getenv('S3_BUCKET')}")
logging.debug(f"S3_REGION: {os.getenv('S3_REGION')}")

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# AWS S3 Configuration
S3_BUCKET = os.getenv('S3_BUCKET')
S3_ACCESS_KEY = os.getenv('S3_ACCESS_KEY')
S3_SECRET_KEY = os.getenv('S3_SECRET_KEY')
S3_REGION = os.getenv('S3_REGION')

s3_client = boto3.client('s3',
                         aws_access_key_id=S3_ACCESS_KEY,
                         aws_secret_access_key=S3_SECRET_KEY,
                         region_name=S3_REGION)

# MongoDB setup
# Encode the username and password to handle special characters
username = quote_plus('abdulrafeh0091')
password = quote_plus('Rafeh@0091')

# Update the MongoDB connection string to include `tls=true`
mongo_uri = f'mongodb+srv://{username}:{password}@cluster0.wnjujo6.mongodb.net/?retryWrites=true&w=majority&tls=true'
client = MongoClient(mongo_uri)
db = client['zk_file_share']
users_collection = db['User']

# Add detailed logging for MongoDB connection
try:
    client.admin.command('ping')
    logging.info("MongoDB connection successful.")
except Exception as e:
    logging.error(f"MongoDB connection failed: {e}")
    raise

# In-memory storage for simplicity
files = {}
codes = {}

def encrypt_file(filepath, password):
    # Generate a random salt
    salt = os.urandom(16)

    # Derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Encrypt the file
    with open(filepath, 'rb') as f:
        plaintext = f.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Save the encrypted file
    with open(filepath, 'wb') as f:
        f.write(salt + iv + ciphertext)

def decrypt_file(filepath, password):
    # Read the encrypted file
    with open(filepath, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    # Derive the key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Decrypt the file
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Save the decrypted file
    with open(filepath, 'wb') as f:
        f.write(plaintext)

def upload_to_s3(file_path, file_name):
    try:
        s3_client.upload_file(file_path, S3_BUCKET, file_name)
        return f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{file_name}"
    except NoCredentialsError:
        logging.error("AWS credentials not available.")
        raise

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            if users_collection.find_one({'username': username}):
                flash('Username already exists!')
                return redirect(url_for('signup'))
            hashed_password = generate_password_hash(password)
            users_collection.insert_one({'username': username, 'password': hashed_password})
            flash('Signup successful! Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Error during signup: {e}")
            flash('An error occurred during signup. Please try again later.')
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            logging.debug(f"Login attempt with username: {username}")
            user = users_collection.find_one({'username': username})
            logging.debug(f"User found in database: {user}")
            if user and check_password_hash(user['password'], password):
                session['username'] = username
                return redirect(url_for('dashboard'))
            flash('Invalid username or password!')
        except Exception as e:
            logging.error(f"Error during login: {e}")
            flash('An error occurred during login. Please try again later.')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))

    file = request.files['file']
    encrypt = 'encrypt' in request.form

    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        if encrypt:
            password = 'securepassword'  # Replace with a user-provided password if needed
            encrypt_file(filepath, password)

        # Upload to S3
        file_url = upload_to_s3(filepath, filename)

        # Delete local file after upload
        os.remove(filepath)

        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        codes[code] = {'file_url': file_url, 'timestamp': time.time()}
        flash(f'File uploaded successfully! Share this code: {code}')
        return render_template('dashboard.html', code=code, countdown=600)

    flash('File upload failed!')
    return redirect(url_for('dashboard'))

@app.route('/receive', methods=['POST'])
def receive():
    if 'username' not in session:
        return redirect(url_for('login'))

    code = request.form['code']
    decrypt = 'decrypt' in request.form

    if code in codes:
        file_info = codes[code]
        if time.time() - file_info['timestamp'] > 600:
            return render_template('dashboard.html', error_message='Code expired!')

        file_url = file_info['file_url']

        # Decrypt file if requested (download from S3, decrypt, and serve)
        if decrypt:
            # Download file from S3
            local_path = os.path.join(app.config['UPLOAD_FOLDER'], code)
            s3_client.download_file(S3_BUCKET, code, local_path)

            password = 'securepassword'  # Replace with a user-provided password if needed
            decrypt_file(local_path, password)

            return send_file(local_path, as_attachment=True)

        return redirect(file_url)

    flash('Invalid code! Please try again.')
    return render_template('dashboard.html', error_message='Invalid code! Please try again.')

@app.errorhandler(Exception)
def handle_exception(e):
    # Log the full traceback for debugging
    logging.error(f"Unhandled Exception: {traceback.format_exc()}")
    return "An internal server error occurred. Please try again later.", 500

# Expose the Flask app as a WSGI callable for Vercel
app = app

if __name__ == '__main__':
    app.run(debug=True)