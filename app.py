from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date
import json
import os
from web3 import Web3
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from functools import wraps
import uuid

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///edi5.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy and Flask-Migrate
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Blockchain Configuration
GANACHE_URL = "http://127.0.0.1:7545"
CONTRACT_ADDRESS = "0x0e181c164710c87e9F1905ba79a1244CC8ee622b"
CHAIN_ID = 1337  # Default for Ganache
GAS_PRICE = 20000000000  # 20 gwei

# Connect to Blockchain
try:
    web3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    if web3.is_connected():
        print(f"Connected to Ganache at {GANACHE_URL}")
        
        # Get accounts from Ganache
        accounts = web3.eth.accounts
        if accounts:
            DEFAULT_ACCOUNT = accounts[0]
            # In a production environment, never hardcode private keys
            PRIVATE_KEY = "0xe41cd5ebbccc66a063227409084e2ab523a15361c322f28171db489fbdcea67a" 
        else:
            DEFAULT_ACCOUNT = None
            print("No accounts found in Ganache")
    else:
        web3 = None
        DEFAULT_ACCOUNT = None
        print(f"Failed to connect to Ganache at {GANACHE_URL}")
except Exception as e:
    web3 = None
    DEFAULT_ACCOUNT = None
    print(f"Blockchain initialization error: {e}")

# Load Contract ABI
def load_contract_abi():
    try:
        with open('i:\\Blockchain\\edi5\\ExamContractABI.json', 'r') as file:
            contract_abi = json.load(file)
        return contract_abi
    except Exception as e:
        print(f"Error loading contract ABI: {e}")
        return None

# Get Contract Instance
def get_contract():
    if not web3 or not web3.is_connected():
        return None
    
    abi = load_contract_abi()
    if not abi:
        return None
    
    try:
        contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)
        return contract
    except Exception as e:
        print(f"Error getting contract: {e}")
        return None

# ==== Database Models ====

# Multitenant Tenant Model
class Tenant(db.Model):
    __tablename__ = 'tenants'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    subdomain = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    users = db.relationship('User', backref='tenant', lazy=True)
    exams = db.relationship('Exam', backref='tenant', lazy=True)

# User Model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'student', 'examiner'
    aadhaar_number = db.Column(db.String(12), nullable=True)
    college_name = db.Column(db.String(200), nullable=True)
    education_level = db.Column(db.String(50), nullable=True)
    blockchain_address = db.Column(db.String(42), nullable=True)  # Ethereum address
    public_key = db.Column(db.Text, nullable=True)  # For document signing
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    exam_registrations = db.relationship('ExamRegistration', backref='student', lazy=True)
    results = db.relationship('Result', backref='student', lazy=True)
    queries = db.relationship('Query', backref='student', lazy=True)

# Exam Model
class Exam(db.Model):
    __tablename__ = 'exams'
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    age_min = db.Column(db.Integer, nullable=False)
    age_max = db.Column(db.Integer, nullable=False)
    education_level = db.Column(db.String(50), nullable=False)
    eligible_colleges = db.Column(db.Text, nullable=True)
    date = db.Column(db.Date, nullable=True)  # Exam date
    start_time = db.Column(db.Time, nullable=True)  # Start time
    end_time = db.Column(db.Time, nullable=True)  # End time (calculated from time_limit)
    time_limit = db.Column(db.Integer, nullable=True)  # Time limit in minutes
    results_published = db.Column(db.Boolean, default=False)
    blockchain_tx_hash = db.Column(db.String(66), nullable=True)  # Transaction hash for blockchain verification
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships with cascade delete for all related records
    mcqs = db.relationship('MCQ', backref='exam', lazy=True, cascade="all, delete-orphan")
    registrations = db.relationship('ExamRegistration', backref='exam', lazy=True, cascade="all, delete-orphan")
    results = db.relationship('Result', backref='exam', lazy=True, cascade="all, delete-orphan")

# Exam Registration Model
class ExamRegistration(db.Model):
    __tablename__ = 'exam_registrations'
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exams.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    college_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.Text, nullable=False)
    aadhaar_number = db.Column(db.String(12), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    blockchain_tx_hash = db.Column(db.String(66), nullable=True)
    
    # Ensure unique student-exam combination
    __table_args__ = (db.UniqueConstraint('student_id', 'exam_id', name='_student_exam_uc'),)

# MCQ (Multiple Choice Question) Model
class MCQ(db.Model):
    __tablename__ = 'mcqs'
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exams.id'), nullable=False)
    question = db.Column(db.String(500), nullable=False)
    option1 = db.Column(db.String(255), nullable=False)
    option2 = db.Column(db.String(255), nullable=False)
    option3 = db.Column(db.String(255), nullable=False)
    option4 = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(20), nullable=False)  # 'option1', 'option2', etc.
    blockchain_tx_hash = db.Column(db.String(66), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Result Model
class Result(db.Model):
    __tablename__ = 'results'
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exams.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)  # Score as percentage
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    blockchain_tx_hash = db.Column(db.String(66), nullable=True)
    
    # Ensure unique student-exam combination
    __table_args__ = (db.UniqueConstraint('student_id', 'exam_id', name='_result_student_exam_uc'),)

# Query Model for Student-Admin Communication
class Query(db.Model):
    __tablename__ = 'queries'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=True)  # Admin's response
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Blockchain Log Model
class BlockchainLog(db.Model):
    __tablename__ = 'blockchain_logs'
    id = db.Column(db.Integer, primary_key=True)
    action_type = db.Column(db.String(50), nullable=False)  # e.g., exam_creation, registration, submission
    related_id = db.Column(db.Integer, nullable=False)  # ID of related object (exam, registration, etc.)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    tx_hash = db.Column(db.String(66), nullable=False)  # Transaction hash
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)  # JSON data with additional details
    verified = db.Column(db.Boolean, default=False)
    
    # Relationship
    user = db.relationship('User', backref='blockchain_logs', lazy=True)

# ==== Blockchain Helper Functions ====

def log_to_blockchain(action_type, related_id, user_id=None, details=None):
    """Log an action to the blockchain and database"""
    if not web3 or not web3.is_connected() or not DEFAULT_ACCOUNT:
        print("Blockchain connection unavailable")
        return None
    
    contract = get_contract()
    if not contract:
        print("Contract not available")
        return None
    
    # Prepare timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Convert details to JSON string if provided
    details_str = json.dumps(details) if details else ""
    user_id_str = str(user_id) if user_id else "0"
    
    try:
        # Build transaction
        tx = contract.functions.logExamAction(
            int(related_id),
            action_type,
            user_id_str,
            timestamp
        ).build_transaction({
            'from': DEFAULT_ACCOUNT,
            'nonce': web3.eth.get_transaction_count(DEFAULT_ACCOUNT),
            'gas': 2000000,
            'gasPrice': web3.to_wei('20', 'gwei'),
            'chainId': CHAIN_ID
        })
        
        # Sign and send transaction
        signed_tx = web3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        
        # Handle different attribute names in web3.py versions
        if hasattr(signed_tx, 'rawTransaction'):
            raw_tx = signed_tx.rawTransaction
        elif hasattr(signed_tx, 'raw_transaction'):
            raw_tx = signed_tx.raw_transaction
        else:
            # Debug information
            print(f"Signed transaction object attributes: {dir(signed_tx)}")
            for attr in dir(signed_tx):
                if 'raw' in attr.lower() and not attr.startswith('_'):
                    raw_tx = getattr(signed_tx, attr)
                    print(f"Found likely raw transaction data in attribute: {attr}")
                    break
            else:
                raise AttributeError("Could not find raw transaction data in signed transaction")
        
        tx_hash = web3.eth.send_raw_transaction(raw_tx)
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Log to the database
        blockchain_log = BlockchainLog(
            action_type=action_type,
            related_id=related_id,
            user_id=user_id,
            tx_hash=tx_hash.hex(),
            details=details_str,
            verified=(receipt.status == 1)
        )
        db.session.add(blockchain_log)
        db.session.commit()
        
        return tx_hash.hex()
    except Exception as e:
        print(f"Error logging to blockchain: {e}")
        # Add more detailed error information
        import traceback
        print(traceback.format_exc())
        return None

def verify_blockchain_log(tx_hash):
    """Verify a transaction on the blockchain"""
    if not web3 or not web3.is_connected():
        return False
    
    try:
        tx_receipt = web3.eth.get_transaction_receipt(tx_hash)
        return tx_receipt is not None and tx_receipt.status == 1
    except Exception as e:
        print(f"Error verifying blockchain log: {e}")
        return False

def generate_key_pair():
    """Generate a public/private key pair for document signing"""
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_pem.decode(), private_pem.decode()
    except Exception as e:
        print(f"Error generating key pair: {e}")
        return None, None

# ==== Authentication Decorators ====

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            flash('You need admin privileges to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'student':
            flash('You need student privileges to access this page.', 'danger')
        return f(*args, **kwargs)
    return decorated_function

# ==== Helper Functions ====

def get_current_tenant_id():
    """Get the current tenant ID based on subdomain or session"""
    # In a production app, you'd get this from the subdomain
    # For simplicity, we'll use a session variable or default to 1
    return session.get('tenant_id', 1)

# ==== Routes ====

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Find the user (in a multitenancy context, you'd filter by tenant)
        user = User.query.filter_by(username=username, active=True).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['tenant_id'] = user.tenant_id
            
            # Log the login activity to blockchain
            details = {
                'username': username,
                'timestamp': datetime.now().isoformat(),
                'ip_address': request.remote_addr
            }
            log_to_blockchain('user_login', user.id, user.id, details)
            
            flash('Login successful!', 'success')
            
            # Redirect based on role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'student':
                return redirect(url_for('student_dashboard'))
            else:
                return redirect(url_for('examiner_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'student')
        tenant_id = get_current_tenant_id()
        
        # Check if username or email already exists
        if User.query.filter_by(username=username, tenant_id=tenant_id).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email, tenant_id=tenant_id).first():
            flash('Email already exists.', 'danger')
            return redirect(url_for('register'))
        
        # Generate key pair for blockchain identity
        public_key, private_key = generate_key_pair()
        
        # Create new user
        user = User(
            tenant_id=tenant_id,
            username=username,
            email=email,
            password=generate_password_hash(password),
            role=role,
            public_key=public_key
        )
        
        # Add additional fields for students
        if role == 'student':
            user.aadhaar_number = request.form.get('aadhaar_number', '')
            user.college_name = request.form.get('college_name', '')
            user.education_level = request.form.get('education_level', '')
        
        db.session.add(user)
        db.session.commit()
        
        # Log registration to blockchain
        details = {
            'username': username,
            'email': email,
            'role': role,
            'timestamp': datetime.now().isoformat()
        }
        tx_hash = log_to_blockchain('user_registration', user.id, user.id, details)
        
        # Store temporary private key to show to user once
        if private_key:
            session['temp_private_key'] = private_key
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_to_blockchain('user_logout', user_id, user_id)
    
    # Clear session
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# ==== Admin Routes ====

@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    tenant_id = get_current_tenant_id()
    
    # Get all exams for this tenant
    exams = Exam.query.filter_by(tenant_id=tenant_id).order_by(Exam.date.desc()).all()
    
    # Get statistics
    stats = {
        'total_exams': Exam.query.filter_by(tenant_id=tenant_id).count(),
        'total_students': User.query.filter_by(role='student', tenant_id=tenant_id).count(),
        'total_registrations': db.session.query(ExamRegistration).\
            join(Exam).filter(Exam.tenant_id == tenant_id).count(),
        'pending_queries': Query.query.filter_by(response=None).\
            join(User).filter(User.tenant_id == tenant_id).count()
    }
    
    return render_template('admin_dashboard.html', exams=exams, stats=stats)

@app.route('/admin/add_exam', methods=['GET', 'POST'])
@login_required
@admin_required
def add_exam():
    tenant_id = get_current_tenant_id()
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        age_min = int(request.form['age_min'])
        age_max = int(request.form['age_max'])
        education_level = request.form['education_level']
        eligible_colleges = request.form['eligible_colleges']
        
        # Handle date and time limit
        date_str = request.form['date']
        exam_date = datetime.strptime(date_str, '%Y-%m-%d').date() if date_str else None
        time_limit = int(request.form['time_limit']) if request.form.get('time_limit') else None

        # Create exam
        exam = Exam(
            tenant_id=tenant_id,
            name=name,
            description=description,
            age_min=age_min,
            age_max=age_max,
            education_level=education_level,
            eligible_colleges=eligible_colleges,
            date=exam_date,
            time_limit=time_limit
        )

        db.session.add(exam)
        db.session.commit()
        
        # Log to blockchain
        details = {
            'name': name,
            'date': date_str if date_str else 'Not set',
            'time_limit': time_limit if time_limit else 'Not set',
            'created_by': session['username']
        }
        tx_hash = log_to_blockchain('exam_creation', exam.id, session['user_id'], details)
        
        # Update exam with blockchain hash
        if tx_hash:
            exam.blockchain_tx_hash = tx_hash
            db.session.commit()
        
        flash('Exam added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_exam.html')

@app.route('/admin/edit_exam/<int:exam_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_exam(exam_id):
    tenant_id = get_current_tenant_id()
    exam = Exam.query.filter_by(id=exam_id, tenant_id=tenant_id).first_or_404()

    if request.method == 'POST':
        exam.name = request.form['name']
        exam.description = request.form['description']
        exam.age_min = int(request.form['age_min'])
        exam.age_max = int(request.form['age_max'])
        exam.education_level = request.form['education_level']
        exam.eligible_colleges = request.form['eligible_colleges']
        
        # Handle date and time limit
        date_str = request.form['date']
        exam.date = datetime.strptime(date_str, '%Y-%m-%d').date() if date_str else None
        exam.time_limit = int(request.form['time_limit']) if request.form.get('time_limit') else None

        db.session.commit()
        
        # Log to blockchain
        details = {
            'name': exam.name,
            'date': date_str if date_str else 'Not set',
            'updated_by': session['username']
        }
        log_to_blockchain('exam_update', exam.id, session['user_id'], details)
        
        flash('Exam updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_exam.html', exam=exam)

@app.route('/admin/delete_exam/<int:exam_id>')
@login_required
@admin_required
def delete_exam(exam_id):
    tenant_id = get_current_tenant_id()
    exam = Exam.query.filter_by(id=exam_id, tenant_id=tenant_id).first_or_404()
    
    # Log deletion to blockchain before deleting
    details = {'name': exam.name, 'deleted_by': session['username']}
    log_to_blockchain('exam_deletion', exam.id, session['user_id'], details)
    
    try:
        db.session.delete(exam)
        db.session.commit()
        flash('Exam deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting exam: {str(e)}', 'danger')
        print(f"Error deleting exam: {e}")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/set_mcqs/<int:exam_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def set_mcqs(exam_id):
    tenant_id = get_current_tenant_id()
    exam = Exam.query.filter_by(id=exam_id, tenant_id=tenant_id).first_or_404()
    
    if request.method == 'POST':
        question = request.form['question']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        correct_answer = request.form['correct_answer']
        
        # Create MCQ
        mcq = MCQ(
            exam_id=exam_id,
            question=question,
            option1=option1,
            option2=option2,
            option3=option3,
            option4=option4,
            correct_answer=correct_answer
        )
        
        db.session.add(mcq)
        db.session.commit()
        
        # Log to blockchain
        details = {
            'exam_id': exam_id,
            'exam_name': exam.name,
            'question': question[:50] + '...'  # Truncated for privacy
        }
        tx_hash = log_to_blockchain('question_added', mcq.id, session['user_id'], details)
        
        if tx_hash:
            mcq.blockchain_tx_hash = tx_hash
            db.session.commit()
        
        flash('Question added successfully!', 'success')
        return redirect(url_for('set_mcqs', exam_id=exam_id))
    
    # Get all questions for this exam
    mcqs = MCQ.query.filter_by(exam_id=exam_id).all()
    return render_template('set_mcqs.html', exam=exam, mcqs=mcqs)

@app.route('/schedule_exam/<int:exam_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def schedule_exam(exam_id):
    tenant_id = get_current_tenant_id()
    exam = Exam.query.filter_by(id=exam_id, tenant_id=tenant_id).first_or_404()
    
    if request.method == 'POST':
        # Parse date and time information
        date_str = request.form['exam_date']
        start_time_str = request.form['start_time']
        end_time_str = request.form['end_time']
        
        try:
            # Convert to Python objects
            exam_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            start_time = datetime.strptime(start_time_str, '%H:%M').time()
            end_time = datetime.strptime(end_time_str, '%H:%M').time()
            
            # Update exam
            exam.date = exam_date
            exam.start_time = start_time
            exam.end_time = end_time
            db.session.commit()
            
            # Log to blockchain
            details = {
                'exam_id': exam.id,
                'exam_name': exam.name,
                'date': date_str,
                'start_time': start_time_str,
                'end_time': end_time_str,
                'scheduled_by': session['username']
            }
            log_to_blockchain('exam_scheduled', exam.id, session['user_id'], details)
            
            flash('Exam schedule updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except ValueError as e:
            flash(f'Invalid date or time format: {e}', 'danger')
    
    return render_template('schedule_exam.html', exam=exam)

@app.route('/admin/publish_results/<int:exam_id>')
@login_required
@admin_required
def publish_results(exam_id):
    tenant_id = get_current_tenant_id()
    exam = Exam.query.filter_by(id=exam_id, tenant_id=tenant_id).first_or_404()
    
    # Update results published flag
    exam.results_published = True
    db.session.commit()
    
    # Log to blockchain
    details = {
        'exam_id': exam.id,
        'exam_name': exam.name,
        'published_by': session['username'],
        'timestamp': datetime.now().isoformat()
    }
    log_to_blockchain('results_published', exam.id, session['user_id'], details)
    
    flash('Results published successfully! Students can now view their results.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/view_results/<int:exam_id>')
@login_required
@admin_required
def admin_view_results(exam_id):
    tenant_id = get_current_tenant_id()
    exam = Exam.query.filter_by(id=exam_id, tenant_id=tenant_id).first_or_404()
    
    # Get all results for this exam with student details
    results = (
        db.session.query(
            Result,
            User.username,
            ExamRegistration.aadhaar_number,
            ExamRegistration.college_name
        )
        .join(User, User.id == Result.student_id)
        .join(ExamRegistration, (ExamRegistration.student_id == Result.student_id) & (ExamRegistration.exam_id == exam_id))
        .filter(Result.exam_id == exam_id)
        .order_by(Result.score.desc())
        .all()
    )
    
    return render_template('admin_view_results.html', exam=exam, results=results)

@app.route('/view_queries', methods=['GET', 'POST'])
@login_required
@admin_required
def view_queries():
    tenant_id = get_current_tenant_id()
    
    if request.method == 'POST':
        query_id = request.form['query_id']
        response = request.form['response']
        
        query = Query.query.get_or_404(query_id)
        # Verify the query belongs to a student in this tenant
        if User.query.get(query.student_id).tenant_id != tenant_id:
            flash('Unauthorized access!', 'danger')
            return redirect(url_for('admin_dashboard'))
            
        query.response = response
        db.session.commit()
        
        flash('Response submitted successfully!', 'success')
    
    # Get all queries with student information for this tenant
    queries_with_students = (
        db.session.query(Query)
        .join(User, User.id == Query.student_id)
        .filter(User.tenant_id == tenant_id)
        .all()
    )
    
    return render_template('view_queries.html', queries=queries_with_students)

@app.route('/blockchain_logs')
@login_required
@admin_required
def blockchain_logs():
    tenant_id = get_current_tenant_id()
    
    # Get blockchain logs related to this tenant's actions
    logs = (
        db.session.query(BlockchainLog)
        .join(User, User.id == BlockchainLog.user_id, isouter=True)  # Using outer join to include system transactions
        .filter((User.tenant_id == tenant_id) | (BlockchainLog.user_id == None))
        .order_by(BlockchainLog.timestamp.desc())
        .all()
    )
    
    # Mark verified logs in the database
    for log in logs:
        if not log.verified:
            is_verified = verify_blockchain_log(log.tx_hash)
            if is_verified:
                log.verified = True
                db.session.commit()
    
    return render_template('blockchain_logs.html', logs=logs)

@app.route('/api/verify_all', methods=['POST'])
@login_required
@admin_required
def verify_all_transactions():
    """API endpoint to verify multiple transactions"""
    tx_hashes = request.json.get('tx_hashes', [])
    results = []
    
    for tx_hash in tx_hashes:
        is_verified = verify_blockchain_log(tx_hash)
        log = BlockchainLog.query.filter_by(tx_hash=tx_hash).first()
        
        if log and is_verified and not log.verified:
            log.verified = True
            db.session.commit()
            
        results.append({
            'tx_hash': tx_hash,
            'verified': is_verified
        })
    
    return jsonify({
        'results': results,
        'success': True,
        'total': len(tx_hashes),
        'verified': sum(1 for r in results if r['verified'])
    })

# Maintain backward compatibility with old route
@app.route('/admin/blockchain_logs')
@login_required
@admin_required
def admin_blockchain_logs():
    """Redirect to the main blockchain logs page for backward compatibility"""
    return redirect(url_for('blockchain_logs'))

# ==== Student Routes ====

@app.route('/student_dashboard')
@login_required
@student_required
def student_dashboard():
    tenant_id = get_current_tenant_id()
    student_id = session['user_id']
    
    # Get all available exams for this tenant
    exams = Exam.query.filter_by(tenant_id=tenant_id).all()
    
    # Get exams the student is registered for
    registered_exams = ExamRegistration.query.filter_by(student_id=student_id).all()
    registered_exam_ids = [reg.exam_id for reg in registered_exams]
    
    # Determine status for each exam
    exam_statuses = {}
    for exam in exams:
        now = datetime.now()
        
        # Check if student already submitted this exam
        result = Result.query.filter_by(student_id=student_id, exam_id=exam.id).first()
        
        if result:
            exam_statuses[exam.id] = 'submitted'
        elif exam.id not in registered_exam_ids:
            exam_statuses[exam.id] = 'not_registered'
        elif not exam.date or not exam.start_time:
            exam_statuses[exam.id] = 'scheduled'
        else:
            exam_datetime_start = datetime.combine(exam.date, exam.start_time)
            exam_datetime_end = datetime.combine(exam.date, exam.end_time) if exam.end_time else (
                exam_datetime_start + timedelta(minutes=exam.time_limit) if exam.time_limit else None
            )
            
            if now < exam_datetime_start:
                exam_statuses[exam.id] = 'upcoming'
            elif (not exam_datetime_end) or (now <= exam_datetime_end):
                exam_statuses[exam.id] = 'available'
            else:
                exam_statuses[exam.id] = 'expired'
    
    return render_template(
        'student_dashboard.html',
        exams=exams,
        exam_statuses=exam_statuses,
        registered_exam_ids=registered_exam_ids
    )

@app.route('/register_exam/<int:exam_id>', methods=['GET', 'POST'])
@login_required
@student_required
def register_exam(exam_id):
    tenant_id = get_current_tenant_id()
    student_id = session['user_id']
    
    # Verify the exam belongs to this tenant
    exam = Exam.query.filter_by(id=exam_id, tenant_id=tenant_id).first_or_404()
    
    # Check if already registered
    existing_reg = ExamRegistration.query.filter_by(student_id=student_id, exam_id=exam_id).first()
    if existing_reg:
        flash('You are already registered for this exam.', 'warning')
        return redirect(url_for('student_dashboard'))
    
    # Get student information
    student = User.query.get(student_id)
    
    if request.method == 'POST':
        name = request.form['name']
        college_name = request.form['college_name']
        address = request.form['address']
        aadhaar_number = request.form['aadhaar_number']
        age = int(request.form['age'])
        
        # Validate eligibility
        if age < exam.age_min or age > exam.age_max:
            flash(f'You must be between {exam.age_min} and {exam.age_max} years old to register.', 'danger')
            return redirect(url_for('register_exam', exam_id=exam_id))
        
        # Create registration
        registration = ExamRegistration(
            student_id=student_id,
            exam_id=exam_id,
            name=name,
            college_name=college_name,
            address=address,
            aadhaar_number=aadhaar_number,
            age=age
        )
        
        db.session.add(registration)
        db.session.commit()
        
        # Log to blockchain
        details = {
            'student_id': student_id,
            'student_name': name,
            'exam_id': exam_id,
            'exam_name': exam.name,
            'college': college_name
        }
        tx_hash = log_to_blockchain('exam_registration', registration.id, student_id, details)
        
        if tx_hash:
            registration.blockchain_tx_hash = tx_hash
            db.session.commit()
        
        flash('Registration successful! You are now registered for this exam.', 'success')
        return redirect(url_for('student_dashboard'))
    
    return render_template('register_exam.html', exam=exam, student=student)

@app.route('/take_exam/<int:exam_id>', methods=['GET', 'POST'])
@login_required
@student_required
def take_exam(exam_id):
    tenant_id = get_current_tenant_id()
    student_id = session['user_id']
    
    # Verify the exam belongs to this tenant
    exam = Exam.query.filter_by(id=exam_id, tenant_id=tenant_id).first_or_404()
    
    # Check registration
    registration = ExamRegistration.query.filter_by(student_id=student_id, exam_id=exam_id).first()
    if not registration:
        flash('You are not registered for this exam.', 'danger')
        return redirect(url_for('student_dashboard'))
    
    # Check if exam is active
    now = datetime.now()
    
    if not exam.date or not exam.start_time:
        flash('This exam is not properly scheduled yet.', 'danger')
        return redirect(url_for('student_dashboard'))
    
    exam_start = datetime.combine(exam.date, exam.start_time)
    exam_end = datetime.combine(exam.date, exam.end_time) if exam.end_time else (
        exam_start + timedelta(minutes=exam.time_limit) if exam.time_limit else None
    )
    
    if now < exam_start:
        flash('This exam has not started yet.', 'danger')
        return redirect(url_for('student_dashboard'))
    
    if exam_end and now > exam_end:
        flash('This exam has ended.', 'danger')
        return redirect(url_for('student_dashboard'))
    
    # Check if already taken
    existing_result = Result.query.filter_by(student_id=student_id, exam_id=exam_id).first()
    if existing_result:
        flash('You have already completed this exam.', 'danger')
        return redirect(url_for('student_dashboard'))
    
    # Get exam questions
    mcqs = MCQ.query.filter_by(exam_id=exam_id).all()
    
    if request.method == 'POST':
        # Calculate score
        score = 0
        total_questions = len(mcqs)
        
        for mcq in mcqs:
            answer_key = f'mcq_{mcq.id}'
            if answer_key in request.form and request.form[answer_key] == mcq.correct_answer:
                score += 1
        
        # Calculate percentage score
        percentage_score = int((score / total_questions) * 100) if total_questions > 0 else 0
        
        # Create result
        result = Result(
            student_id=student_id,
            exam_id=exam_id,
            score=percentage_score
        )
        
        db.session.add(result)
        db.session.commit()
        
        # Log to blockchain
        details = {
            'student_id': student_id,
            'student_name': session['username'],
            'exam_id': exam_id,
            'exam_name': exam.name,
            'score': percentage_score,
            'completed_at': datetime.now().isoformat()
        }
        tx_hash = log_to_blockchain('exam_submission', result.id, student_id, details)
        
        if tx_hash:
            result.blockchain_tx_hash = tx_hash
            db.session.commit()
        
        flash(f'Exam submitted successfully! Your score: {percentage_score}%.', 'success')
        return redirect(url_for('student_dashboard'))
    
    # Record exam start time
    session['exam_start_time'] = datetime.now().isoformat()
    
    # Log exam start
    details = {
        'student_id': student_id,
        'student_name': session['username'],
        'exam_id': exam_id,
        'exam_name': exam.name,
        'started_at': session['exam_start_time']
    }
    log_to_blockchain('exam_started', exam_id, student_id, details)
    
    return render_template('take_exam.html', exam=exam, mcqs=mcqs)

@app.route('/view_results/<int:exam_id>')
@login_required
@student_required
def view_results(exam_id):
    tenant_id = get_current_tenant_id()
    student_id = session['user_id']
    
    # Verify the exam belongs to this tenant
    exam = Exam.query.filter_by(id=exam_id, tenant_id=tenant_id).first_or_404()
    
    # Check if results are published
    if not exam.results_published:
        flash('Results for this exam have not been published yet.', 'info')
        return redirect(url_for('student_dashboard'))
    
    # Get student's result
    student_result = Result.query.filter_by(student_id=student_id, exam_id=exam_id).first()
    if not student_result:
        flash('You have not taken this exam yet.', 'warning')
        return redirect(url_for('student_dashboard'))
    
    # Get all student results for ranking
    rankings = (
        db.session.query(
            Result,
            User.username,
            ExamRegistration.aadhaar_number,
            ExamRegistration.college_name
        )
        .join(User, User.id == Result.student_id)
        .join(ExamRegistration, (ExamRegistration.student_id == Result.student_id) & (ExamRegistration.exam_id == exam_id))
        .filter(Result.exam_id == exam_id)
        .order_by(Result.score.desc())
        .all()
    )
    
    # Find student's rank
    rank = next((idx + 1 for idx, (result, _, _, _) in enumerate(rankings) if result.student_id == student_id), 0)
    
    return render_template(
        'view_results.html',
        exam=exam,
        student_result=student_result,
        rankings=rankings,
        rank=rank,
        enumerate=enumerate
    )

@app.route('/contact_admin', methods=['GET', 'POST'])
@login_required
@student_required
def contact_admin():
    student_id = session['user_id']
    
    if request.method == 'POST':
        message = request.form['message']
        
        query = Query(
            student_id=student_id,
            message=message
        )
        
        db.session.add(query)
        db.session.commit()
        
        flash('Your query has been submitted successfully. An administrator will respond shortly.', 'success')
        return redirect(url_for('student_dashboard'))
    
    # Get previous queries by this student
    previous_queries = Query.query.filter_by(student_id=student_id).order_by(Query.timestamp.desc()).all()
    
    return render_template('contact_admin.html', previous_queries=previous_queries)

# ==== API Routes for Blockchain Verification ====

@app.route('/api/verify/<string:tx_hash>')
def api_verify_transaction(tx_hash):
    is_verified = verify_blockchain_log(tx_hash)
    
    if is_verified:
        log = BlockchainLog.query.filter_by(tx_hash=tx_hash).first()
        
        if log:
            return jsonify({
                'verified': True,
                'action_type': log.action_type,
                'timestamp': log.timestamp.isoformat(),
                'details': json.loads(log.details) if log.details else {}
            })
    
    return jsonify({'verified': False, 'message': 'Transaction not found or invalid'})

@app.route('/verify_certificate/', defaults={'tx_hash': None})
@app.route('/verify_certificate/<string:tx_hash>')
def verify_certificate(tx_hash):
    """
    Certificate verification page. Shows a form if no tx_hash is provided,
    or verifies and displays the certificate details if a valid tx_hash is given.
    """
    # If no transaction hash provided, show the verification form
    if not tx_hash:
        return render_template('verify_certificate.html', is_verified=False)
    
    error = None
    is_verified = False
    
    try:
        # Verify the blockchain transaction
        is_verified = verify_blockchain_log(tx_hash)
        
        # Get the log from database
        log = BlockchainLog.query.filter_by(tx_hash=tx_hash).first()
        
        if not log:
            error = "Transaction not found in our records"
            is_verified = False
        
        # Only certificates from exam submissions are valid for verification
        elif log.action_type != 'exam_submission' and log.action_type != 'results_published':
            error = f"Transaction is not a certificate (type: {log.action_type})"
            is_verified = False
        
        # If verified, get certificate details
        if is_verified:
            try:
                details = json.loads(log.details) if log.details else {}
                result = Result.query.get_or_404(log.related_id)
                student = User.query.get_or_404(result.student_id)
                exam = Exam.query.get_or_404(result.exam_id)
                
                return render_template(
                    'verify_certificate.html',
                    is_verified=True,
                    student=student,
                    exam=exam,
                    result=result,
                    log=log,
                    details=details
                )
            except Exception as e:
                error = f"Error retrieving certificate details: {str(e)}"
                is_verified = False
    
    except Exception as e:
        error = f"Verification error: {str(e)}"
        is_verified = False
    
    # If verification failed or error occurred
    return render_template(
        'verify_certificate.html',
        is_verified=False,
        error=error,
        tx_hash=tx_hash
    )

# ==== Error Handlers ====

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_code=500, message="Internal server error"), 500

# ==== CLI Commands ====

@app.cli.command("create-tenant")
def create_tenant_command():
    """Create a new tenant."""
    tenant_name = input("Tenant name: ")
    subdomain = input("Subdomain: ")
    
    existing = Tenant.query.filter_by(subdomain=subdomain).first()
    if existing:
        print(f"Error: Subdomain '{subdomain}' already exists.")
        return
    
    tenant = Tenant(name=tenant_name, subdomain=subdomain)
    db.session.add(tenant)
    db.session.commit()
    print(f"Tenant created successfully with ID: {tenant.id}")
    
    # Create admin user for this tenant
    admin_username = input("Admin username: ")
    admin_email = input("Admin email: ")
    admin_password = input("Admin password: ")
    
    admin = User(
        tenant_id=tenant.id,
        username=admin_username,
        email=admin_email,
        password=generate_password_hash(admin_password),
        role='admin'
    )
    db.session.add(admin)
    db.session.commit()
    print(f"Admin user created with ID: {admin.id}")

# ==== Main ====

if __name__ == '__main__':
    with app.app_context():
        # Create database tables if they don't exist
        db.create_all()
        
        # Create default tenant if none exists
        if Tenant.query.count() == 0:
            tenant = Tenant(name="Default Organization", subdomain="default")
            db.session.add(tenant)
            db.session.commit()
            
            # Create admin user
            admin = User(
                tenant_id=tenant.id,
                username="admin",
                email="admin@example.com",
                password=generate_password_hash("admin123"),
                role="admin"
            )
            db.session.add(admin)
            db.session.commit()
            print("Default tenant and admin user created.")
    
    app.run(debug=True)

