# ─── Standard Library Imports ───────────────────────────────────────────────
import os
import json
import csv
import secrets
import logging
import tempfile
import re
from datetime import datetime, timezone, timedelta
from io import BytesIO, StringIO

# ─── Third Party Imports ────────────────────────────────────────────────────
import openai
from flask import (
    Flask, render_template, redirect, url_for, flash, request, 
    jsonify, abort, send_from_directory, send_file, make_response, session
)
from flask_cors import CORS
from flask_login import (
    LoginManager, login_user, login_required, logout_user, 
    current_user, UserMixin
)
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from sqlalchemy import func, and_
from bs4 import BeautifulSoup

# ─── ReportLab Imports ──────────────────────────────────────────────────────
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

# ─── Local Imports ──────────────────────────────────────────────────────────
from config import (
    SECRET_KEY, SQLALCHEMY_DATABASE_URI, OPENAI_API_KEY, OPENAI_MODEL,
    UPLOAD_FOLDER, ALLOWED_EXTENSIONS
)
from models import *
# Constants
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}
MODEL_NAME = "gpt-4"  # Configure as needed

# Utility Functions
def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def role_required(role):
    """Decorator to check user role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                if current_user.role != role:
                    logger.warning(f"Unauthorized access attempt by user {current_user.id} to {role}-only endpoint")
                    return redirect(url_for("student_dashboard"))
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Role check error: {str(e)}")
                return redirect(url_for("student_dashboard"))
        return decorated_function
    return decorator

def clean_html_for_pdf(html_content):
    """Enhanced HTML cleaning for PDF generation."""
    try:
        if not html_content:
            return ""
        
        content = html_content
        
        # Handle paragraphs
        content = re.sub(r'<p[^>]*>', '', content)
        content = content.replace('</p>', '<br/><br/>')
        
        # Handle headings
        content = re.sub(r'<h[1-6][^>]*>', '<b><font size="13" color="#2C3E50">', content)
        content = re.sub(r'</h[1-6]>', '</font></b><br/><br/>', content)
        
        # Handle bold and italic with colors
        content = content.replace('<strong>', '<b><font color="#1B4F72">').replace('</strong>', '</font></b>')
        content = content.replace('<em>', '<i><font color="#7D3C98">').replace('</em>', '</font></i>')
        content = content.replace('<b>', '<b><font color="#1B4F72">').replace('</b>', '</font></b>')
        content = content.replace('<i>', '<i><font color="#7D3C98">').replace('</i>', '</font></i>')
        
        # Handle code blocks and inline code
        content = re.sub(r'<pre[^>]*>', '<br/><font name="Courier" size="9" color="#1B4F72" backColor="#F8F9FA">', content)
        content = content.replace('</pre>', '</font><br/><br/>')
        content = re.sub(r'<code[^>]*>', '<font name="Courier" size="10" color="#C0392B" backColor="#FADBD8">', content)
        content = content.replace('</code>', '</font>')
        
        # Handle lists with better formatting
        content = re.sub(r'<ul[^>]*>', '<br/>', content)
        content = content.replace('</ul>', '<br/>')
        content = re.sub(r'<ol[^>]*>', '<br/>', content)
        content = content.replace('</ol>', '<br/>')
        content = re.sub(r'<li[^>]*>', '  • ', content)
        content = content.replace('</li>', '<br/>')
        
        # Handle line breaks
        content = content.replace('<br>', '<br/>').replace('<br/>', '<br/>')
        
        # Handle blockquotes
        content = re.sub(r'<blockquote[^>]*>', '<br/><i><font color="#5D6D7E" size="10">"', content)
        content = content.replace('</blockquote>', '"</font></i><br/><br/>')
        
        # Handle links (show URL)
        content = re.sub(r'<a[^>]*href="([^"]*)"[^>]*>([^<]*)</a>', r'<font color="#3498DB"><u>\2</u></font> (\1)', content)
        
        # Clean up multiple line breaks
        content = re.sub(r'(<br/>){3,}', '<br/><br/>', content)
        
        return content.strip()
    except Exception as e:
        logger.error(f"HTML cleaning error: {str(e)}")
        return html_content or ""

def get_pdf_styles():
    """Get standardized PDF styles."""
    try:
        styles = getSampleStyleSheet()
        
        custom_styles = {
            'title': ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                textColor=HexColor('#2C3E50'),
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ),
            'heading': ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                spaceBefore=10,
                textColor=HexColor('#34495E'),
                leftIndent=0,
                fontName='Helvetica-Bold'
            ),
            'content': ParagraphStyle(
                'CustomContent',
                parent=styles['Normal'],
                fontSize=11,
                spaceAfter=12,
                textColor=HexColor('#2C3E50'),
                alignment=TA_JUSTIFY,
                leftIndent=20,
                lineHeight=1.4
            ),
            'html_content': ParagraphStyle(
                'HTMLContent',
                parent=styles['Normal'],
                fontSize=11,
                spaceAfter=8,
                spaceBefore=4,
                textColor=HexColor('#2C3E50'),
                alignment=TA_JUSTIFY,
                leftIndent=25,
                rightIndent=10,
                lineHeight=1.5
            ),
            'pill_title': ParagraphStyle(
                'PillTitle',
                parent=styles['Heading3'],
                fontSize=14,
                fontName='Helvetica-Bold',
                textColor=HexColor('#8E44AD'),
                spaceAfter=8,
                spaceBefore=15,
                leftIndent=20,
                backColor=HexColor('#F4F1FB'),
                borderColor=HexColor('#8E44AD'),
                borderWidth=1,
                borderPadding=5
            ),
            'pill_content': ParagraphStyle(
                'PillContent',
                parent=styles['Normal'],
                fontSize=11,
                textColor=HexColor('#2C3E50'),
                leftIndent=25,
                rightIndent=15,
                spaceAfter=10,
                lineHeight=1.4,
                alignment=TA_JUSTIFY
            ),
            'bullet': ParagraphStyle(
                'BulletStyle',
                parent=styles['Normal'],
                fontSize=11,
                leftIndent=40,
                bulletIndent=20,
                spaceAfter=6
            )
        }
        
        return custom_styles
    except Exception as e:
        logger.error(f"PDF styles error: {str(e)}")
        return {}

# ─── Logging Configuration ──────────────────────────────────────────────────
def setup_logging():
    """Configure file-based logging for the application"""
    try:
        # Create logs directory if it doesn't exist
        log_dir = 'logs'
        os.makedirs(log_dir, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(log_dir, 'app.log')),
                logging.StreamHandler()  # Also log to console
            ]
        )
        
        # Create separate loggers for different components
        auth_logger = logging.getLogger('auth')
        admin_logger = logging.getLogger('admin')
        teacher_logger = logging.getLogger('teacher')
        student_logger = logging.getLogger('student')
        api_logger = logging.getLogger('api')
        
        return {
            'auth': auth_logger,
            'admin': admin_logger,
            'teacher': teacher_logger,
            'student': student_logger,
            'api': api_logger
        }
    except Exception as e:
        print(f"Error setting up logging: {e}")
        return {}

# Initialize loggers
loggers = setup_logging()

# ─── App Configuration ──────────────────────────────────────────────────────
def create_app():
    """Application factory pattern for Flask app creation"""
    try:
        app = Flask(__name__, static_folder="static", template_folder="templates")
        
        # Configuration
        app.config["SECRET_KEY"] = SECRET_KEY
        app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
        app.logger.setLevel(logging.INFO)
        
        # Ensure upload directory exists
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        
        # Initialize extensions
        db.init_app(app)
        CORS(app)
        
        # OpenAI configuration
        openai.api_key = OPENAI_API_KEY
        
        loggers.get('auth', logging.getLogger()).info("Flask app created successfully")
        return app
        
    except Exception as e:
        logging.error(f"Error creating Flask app: {e}")
        raise

app = create_app()
MODEL_NAME = OPENAI_MODEL

# ─── Login Manager Setup ────────────────────────────────────────────────────
def setup_login_manager(app):
    """Configure Flask-Login"""
    try:
        login_manager = LoginManager(app)
        login_manager.login_view = 'login'
        login_manager.login_message = 'Please log in to access this page.'
        login_manager.login_message_category = 'info'
        
        @login_manager.user_loader
        def load_user(user_id):
            try:
                return User.query.get(int(user_id))
            except Exception as e:
                loggers.get('auth', logging.getLogger()).error(f"Error loading user {user_id}: {e}")
                return None
                
        loggers.get('auth', logging.getLogger()).info("Login manager configured successfully")
        return login_manager
        
    except Exception as e:
        loggers.get('auth', logging.getLogger()).error(f"Error setting up login manager: {e}")
        raise

login_manager = setup_login_manager(app)

# ─── Utility Functions ──────────────────────────────────────────────────────
def allowed_file(filename):
    """Check if uploaded file has allowed extension"""
    try:
        return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    except Exception as e:
        loggers.get('api', logging.getLogger()).error(f"Error checking file extension for {filename}: {e}")
        return False

def log_user_action(action, details=""):
    """Log user actions for audit trail"""
    try:
        user_id = current_user.id if current_user.is_authenticated else "Anonymous"
        username = current_user.username if current_user.is_authenticated else "Anonymous"
        loggers.get('auth', logging.getLogger()).info(f"User {username} (ID: {user_id}) - {action} - {details}")
    except Exception as e:
        logging.error(f"Error logging user action: {e}")

# ─── Error Handlers ─────────────────────────────────────────────────────────
@app.errorhandler(HTTPException)
def handle_http_exception(e):
    """Handle HTTP exceptions globally"""
    try:
        loggers.get('api', logging.getLogger()).error(f"HTTP Exception: {e.code} - {e.description}")
        return jsonify({"error": e.description}), e.code
    except Exception as ex:
        logging.error(f"Error in HTTP exception handler: {ex}")
        return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(Exception)
def handle_general_exception(e):
    """Handle general exceptions"""
    try:
        logging.error(f"Unhandled exception: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    except Exception as ex:
        logging.error(f"Error in general exception handler: {ex}")
        return jsonify({"error": "Critical error"}), 500

# ─── Database Initialization ────────────────────────────────────────────────
def init_database():
    """Initialize database tables"""
    try:
        with app.app_context():
            db.create_all()
            loggers.get('admin', logging.getLogger()).info("Database tables created successfully")
    except Exception as e:
        loggers.get('admin', logging.getLogger()).error(f"Error initializing database: {e}")
        raise

# ─── Session Management ─────────────────────────────────────────────────────
@app.before_request
def check_forced_logout():
    """Check if user has been force logged out"""
    try:
        if current_user.is_authenticated:
            stored_token = session.get('user_session_token')
            login_time = session.get('login_time')
            
            # Convert login_time to datetime object if it's stored as string
            if isinstance(login_time, str):
                try:
                    login_time = datetime.fromisoformat(login_time.replace('Z', '+00:00'))
                except:
                    login_time = datetime.min
            elif login_time is None:
                login_time = datetime.min
                
            # Ensure both datetimes are timezone-naive for comparison
            force_logout_at = current_user.force_logout_at
            if force_logout_at and force_logout_at.tzinfo is not None:
                force_logout_at = force_logout_at.replace(tzinfo=None)
            if login_time.tzinfo is not None:
                login_time = login_time.replace(tzinfo=None)
                
            if (stored_token != current_user.session_token or
                (force_logout_at and force_logout_at > login_time)):
                session.clear()
                logout_user()
                flash("Your session has been terminated by an administrator.", "warning")
                return redirect(url_for('login'))
    except Exception as e:
        loggers.get('auth', logging.getLogger()).error(f"Error in forced logout check: {e}")

@app.before_request
def check_session_validity():
    """Check if user's session is still valid"""
    try:
        if current_user.is_authenticated:
            stored_token = session.get('user_session_token')
            if not stored_token or stored_token != current_user.session_token:
                logout_user()
                session.clear()
                if request.is_json:
                    return jsonify({'error': 'Session expired', 'redirect': url_for('login')}), 401
                else:
                    flash('Your session has expired. Please log in again.', 'warning')
                    return redirect(url_for('login'))
    except Exception as e:
        loggers.get('auth', logging.getLogger()).error(f"Error checking session validity: {e}")

# ═══════════════════════════════════════════════════════════════════════════
# ─── AUTHENTICATION ROUTES ──────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/")
def root():
    """Root route - redirect to login"""
    try:
        log_user_action("Accessed root route")
        return redirect(url_for("login"))
    except Exception as e:
        loggers.get('auth', logging.getLogger()).error(f"Error in root route: {e}")
        return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration route"""
    try:
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            role = request.form.get("role", "").strip()
            name = request.form.get("name", "").strip()
            htno = request.form.get("htno", "").strip()
            
            # Validation
            if not username or not password or not role:
                flash("Username, password, and role are required.", "danger")
                return render_template("register.html")
            
            if len(password) < 6:
                flash("Password must be at least 6 characters long.", "danger")
                return render_template("register.html")
            
            # Check if user already exists
            if User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
                return render_template("register.html")
            
            # Create new user
            user = User(
                username=username,
                password=generate_password_hash(password),
                role=role,
                name=name,
                htno=htno
            )
            
            db.session.add(user)
            db.session.commit()
            
            log_user_action("User registered", f"Username: {username}, Role: {role}")
            flash("Registration successful.", "success")
            return redirect(url_for("login"))
            
        return render_template("register.html")
        
    except Exception as e:
        loggers.get('auth', logging.getLogger()).error(f"Error in user registration: {e}")
        flash("An error occurred during registration. Please try again.", "danger")
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """User login route"""
    try:
        # If user is already logged in, redirect to appropriate dashboard
        if current_user.is_authenticated:
            if current_user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            elif current_user.role == "teacher":
                return redirect(url_for("teacher_dashboard"))
            else:
                return redirect(url_for("student_dashboard"))
        
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            
            if not username or not password:
                flash("Please enter both username and password.", "danger")
                return render_template("login.html")
            
            user = User.query.filter_by(username=username).first()
            
            if user and check_password_hash(user.password, password):
                # Check if user account is active
                if user.status != 'active':
                    flash("Your account is not active. Please contact an administrator.", "warning")
                    return render_template("login.html")
                
                # Update login information
                user.update_login_info()
                session['user_session_token'] = user.session_token
                session['login_time'] = datetime.utcnow()
                
                # Login the user with remember=True for persistent sessions
                login_user(user, remember=True)
                session.permanent = True
                
                log_user_action("User logged in", f"Username: {username}")
                
                if user.must_change_password:
                    flash("Welcome! You must change your password before continuing.", "info")
                    return redirect(url_for("change_password"))
                
                # Success message
                flash(f"Welcome back, {user.name or user.username}!", "success")
                
                # Redirect based on role
                if user.role == "admin":
                    return redirect(url_for("admin_dashboard"))
                elif user.role == "teacher":
                    return redirect(url_for("teacher_dashboard"))
                else:
                    return redirect(url_for("student_dashboard"))
            else:
                flash("Invalid username or password.", "danger")
                log_user_action("Failed login attempt", f"Username: {username}")
        
        return render_template("login.html")
        
    except Exception as e:
        loggers.get('auth', logging.getLogger()).error(f"Error in login route: {e}")
        flash("An error occurred during login. Please try again.", "danger")
        return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    """User logout route"""
    try:
        username = current_user.username
        logout_user()
        session.clear()
        log_user_action("User logged out", f"Username: {username}")
        return redirect(url_for("login"))
    except Exception as e:
        loggers.get('auth', logging.getLogger()).error(f"Error in logout route: {e}")
        return redirect(url_for("login"))

# ═══════════════════════════════════════════════════════════════════════════
# ─── ADMIN ROUTES ───────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    """Admin dashboard route"""
    try:
        if current_user.role != "admin":
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("student_dashboard"))
        
        courses = Course.query.order_by(Course.created_at.desc()).all()
        teachers = User.query.filter_by(role="teacher").all()
        students = User.query.filter_by(role="student").all()
        groups = Group.query.all()
        
        log_user_action("Accessed admin dashboard")
        
        return render_template("admin_dashboard.html", 
                             courses=courses, teachers=teachers, 
                             students=students, groups=groups)
                             
    except Exception as e:
        loggers.get('admin', logging.getLogger()).error(f"Error in admin dashboard: {e}")
        flash("Error loading admin dashboard.", "danger")
        return redirect(url_for("login"))

@app.route("/admin/manage_users")
@login_required
def manage_users():
    """Manage users route for admin"""
    try:
        if current_user.role != "admin":
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("student_dashboard"))
        
        # Get all users with pagination
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        users = User.query.filter(User.role != 'admin').paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        log_user_action("Accessed user management")
        return render_template("manage_users.html", users=users)
        
    except Exception as e:
        loggers.get('admin', logging.getLogger()).error(f"Error in manage users: {e}")
        flash("Error loading user management.", "danger")
        return redirect(url_for("admin_dashboard"))

@app.route("/admin/edit_user/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    """Edit user route for admin"""
    try:
        if current_user.role != "admin":
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("student_dashboard"))
        
        user = User.query.get_or_404(user_id)
        
        # Don't allow editing admin accounts
        if user.role == "admin":
            flash("Cannot edit admin accounts", "danger")
            return redirect(url_for("manage_users"))
        
        if request.method == "POST":
            try:
                # Update user details
                user.name = request.form.get("name", "").strip()
                user.htno = request.form.get("htno", "").strip()
                
                # Update username if provided and different
                new_username = request.form.get("username", "").strip()
                if new_username and new_username != user.username:
                    # Check if username already exists
                    existing_user = User.query.filter(
                        User.username == new_username,
                        User.id != user.id
                    ).first()
                    if existing_user:
                        flash("Username already exists", "danger")
                        return render_template("edit_user.html", user=user)
                    user.username = new_username
                
                # Update password if provided
                new_password = request.form.get("new_password", "").strip()
                if new_password:
                    if len(new_password) < 6:
                        flash("Password must be at least 6 characters long", "danger")
                        return render_template("edit_user.html", user=user)
                    user.password = generate_password_hash(new_password)
                    user.must_change_password = request.form.get("force_password_change") == "on"
                    user.password_changed_at = datetime.utcnow()
                
                # Update role if changed
                new_role = request.form.get("role")
                if new_role in ["teacher", "student"]:
                    user.role = new_role
                
                # Update status
                new_status = request.form.get("status")
                if new_status in ["active", "inactive"]:
                    user.status = new_status
                
                db.session.commit()
                log_user_action("User updated", f"User ID: {user_id}, Username: {user.username}")
                flash(f"User {user.username} updated successfully", "success")
                return redirect(url_for("manage_users"))
                
            except Exception as e:
                db.session.rollback()
                loggers.get('admin', logging.getLogger()).error(f"Error updating user {user_id}: {e}")
                flash(f"Error updating user: {str(e)}", "danger")
        
        return render_template("edit_user.html", user=user)
        
    except Exception as e:
        loggers.get('admin', logging.getLogger()).error(f"Error in edit user route: {e}")
        flash("Error accessing user edit page.", "danger")
        return redirect(url_for("manage_users"))

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    """Delete user route for admin"""
    try:
        if current_user.role != "admin":
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("student_dashboard"))
        
        user = User.query.get_or_404(user_id)
        
        # Don't allow deleting admin accounts
        if user.role == "admin":
            flash("Cannot delete admin accounts", "danger")
            return redirect(url_for("manage_users"))
        
        try:
            username = user.username
            
            # Delete associated records first
            StudentGroup.query.filter_by(student_id=user.id).delete()
            Submission.query.filter_by(student_id=user.id).delete()
            
            # If user is a teacher, handle their courses
            if user.role == "teacher":
                Course.query.filter_by(teacher_id=user.id).delete()
            
            db.session.delete(user)
            db.session.commit()
            
            log_user_action("User deleted", f"User ID: {user_id}, Username: {username}")
            flash(f"User {username} deleted successfully", "success")
            
        except Exception as e:
            db.session.rollback()
            loggers.get('admin', logging.getLogger()).error(f"Error deleting user {user_id}: {e}")
            flash(f"Error deleting user: {str(e)}", "danger")
        
        return redirect(url_for("manage_users"))
        
    except Exception as e:
        loggers.get('admin', logging.getLogger()).error(f"Error in delete user route: {e}")
        flash("Error deleting user.", "danger")
        return redirect(url_for("manage_users"))

@app.route("/admin/create_user", methods=["GET", "POST"])
@login_required
def create_user():
    """Create user route for admin"""
    try:
        if current_user.role != "admin":
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("student_dashboard"))
        
        if request.method == "POST":
            try:
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "").strip()
                role = request.form.get("role")
                name = request.form.get("name", "").strip()
                htno = request.form.get("htno", "").strip()
                
                # Validation
                if not username or not password or not role:
                    flash("Username, password, and role are required", "danger")
                    return render_template("create_user.html")
                
                if len(password) < 6:
                    flash("Password must be at least 6 characters long", "danger")
                    return render_template("create_user.html")
                
                if role not in ["teacher", "student"]:
                    flash("Invalid role selected", "danger")
                    return render_template("create_user.html")
                
                # Check if username already exists
                existing_user = User.query.filter_by(username=username).first()
                if existing_user:
                    flash("Username already exists", "danger")
                    return render_template("create_user.html")
                
                # Create new user
                new_user = User(
                    username=username,
                    password=generate_password_hash(password),
                    role=role,
                    name=name,
                    htno=htno,
                    must_change_password=request.form.get("force_password_change") == "on",
                    created_at=datetime.utcnow()
                )
                
                db.session.add(new_user)
                db.session.commit()
                
                log_user_action("User created", f"Username: {username}, Role: {role}")
                flash(f"User {username} created successfully", "success")
                return redirect(url_for("manage_users"))
                
            except Exception as e:
                db.session.rollback()
                loggers.get('admin', logging.getLogger()).error(f"Error creating user: {e}")
                flash(f"Error creating user: {str(e)}", "danger")
        
        return render_template("create_user.html")
        
    except Exception as e:
        loggers.get('admin', logging.getLogger()).error(f"Error in create user route: {e}")
        flash("Error accessing user creation page.", "danger")
        return redirect(url_for("manage_users"))

@app.route("/admin/bulk_create_users", methods=["GET", "POST"])
@login_required
def bulk_create_users():
    """Bulk create users route for admin"""
    try:
        if current_user.role != "admin":
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("student_dashboard"))
        
        if request.method == "POST":
            try:
                users_data = request.form.get("users_data", "").strip()
                role = request.form.get("role", "student")
                
                if not users_data:
                    flash("Please provide user data", "danger")
                    return render_template("bulk_create_users.html")
                
                lines = users_data.split('\n')
                created_count = 0
                errors = []
                
                for line_num, line in enumerate(lines, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    parts = line.split(',')
                    if len(parts) < 2:
                        errors.append(f"Line {line_num}: Invalid format (need at least username,password)")
                        continue
                    
                    username = parts[0].strip()
                    password = parts[1].strip()
                    name = parts[2].strip() if len(parts) > 2 else ""
                    htno = parts[3].strip() if len(parts) > 3 else ""
                    
                    # Check if user already exists
                    if User.query.filter_by(username=username).first():
                        errors.append(f"Line {line_num}: Username '{username}' already exists")
                        continue
                    
                    if len(password) < 6:
                        errors.append(f"Line {line_num}: Password too short for '{username}'")
                        continue
                    
                    # Create user
                    new_user = User(
                        username=username,
                        password=generate_password_hash(password),
                        role=role,
                        name=name,
                        htno=htno,
                        must_change_password=True,
                        created_at=datetime.utcnow()
                    )
                    
                    db.session.add(new_user)
                    created_count += 1
                
                db.session.commit()
                
                log_user_action("Bulk users created", f"Created: {created_count}, Errors: {len(errors)}")
                
                if created_count > 0:
                    flash(f"Successfully created {created_count} users", "success")
                
                if errors:
                    flash(f"Errors encountered: {'; '.join(errors)}", "warning")
                
                return redirect(url_for("manage_users"))
                
            except Exception as e:
                db.session.rollback()
                loggers.get('admin', logging.getLogger()).error(f"Error in bulk create users: {e}")
                flash(f"Error creating users: {str(e)}", "danger")
        
        return render_template("bulk_create_users.html")
        
    except Exception as e:
        loggers.get('admin', logging.getLogger()).error(f"Error in bulk create users route: {e}")
        flash("Error accessing bulk user creation page.", "danger")
        return redirect(url_for("manage_users"))
# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route("/admin/dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    """Admin dashboard with overview of all entities."""
    try:
        logger.info(f"Admin {current_user.id} accessing dashboard")
        
        courses = Course.query.order_by(Course.created_at.desc()).all()
        teachers = User.query.filter_by(role="teacher").all()
        students = User.query.filter_by(role="student").all()
        groups = Group.query.all()
        
        return render_template(
            "admin_dashboard.html", 
            courses=courses, 
            teachers=teachers, 
            students=students, 
            groups=groups
        )
    except Exception as e:
        logger.error(f"Admin dashboard error: {str(e)}")
        flash("Error loading dashboard.", "error")
        return redirect(url_for("index"))

@app.route("/admin/create-course", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_create_course():
    """Create new course."""
    try:
        logger.info(f"Admin {current_user.id} accessing create course")
        
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            code = request.form.get("code", "").strip()
            description = request.form.get("description", "").strip()
            teacher_id = request.form.get("teacher_id")
            
            # Validation
            if not all([name, code, teacher_id]):
                flash("All fields are required.", "danger")
                return render_template("admin_create_course.html", 
                                     teachers=User.query.filter_by(role="teacher").all())
            
            # Check for duplicate course code
            if Course.query.filter_by(code=code).first():
                flash("Course code already exists.", "danger")
                return render_template("admin_create_course.html", 
                                     teachers=User.query.filter_by(role="teacher").all())
            
            # Create course
            new_course = Course(
                name=name,
                code=code,
                description=description,
                teacher_id=teacher_id
            )
            
            db.session.add(new_course)
            db.session.commit()
            
            logger.info(f"Course '{name}' created by admin {current_user.id}")
            flash(f"Course '{name}' created successfully.", "success")
            return redirect(url_for("admin_dashboard"))
        
        # GET request
        teachers = User.query.filter_by(role="teacher").all()
        return render_template("admin_create_course.html", teachers=teachers)
        
    except Exception as e:
        logger.error(f"Create course error: {str(e)}")
        db.session.rollback()
        flash("Error creating course.", "error")
        return render_template("admin_create_course.html", 
                             teachers=User.query.filter_by(role="teacher").all())

@app.route("/admin/create-group", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_create_group():
    """Create new group for a course."""
    try:
        logger.info(f"Admin {current_user.id} accessing create group")
        
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            course_id = request.form.get("course_id")
            
            # Validation
            if not all([name, course_id]):
                flash("All fields are required.", "danger")
                return render_template("admin_create_group.html", 
                                     courses=Course.query.filter_by(is_active=True).all())
            
            # Create group
            new_group = Group(name=name, course_id=course_id)
            db.session.add(new_group)
            db.session.commit()
            
            logger.info(f"Group '{name}' created by admin {current_user.id}")
            flash(f"Group '{name}' created successfully.", "success")
            return redirect(url_for("admin_dashboard"))
        
        # GET request
        courses = Course.query.filter_by(is_active=True).all()
        return render_template("admin_create_group.html", courses=courses)
        
    except Exception as e:
        logger.error(f"Create group error: {str(e)}")
        db.session.rollback()
        flash("Error creating group.", "error")
        return render_template("admin_create_group.html", 
                             courses=Course.query.filter_by(is_active=True).all())

@app.route("/admin/create-student", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_create_student():
    """Create individual student account."""
    try:
        logger.info(f"Admin {current_user.id} accessing create student")
        
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            temp_password = request.form.get("temp_password", "").strip()
            name = request.form.get("name", "").strip()
            htno = request.form.get("htno", "").strip()
            
            # Validation
            if not all([username, temp_password]):
                flash("Username and password are required.", "danger")
                return render_template("admin_create_student.html")
            
            # Check if username already exists
            if User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
                return render_template("admin_create_student.html")
            
            # Create new student
            new_student = User(
                username=username,
                password=generate_password_hash(temp_password),
                role="student",
                name=name,
                htno=htno,
                must_change_password=True
            )
            
            db.session.add(new_student)
            db.session.commit()
            
            logger.info(f"Student '{username}' created by admin {current_user.id}")
            flash(f"Student '{username}' created successfully. They must change their password on first login.", "success")
            return redirect(url_for("admin_dashboard"))
        
        return render_template("admin_create_student.html")
        
    except Exception as e:
        logger.error(f"Create student error: {str(e)}")
        db.session.rollback()
        flash("Error creating student.", "error")
        return render_template("admin_create_student.html")

@app.route("/admin/import-students", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_import_students():
    """Import students from CSV file."""
    try:
        logger.info(f"Admin {current_user.id} accessing import students")
        
        if request.method == "POST":
            group_id = request.form.get("group_id")
            csv_file = request.files.get("csv_file")
            
            # Validation
            if not group_id:
                flash("Please select a group.", "error")
                return redirect(url_for("admin_import_students"))
            
            if not csv_file or csv_file.filename == '':
                flash("Please upload a CSV file.", "error")
                return redirect(url_for("admin_import_students"))
            
            group = Group.query.get_or_404(group_id)
            
            # Process CSV file
            try:
                file_content = csv_file.read().decode('utf-8')
                csv_reader = csv.reader(io.StringIO(file_content))
                
                imported = 0
                added_to_group = 0
                errors = []
                skipped = []
                
                for row_num, row in enumerate(csv_reader, 1):
                    try:
                        # Skip empty rows
                        if not row or all(cell.strip() == '' for cell in row):
                            continue
                        
                        if len(row) != 3:
                            errors.append(f"Row {row_num}: Invalid format - expected 3 columns (htno,name,password)")
                            continue
                        
                        htno, name, password = [cell.strip() for cell in row]
                        
                        if not htno or not name or not password:
                            errors.append(f"Row {row_num}: Missing required data")
                            continue
                        
                        # Check if student already exists
                        existing_student = User.query.filter_by(htno=htno).first()
                        
                        if existing_student:
                            # Check if already in this group
                            existing_enrollment = StudentGroup.query.filter_by(
                                student_id=existing_student.id, 
                                group_id=group_id
                            ).first()
                            
                            if existing_enrollment:
                                skipped.append(f"Row {row_num}: Student {htno} already enrolled")
                                continue
                            else:
                                # Add existing student to group
                                student_group = StudentGroup(
                                    student_id=existing_student.id, 
                                    group_id=group_id
                                )
                                db.session.add(student_group)
                                added_to_group += 1
                        else:
                            # Create new student
                            student = User(
                                username=htno,
                                password=generate_password_hash(password),
                                role="student",
                                name=name,
                                htno=htno,
                                must_change_password=True
                            )
                            db.session.add(student)
                            db.session.flush()
                            
                            # Add to group
                            student_group = StudentGroup(
                                student_id=student.id, 
                                group_id=group_id
                            )
                            db.session.add(student_group)
                            imported += 1
                            
                    except Exception as row_error:
                        logger.error(f"Row {row_num} processing error: {str(row_error)}")
                        errors.append(f"Row {row_num}: {str(row_error)}")
                        continue
                
                # Commit all changes
                db.session.commit()
                
                # Prepare success message
                success_parts = []
                if imported > 0:
                    success_parts.append(f"{imported} new students created")
                if added_to_group > 0:
                    success_parts.append(f"{added_to_group} existing students added")
                
                if success_parts:
                    success_msg = f"Successfully: {', '.join(success_parts)} to group '{group.name}'"
                    flash(success_msg, "success")
                
                # Show warnings and errors
                if skipped:
                    flash(f"Skipped {len(skipped)} entries (already enrolled)", "info")
                
                if errors:
                    flash(f"Errors in {len(errors)} rows - check CSV format", "warning")
                
                logger.info(f"CSV import completed by admin {current_user.id}: {imported} new, {added_to_group} existing, {len(errors)} errors")
                
            except Exception as csv_error:
                logger.error(f"CSV processing error: {str(csv_error)}")
                db.session.rollback()
                flash(f"Error processing CSV file: {str(csv_error)}", "error")
            
            return redirect(url_for("admin_import_students"))
        
        # GET request - show form
        groups = Group.query.options(
            db.joinedload(Group.course),
            db.joinedload(Group.student_groups).joinedload(StudentGroup.student)
        ).all()
        
        return render_template("admin_import_students.html", groups=groups)
        
    except Exception as e:
        logger.error(f"Import students error: {str(e)}")
        flash("Error accessing import page.", "error")
        return redirect(url_for("admin_dashboard"))

@app.route("/admin/create_problem")
@login_required
@role_required("admin")
def admin_create_problem():
    """Render problem creation form for admin."""
    try:
        logger.info(f"Admin {current_user.id} accessing create problem")
        return render_template("admin_create.html")
    except Exception as e:
        logger.error(f"Admin create problem error: {str(e)}")
        flash("Error loading problem creation form.", "error")
        return redirect(url_for("admin_dashboard"))

# ============================================================================
# TEACHER API ROUTES
# ============================================================================

@app.route("/api/generate_solution", methods=["POST"])
@login_required
@role_required("teacher")
def api_generate_solution():
    """Generate solution for a problem using GPT."""
    try:
        logger.info(f"Teacher {current_user.id} generating solution")
        
        data = request.get_json() or {}
        problem_statement = data.get('problem_statement', '').strip()
        rubric = data.get('rubric', {})
        evaluation_prompt = data.get('evaluation_prompt', '').strip()
        topics = data.get('topics', [])
        
        # Validation
        if not problem_statement or not rubric:
            logger.warning(f"Invalid solution generation request from teacher {current_user.id}")
            return jsonify({"error": "Problem statement and rubric are required"}), 400
        
        # Construct system prompt
        system_prompt = (
            "You are an expert educator and solution provider. Generate a comprehensive, section-wise solution for the following problem. "
            "Produce a JSON object under the key 'solution' whose value is an object with a 'sections' array. "
            "Each section object must include:\n"
            "• aspect: the exact name of the rubric section\n"
            "• marks: the maximum marks for this section\n"
            "• content: detailed HTML-formatted solution content that includes:\n"
            "  - Clear, step-by-step explanations\n"
            "  - Code examples where applicable (use <pre><code> tags)\n"
            "  - Reasoning behind design decisions\n"
            "  - Best practices and common pitfalls to avoid\n"
            "  Format using proper HTML tags: <h4> for subheadings, <p> for paragraphs, <strong> for emphasis, <ul><li> for lists\n\n"
            "Format the content with proper HTML structure:\n"
            "- Use <strong> for key terms and important concepts\n"
            "- Use <ul><li> for bullet point lists\n"
            "- Use <p> for paragraphs (keep them focused and clear)\n"
            "- Use <h6> for subheadings when helpful\n"
            "- Use <pre><code> for code blocks\n"
            "- Ensure all HTML is properly formatted and escaped\n"
            "- Do not use h1 to h5 tags in response\n\n"
            "Make the content professional, educational, and suitable for student learning.\n"
            "Return **only** the JSON.\n\n"
            f"Problem Statement:\n\"\"\"\n{problem_statement}\n\"\"\"\n\n"
            f"Knowledge Topics: {', '.join(topics)}\n\n"
            f"Evaluation Rubric:\n{chr(10).join([f'- {aspect}: {marks} marks' for aspect, marks in rubric.items()])}\n\n"
            f"Evaluation Context:\n{evaluation_prompt}"
        )
        
        logger.debug(f"Generating solution with OpenAI for teacher {current_user.id}")
        
        resp = openai.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": "Generate the comprehensive solution as specified."}
            ]
        )
        
        content = resp.choices[0].message.content.strip()
        
        # Clean JSON if wrapped in code blocks
        if content.startswith("```json"):
            content = content[7:-3].strip()
        elif content.startswith("```"):
            content = content[3:-3].strip()
        
        parsed = json.loads(content)
        solution_data = parsed.get("solution", {})
        sections = solution_data.get("sections", [])
        
        # Validate sections structure
        for section in sections:
            if not all(key in section for key in ["aspect", "marks", "content"]):
                logger.error(f"Invalid section structure from OpenAI for teacher {current_user.id}")
                return jsonify({"error": "Invalid section structure from model"}), 502
        
        # Fallback if no sections
        if not sections:
            logger.warning(f"No sections generated, creating fallback for teacher {current_user.id}")
            sections = [
                {
                    "aspect": aspect,
                    "marks": marks,
                    "content": f"<p>Solution for {aspect} ({marks} marks):</p><div>{content}</div>"
                }
                for aspect, marks in rubric.items()
            ]
        
        logger.info(f"Solution generated successfully for teacher {current_user.id}")
        return jsonify({
            "solution": {"sections": sections},
            "total_sections": len(sections)
        })
        
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in solution generation: {str(e)}")
        return jsonify({
            "error": "Invalid JSON from model", 
            "raw": resp.choices[0].message.content if 'resp' in locals() else None,
            "json_error": str(e)
        }), 502
    except Exception as e:
        logger.error(f"Solution generation error: {str(e)}")
        return jsonify({"error": f"Failed to generate solution: {str(e)}"}), 500

@app.route("/api/save_problem", methods=["POST"])
@login_required
@role_required("teacher")
def api_save_problem():
    """Save problem with solution."""
    try:
        logger.info(f"Teacher {current_user.id} saving problem")
        
        form = request.form
        files = request.files
        course_id = form.get("course_id")
        
        # Verify teacher owns this course
        course = Course.query.filter_by(id=course_id, teacher_id=current_user.id).first()
        if not course:
            logger.warning(f"Teacher {current_user.id} attempted to save problem for unauthorized course {course_id}")
            return jsonify({"error": "Invalid course or access denied"}), 403
        
        # Create problem
        problem = Problem(
            title=form.get("title", "").strip(),
            statement=form.get("statement", "").strip(),
            topics=form.get("topics_json", "[]"),
            rubric=form.get("rubric_json", "{}"),
            pills=form.get("pills_json", "[]"),
            prompt=form.get("prompt_text", "").strip(),
            solution=form.get("solution_json"),
            video_url=form.get("video_url", "").strip() or None,
            course_id=course_id,
            created_by=current_user.id,
            is_active=0
        )
        
        # Handle PDF upload
        pdf_file = files.get("doc_file")
        if pdf_file and allowed_file(pdf_file.filename):
            try:
                filename = secure_filename(pdf_file.filename)
                upload_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                pdf_file.save(upload_path)
                problem.doc_path = f"uploads/docs/{filename}"
                logger.info(f"PDF uploaded for problem by teacher {current_user.id}: {filename}")
            except Exception as upload_error:
                logger.error(f"PDF upload error: {str(upload_error)}")
                # Continue without PDF if upload fails
        
        db.session.add(problem)
        db.session.commit()
        
        logger.info(f"Problem '{problem.title}' saved by teacher {current_user.id}")
        return jsonify({"status": "ok"})
        
    except Exception as e:
        logger.error(f"Save problem error: {str(e)}")
        db.session.rollback()
        return jsonify({"error": f"Failed to save problem: {str(e)}"}), 500

