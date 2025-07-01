# ─── Standard Library Imports ───────────────────────────────────────────────
import os
import json
import csv
import secrets
import logging
import tempfile
import re
import io
from datetime import datetime, timezone, timedelta
from io import BytesIO, StringIO
from functools import wraps
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
import logging
from logging.handlers import RotatingFileHandler
import os
import pytz



# Constants
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}

# ─── Simple Logging Configuration ───────────────────────────────────────────
def setup_logging():
    """Configure simple file-based logging for the application"""
    try:
        # Create logs directory if it doesn't exist
        log_dir = 'logs'
        os.makedirs(log_dir, exist_ok=True)
        
        # Clear any existing handlers to avoid duplicates
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        
        # Configure root logger with simple format
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(log_dir, 'app.log')),
                logging.StreamHandler()  # Also log to console
            ],
            force=True  # Force reconfiguration
        )
        
        logger = logging.getLogger(__name__)
        logger.info("Logging system initialized successfully")
        
        return logger
        
    except Exception as e:
        print(f"Error setting up logging: {e}")
        return logging.getLogger(__name__)

# Initialize logger
logger = setup_logging()

# Utility Functions
def allowed_file(filename):
    """Check if file extension is allowed."""
    try:
        result = '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
        logger.debug(f"File extension check for {filename}: {result}")
        return result
    except Exception as e:
        logger.error(f"Error checking file extension for {filename}: {e}")
        return False

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

def log_user_action(action, details=""):
    """Log user actions for audit trail"""
    try:
        user_id = current_user.id if current_user.is_authenticated else "Anonymous"
        username = current_user.username if current_user.is_authenticated else "Anonymous"
        logger.info(f"User {username} (ID: {user_id}) - {action} - {details}")
    except Exception as e:
        logger.error(f"Error logging user action: {e}")

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
        
        # Ensure upload directory exists
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        
        # Initialize extensions
        db.init_app(app)
        CORS(app)
        
        # OpenAI configuration
        openai.api_key = OPENAI_API_KEY
        
        logger.info("Flask app created successfully")
        return app
        
    except Exception as e:
        logger.error(f"Error creating Flask app: {e}")
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
                user = User.query.get(int(user_id))
                if user:
                    logger.debug(f"User {user_id} loaded successfully")
                else:
                    logger.warning(f"User {user_id} not found")
                return user
            except Exception as e:
                logger.error(f"Error loading user {user_id}: {e}")
                return None
                
        logger.info("Login manager configured successfully")
        return login_manager
        
    except Exception as e:
        logger.error(f"Error setting up login manager: {e}")
        raise

login_manager = setup_login_manager(app)

# ─── Error Handlers ─────────────────────────────────────────────────────────
@app.errorhandler(HTTPException)
def handle_http_exception(e):
    """Handle HTTP exceptions globally"""
    try:
        # Don't log favicon.ico 404 errors as they're normal browser behavior
        if not (e.code == 404 and 'favicon.ico' in request.url):
            logger.error(f"HTTP Exception: {e.code} - {e.description} - URL: {request.url}")
        
        return jsonify({"error": e.description}), e.code
    except Exception as ex:
        logger.error(f"Error in HTTP exception handler: {ex}")
        return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(Exception)
def handle_general_exception(e):
    """Handle general exceptions"""
    try:
        logger.error(f"Unhandled exception: {e} - URL: {request.url}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    except Exception as ex:
        logger.error(f"Error in general exception handler: {ex}")
        return jsonify({"error": "Critical error"}), 500

# ─── Database Initialization ────────────────────────────────────────────────
def init_database():
    """Initialize database tables"""
    try:
        with app.app_context():
            db.create_all()
            logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise


# ─── Session Management ─────────────────────────────────────────────────────
@app.before_request
def check_forced_logout():
    """Check if user has been force logged out"""
    try:
        if current_user.is_authenticated:
            stored_token = session.get('user_session_token')
            login_time = session.get('login_time')
            
            logger.debug(f"Checking forced logout for user {current_user.id}")
            
            # Convert login_time to datetime object if it's stored as string
            if isinstance(login_time, str):
                try:
                    login_time = datetime.fromisoformat(login_time.replace('Z', '+00:00'))
                except:
                    login_time = datetime.min
                    logger.warning(f"Could not parse login_time: {login_time}")
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
                logger.info(f"Forcing logout for user {current_user.id} - session token mismatch or admin logout")
                session.clear()
                logout_user()
                flash("Your session has been terminated by an administrator.", "warning")
                return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error in forced logout check: {e}")

@app.before_request
def check_session_validity():
    """Check if user's session is still valid"""
    try:
        if current_user.is_authenticated:
            stored_token = session.get('user_session_token')
            if not stored_token or stored_token != current_user.session_token:
                logger.info(f"Session expired for user {current_user.id}")
                logout_user()
                session.clear()
                if request.is_json:
                    return jsonify({'error': 'Session expired', 'redirect': url_for('login')}), 401
                else:
                    flash('Your session has expired. Please log in again.', 'warning')
                    return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error checking session validity: {e}")

# ═══════════════════════════════════════════════════════════════════════════
# ─── AUTHENTICATION ROUTES ──────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/")
def root():
    """Root route - redirect to login"""
    try:
        log_user_action("Accessed root route")
        logger.info(f"Root route accessed from IP: {request.remote_addr}")
        return redirect(url_for("login"))
    except Exception as e:
        logger.error(f"Error in root route: {e}")
        return redirect(url_for("login"))

# Test logging endpoint (remove in production)
@app.route("/test-logging")
def test_logging():
    """Test endpoint to verify logging is working"""
    try:
        logger.debug("Debug message test")
        logger.info("Info message test")
        logger.warning("Warning message test")
        logger.error("Error message test")
        
        return jsonify({
            "message": "Logging test completed successfully",
            "check": "logs/app.log file for all messages",
            "logged_messages": [
                "Debug message test",
                "Info message test", 
                "Warning message test",
                "Error message test"
            ]
        })
    except Exception as e:
        logger.error(f"Logging test failed: {e}")
        return jsonify({"error": f"Logging test failed: {e}"}), 500

if __name__ == "__main__":
    try:
        # Initialize database
        init_database()
        
        # Log application startup
        logger.info("="*50)
        logger.info("APPLICATION STARTING")
        logger.info("="*50)
        
        # Run the application
        app.run(debug=True)
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise

import logging

# Set up logger at the top of your file
logger = logging.getLogger(__name__)

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
            logger.info(f"User registered successfully: {username} with role: {role}")
            flash("Registration successful.", "success")
            return redirect(url_for("login"))
            
        return render_template("register.html")
        
    except Exception as e:
        logger.error(f"Error in user registration: {e}")
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
                    logger.warning(f"Inactive user attempted login: {username}")
                    flash("Your account is not active. Please contact an administrator.", "warning")
                    return render_template("login.html")
                
                # Update login information
                user.update_login_info()
                session['user_session_token'] = user.session_token
                session['login_time'] = datetime.now()
                
                # Login the user with remember=True for persistent sessions
                login_user(user, remember=True)
                session.permanent = True
                
                log_user_action("User logged in", f"Username: {username}")
                logger.info(f"User logged in successfully: {username}")
                
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
                logger.warning(f"Failed login attempt for username: {username}")
                flash("Invalid username or password.", "danger")
                log_user_action("Failed login attempt", f"Username: {username}")
        
        return render_template("login.html")
        
    except Exception as e:
        logger.error(f"Error in login route: {e}")
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
        logger.info(f"User logged out: {username}")
        return redirect(url_for("login"))
    except Exception as e:
        logger.error(f"Error in logout route: {e}")
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
            logger.warning(f"Non-admin user attempted admin access: {current_user.username}")
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("student_dashboard"))
        
        courses = Course.query.order_by(Course.created_at.desc()).all()
        teachers = User.query.filter_by(role="teacher").all()
        students = User.query.filter_by(role="student").all()
        groups = Group.query.all()
        
        log_user_action("Accessed admin dashboard")
        logger.debug(f"Admin dashboard accessed by: {current_user.username}")
        
        return render_template("admin_dashboard.html", 
                             courses=courses, teachers=teachers, 
                             students=students, groups=groups)
                             
    except Exception as e:
        logger.error(f"Error in admin dashboard: {e}")
        flash("Error loading admin dashboard.", "danger")
        return redirect(url_for("login"))

@app.route("/admin/manage_users")
@login_required
def manage_users():
    """Manage users route for admin"""
    try:
        if current_user.role != "admin":
            logger.warning(f"Non-admin user attempted user management access: {current_user.username}")
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("student_dashboard"))
        
        # Get all users with pagination
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        users = User.query.filter(User.role != 'admin').paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        log_user_action("Accessed user management")
        logger.debug(f"User management accessed by: {current_user.username}, page: {page}")
        return render_template("manage_users.html", users=users)
        
    except Exception as e:
        logger.error(f"Error in manage users: {e}")
        flash("Error loading user management.", "danger")
        return redirect(url_for("admin_dashboard"))

@app.route("/admin/edit_user/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    """Edit user route for admin"""
    try:
        if current_user.role != "admin":
            logger.warning(f"Non-admin user attempted user edit access: {current_user.username}")
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("student_dashboard"))
        
        user = User.query.get_or_404(user_id)
        
        # Don't allow editing admin accounts
        if user.role == "admin":
            logger.warning(f"Attempt to edit admin account: {user.username} by {current_user.username}")
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
                    user.password_changed_at = datetime.now()
                
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
                logger.info(f"User updated by admin {current_user.username}: User ID {user_id}, Username: {user.username}")
                flash(f"User {user.username} updated successfully", "success")
                return redirect(url_for("manage_users"))
                
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error updating user {user_id}: {e}")
                flash(f"Error updating user: {str(e)}", "danger")
        
        return render_template("edit_user.html", user=user)
        
    except Exception as e:
        logger.error(f"Error in edit user route: {e}")
        flash("Error accessing user edit page.", "danger")
        return redirect(url_for("manage_users"))

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    """Delete user route for admin"""
    try:
        if current_user.role != "admin":
            logger.warning(f"Non-admin user attempted user deletion: {current_user.username}")
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("student_dashboard"))
        
        user = User.query.get_or_404(user_id)
        
        # Don't allow deleting admin accounts
        if user.role == "admin":
            logger.warning(f"Attempt to delete admin account: {user.username} by {current_user.username}")
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
            logger.info(f"User deleted by admin {current_user.username}: User ID {user_id}, Username: {username}")
            flash(f"User {username} deleted successfully", "success")
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting user {user_id}: {e}")
            flash(f"Error deleting user: {str(e)}", "danger")
        
        return redirect(url_for("manage_users"))
        
    except Exception as e:
        logger.error(f"Error in delete user route: {e}")
        flash("Error deleting user.", "danger")
        return redirect(url_for("manage_users"))

@app.route("/admin/create_user", methods=["GET", "POST"])
@login_required
def create_user():
    """Create user route for admin"""
    try:
        if current_user.role != "admin":
            logger.warning(f"Non-admin user attempted user creation: {current_user.username}")
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
                    created_at=datetime.now()
                )
                
                db.session.add(new_user)
                db.session.commit()
                
                log_user_action("User created", f"Username: {username}, Role: {role}")
                logger.info(f"User created by admin {current_user.username}: Username: {username}, Role: {role}")
                flash(f"User {username} created successfully", "success")
                return redirect(url_for("manage_users"))
                
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error creating user: {e}")
                flash(f"Error creating user: {str(e)}", "danger")
        
        return render_template("create_user.html")
        
    except Exception as e:
        logger.error(f"Error in create user route: {e}")
        flash("Error accessing user creation page.", "danger")
        return redirect(url_for("manage_users"))



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
                courses = Course.query.filter_by(is_active=True).all()
                return render_template("admin_create_group.html", courses=courses)
            
            # Validate course exists
            course = Course.query.filter_by(id=course_id, is_active=True).first()
            if not course:
                flash("Invalid course selected.", "danger")
                courses = Course.query.filter_by(is_active=True).all()
                return render_template("admin_create_group.html", courses=courses)
            
            # Check if group name already exists for this course
            existing_group = Group.query.filter_by(name=name, course_id=course_id).first()
            if existing_group:
                flash("A group with this name already exists for this course.", "danger")
                courses = Course.query.filter_by(is_active=True).all()
                return render_template("admin_create_group.html", courses=courses)
            
            # Create group
            new_group = Group(name=name, course_id=course_id)
            db.session.add(new_group)
            db.session.commit()
            
            logger.info(f"Group '{name}' created for course {course_id} by admin {current_user.id}")
            flash(f"Group '{name}' created successfully.", "success")
            return redirect(url_for("admin_dashboard"))
        
        # GET request
        courses = Course.query.filter_by(is_active=True).all()
        return render_template("admin_create_group.html", courses=courses)
        
    except Exception as e:
        logger.error(f"Create group error: {str(e)}")
        db.session.rollback()
        flash("Error creating group.", "error")
        try:
            courses = Course.query.filter_by(is_active=True).all()
            return render_template("admin_create_group.html", courses=courses)
        except Exception as template_error:
            logger.error(f"Template error: {str(template_error)}")
            return redirect(url_for("admin_dashboard"))

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

# ─── API: generate_pills ─────────────────────────────────────────────────────
@app.route("/api/generate_pills", methods=["POST"])
@login_required
def generate_pills():
    """Generate educational pills for given topics with optional problem context."""
    try:
        logger.info(f"User {current_user.id} ({current_user.role}) generating pills")
        
        data = request.get_json() or {}
        topics = data.get("topics")
        problem = data.get("problem_statement") or data.get("statement")
        use_problem_context = data.get("use_problem_context", True)  # Default to True
        
        if not isinstance(topics, list) or not topics:
            logger.warning(f"Invalid topics provided by user {current_user.id}: {topics}")
            abort(400, "Missing or invalid 'topics'; expected a non-empty list of strings.")
        
        # Build system prompt based on whether to use problem context
        if use_problem_context and problem and isinstance(problem, str):
            system_prompt = (
                "You are an expert educator. Given the problem statement below and its key topics, "
                "produce a JSON object under the key 'pills' whose value is an array of objects. "
                "Each object must include:\n"
                "• topic: the exact name of the concept\n"
                "• content: well-structured HTML educational content (400-500 words) with clear sections:\n"
                "  - Brief definition/overview\n"
                "  - Key principles or components (use <ul><li> for bullet points)\n"
                "  - Why it matters in this context\n"
                "  - Common applications or variations\n"
                "  - How this topic helps solve the alternate example\n"
                "  Format using proper HTML tags: <h4> for subheadings, <p> for paragraphs, <strong> for emphasis, <ul><li> for lists\n"
                "• example: 2-3 concrete, relatable scenarios showing how this topic applies to solving a single, alternate version of the original problem. "
                "All examples must relate to the same alternate example. Wrap each example in separate HTML tags: "
                "<example1>first example</example1> <example2>second example</example2> <example3>third example if provided</example3>\n"
                "• key_takeaways: 3-4 bullet points summarizing the most important concepts\n\n"
                "Format the content with proper HTML structure:\n"
                "- Use <strong> for key terms\n"
                "- Use <ul><li> for bullet point lists\n"
                "- Use <p> for paragraphs (keep them short, 2-3 sentences max)\n"
                "- Use <h6> for subheadings when helpful\n"
                "- Use <h6> for headings when helpful\n"
                "- Ensure all HTML is properly formatted and escaped\n"
                "- Ensure not ot use h1 to h5 tags in response\n"
                "- For examples field: wrap each example in numbered HTML tags: <example1>, <example2>, <example3>\n\n"
                "Generate a single alternate version of the problem that is structurally similar but different in surface details.\n"
                "This alternate example should be used consistently across the example sections of all topics.\n"
                "Each topic must include a section that clearly explains how the concept helps in solving that alternate example.\n"
                "Do not reveal or solve the original problem statement.\n"
                "Return **only** the JSON.\n\n"
                f"Problem Statement:\n\"\"\"\n{problem}\n\"\"\"\n"
                "Topics: " + ", ".join(topics)
            )
        else:
            # General knowledge pills without problem context
            system_prompt = (
                "You are an expert educator. Create comprehensive knowledge pills for the given topics. "
                "Produce a JSON object under the key 'pills' whose value is an array of objects. "
                "Each object must include:\n"
                "• topic: the exact name of the concept\n"
                "• content: well-structured educational content (400-500 words) with clear sections:\n"
                "  - Brief definition/overview\n"
                "  - Key principles or components (use bullet points when appropriate)\n"
                "  - Why it's important to understand\n"
                "  - Common applications or use cases\n"
                "• example: 2-3 concrete, relatable scenarios showing practical application. Each example should be wrapped in separate HTML tags: <example1>first example</example1> <example2>second example</example2> <example3>third example if provided</example3>\n"
                "• key_takeaways: 3-4 bullet points summarizing the most important concepts\n\n"
                "Format the content with proper HTML structure:\n"
                "- Use <strong> for key terms\n"
                "- Use <ul><li> for bullet point lists\n"
                "- Use <p> for paragraphs (keep them short, 2-3 sentences max)\n"
                "- Use <h6> for subheadings when helpful\n"
                "- Ensure all HTML is properly formatted and escaped\n"
                "- For examples field: wrap each example in numbered HTML tags: <example1>, <example2>, <example3>\n\n"
                "Make each pill a comprehensive, standalone learning resource.\n"
                "Return **only** the JSON.\n\n"
                "Topics: " + ", ".join(topics)
            )
        
        logger.debug(f"System prompt generated for user {current_user.id}")
        
        resp = openai.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": "Generate the knowledge pills as specified."}
            ],
        )
        
        content = resp.choices[0].message.content.strip()
        
        # Try to extract JSON if wrapped in code blocks
        if content.startswith("```json"):
            content = content[7:-3].strip()
        elif content.startswith("```"):
            content = content[3:-3].strip()
        
        parsed = json.loads(content)
        pills = parsed.get("pills", [])
        
        # Validate the structure of pills
        for pill in pills:
            if not all(key in pill for key in ["topic", "content", "example", "key_takeaways"]):
                logger.error(f"Invalid pill structure from model for user {current_user.id}")
                return jsonify({"error": "Invalid pill structure from model"}), 502
        
        logger.info(f"Successfully generated {len(pills)} pills for user {current_user.id}")
        return jsonify({
            "pills": pills,
            "used_problem_context": use_problem_context and bool(problem),
            "total_pills": len(pills)
        })
        
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error for user {current_user.id}: {str(e)}")
        return jsonify({
            "error": "Invalid JSON from model", 
            "raw": resp.choices[0].message.content,
            "json_error": str(e)
        }), 502
    except Exception as e:
        logger.error(f"Error generating pills for user {current_user.id}: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ─── API: generate_prompt ─────────────────────────────────────────────────────
@app.route("/api/generate_prompt", methods=["POST"])
@login_required
def generate_prompt():
    """Generate evaluation prompt for student submissions."""
    try:
        logger.info(f"User {current_user.id} ({current_user.role}) generating evaluation prompt")
        
        data = request.get_json() or {}
        required_fields = ("base_prompt", "problem_statement", "pill_topics", "rubric")
        
        for key in required_fields:
            if key not in data:
                logger.warning(f"Missing field '{key}' in prompt generation for user {current_user.id}")
                abort(400, f"Missing '{key}' in payload")
        
        problem = data["problem_statement"].strip()
        topics = data["pill_topics"]
        rubric = data["rubric"]
        
        if not isinstance(topics, list) or not topics:
            logger.warning(f"Invalid topics format for user {current_user.id}: {topics}")
            abort(400, "'pill_topics' must be a non-empty list")
        if not isinstance(rubric, dict) or not rubric:
            logger.warning(f"Invalid rubric format for user {current_user.id}: {rubric}")
            abort(400, "'rubric' must be a non-empty dict of category→score")
        
        total = sum(rubric.values())
        eval_lines = [f"{i+1}. {cat} (max {score})" for i,(cat,score) in enumerate(rubric.items())]
        eval_block = "**Evaluation Criteria (Total: {} points):**\n".format(total) + "\n".join(eval_lines)
        
        # Build a much stricter system prompt
        lines = [
            "You are a senior technical evaluator with EXTREMELY STRICT standards. Evaluate the student's solution ONLY based on problem-specific context and implementation details.",
            "",
            f"Problem Statement:\n\"{problem}\"",
            "",
            "Topics to assess: " + ", ".join(topics),
            "",
            eval_block,
            "",
            "**MANDATORY EVALUATION RULES - NO EXCEPTIONS:**",
            "1. **ZERO TOLERANCE for generic statements** - No points for general topic descriptions",
            "2. **PROBLEM-CONTEXT ONLY** - Points awarded ONLY for content directly addressing THIS problem",
            "3. **IMPLEMENTATION SPECIFICITY REQUIRED** - Must explain exact steps for THIS problem",
            "4. **NO CREDIT for topic name-dropping** - Mentioning concepts without problem-specific application = 0 points",
            "",
            "**Scoring Guidelines (STRICT ENFORCEMENT):**",
            "- **Full credit (100%)** ONLY when submission demonstrates:",
            "  • SPECIFIC explanation of how the concept solves THIS exact problem",
            "  • DETAILED implementation steps tailored to the problem requirements",
            "  • CLEAR connection between concept mechanics and problem constraints",
            "  • CONCRETE details about data flow, algorithms, or architecture for THIS problem",
            "",
            "- **Partial credit (50–75%)** ONLY when submission shows:",
            "  • Good understanding of how concept applies to THIS specific problem",
            "  • Some implementation details relevant to problem context",
            "  • Clear problem-specific reasoning but missing some depth",
            "  • Shows adaptation of concept to problem requirements",
            "",
            "- **Minimal credit (10–25%)** ONLY when submission demonstrates:",
            "  • Basic problem-specific application with limited details",
            "  • Shows some connection to problem context but lacks implementation specifics",
            "  • Attempts to relate concept to problem but insufficient depth",
            "",
            "- **ZERO credit (0%)** for ANY of the following:",
            "  • Generic concept definitions without problem context",
            "  • 'I will use [topic]' without explaining HOW in this specific problem",
            "  • General explanations that could apply to any problem",
            "  • Textbook definitions or theory without problem-specific application",
            "  • Vague statements like 'it will help with the application'",
            "  • Any content not directly tied to solving THIS specific problem",
            "",
            "**STRICT EVIDENCE REQUIREMENTS:**",
            "- Must explain EXACTLY how the concept addresses the specific problem requirements",
            "- Must describe PRECISE implementation steps for THIS problem scenario",
            "- Must show understanding of problem constraints and how concept handles them",
            "- Must demonstrate adaptation of concept to problem-specific needs",
            "",
            "**AUTOMATIC ZERO POINTS for:**",
            "- 'I will use machine learning for this application' (no problem-specific details)",
            "- 'Data structures will be helpful' (generic, not problem-specific)",
            "- 'REST APIs are important for web applications' (general statement)",
            "- Any explanation that doesn't mention specific problem elements",
            "- Copy-paste definitions without problem context",
            "",
            "**POINTS AWARDED ONLY for responses like:**",
            "- 'For this user authentication problem, I'll implement JWT tokens by storing user credentials in the payload, setting expiration based on the 24-hour session requirement mentioned, and validating tokens on each API call to the protected user dashboard endpoints'",
            "- 'To handle the real-time chat feature in this messaging app, I'll use WebSockets to establish persistent connections, implement message queuing for offline users, and store conversation history in the database with the specified user-to-user relationship structure'",
            "",
            "**CRITICAL EVALUATION CHECKLIST:**",
            "Before awarding ANY points, verify:",
            "□ Does the answer specifically address elements mentioned in the problem statement?",
            "□ Are implementation details tailored to this exact problem scenario?",
            "□ Does the explanation show how the concept solves the specific challenges in this problem?",
            "□ Would this answer be useless for a different problem? (If yes, it's problem-specific = good)",
            "",
            "- Sum of individual scores must match the reported `total_score` and must not exceed the maximum possible.",
            "",
            "**Format your response as a single JSON object:**",
            "{",
            " \"scores\": {",
        ]
        
        for cat in rubric:
            lines.append(f" \"{cat}\": number,")
        
        lines += [
            " },",
            " \"total_score\": number,",
            " \"feedback\": [",
        ]
        
        for cat in rubric:
            lines.append(f" \"{cat}: specific, 1–2 sentence feedback referring to evidence in the solution\",")
        
        lines += [
            " ]",
            "}",
            "",
            "**FINAL REMINDER: BE RUTHLESSLY STRICT. Award points ONLY for problem-specific, implementation-focused content. Generic knowledge = 0 points.**",
            "",
            "End of prompt."
        ]
        
        prompt_text = "\n".join(lines)
        logger.info(f"Successfully generated evaluation prompt for user {current_user.id}")
        return jsonify({"system_prompt": prompt_text})
        
    except Exception as e:
        logger.error(f"Error generating prompt for user {current_user.id}: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ─── Admin Views ─────────────────────────────────────────────────────────────

@app.route('/admin/delete_problem/<int:id>')
@login_required
@role_required("admin")
def admin_delete_problem(id):
    """Delete a problem (admin only)."""
    try:
        logger.info(f"Admin {current_user.id} attempting to delete problem {id}")
        
        prob = Problem.query.get_or_404(id)
        
        # Check for existing submissions
        submission_count = Submission.query.filter_by(problem_id=id).count()
        if submission_count > 0:
            logger.warning(f"Admin {current_user.id} tried to delete problem {id} with {submission_count} submissions")
            flash(f'Cannot delete problem: {submission_count} student submissions found.', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        db.session.delete(prob)
        db.session.commit()
        
        logger.info(f"Problem {id} successfully deleted by admin {current_user.id}")
        flash('Problem deleted successfully.', 'success')
        
    except Exception as e:
        logger.error(f'Error deleting problem {id} by admin {current_user.id}: {str(e)}')
        db.session.rollback()
        flash('An error occurred while deleting the problem.', 'danger')

    return redirect(url_for('admin_dashboard'))

# ─── Student Views ─────────────────────────────────────────────────────────── 

@app.route("/student/dashboard")
@login_required
@role_required("student")
def student_dashboard():
    """Student dashboard showing enrolled problems and progress."""
    try:
        logger.info(f"Student {current_user.id} accessing dashboard")
        
        if current_user.must_change_password:
            logger.info(f"Student {current_user.id} redirected to change password")
            flash("You must change your password before accessing the dashboard.", "warning")
            return redirect(url_for("change_password"))
        
        # Get student's enrolled groups
        student_groups = StudentGroup.query.filter_by(student_id=current_user.id).all()
        
        # If student is not enrolled in any groups, show empty dashboard
        if not student_groups:
            logger.info(f"Student {current_user.id} has no enrolled groups")
            return render_template("student_dashboard.html",
                                 problems=[], subs={}, courses=[])
        
        # Get courses from enrolled groups
        courses = [sg.group.course for sg in student_groups]
        
        # Get only active courses
        active_courses = [c for c in courses if c.is_active]
        
        # Get problems from active enrolled courses - only active problems
        course_ids = [c.id for c in active_courses]
        problems = []
        
        if course_ids:
            problems = (Problem.query
                       .filter(Problem.course_id.in_(course_ids))
                       .filter(Problem.is_active == True)  # Only active problems
                       .order_by(Problem.created_at.desc())
                       .all())
        
        # Build submission map for the filtered problems
        subs = {}
        for p in problems:
            last = (Submission.query
                   .filter_by(student_id=current_user.id, problem_id=p.id)
                   .order_by(Submission.created_at.desc())
                   .first())
            if last:
                subs[p.id] = last
        
        # Sort: unsolved problems first, then solved ones
        problems = sorted(problems, key=lambda p: p.id in subs)
        
        logger.info(f"Student {current_user.id} dashboard loaded with {len(problems)} problems from {len(active_courses)} active courses")
        
        return render_template("student_dashboard.html",
                             problems=problems, subs=subs, courses=active_courses)
                             
    except Exception as e:
        logger.error(f"Error loading student dashboard for user {current_user.id}: {str(e)}")
        flash("An error occurred while loading your dashboard.", "danger")
        return render_template("student_dashboard.html",
                             problems=[], subs={}, courses=[])

@app.route("/student/reports")
@login_required
@role_required("student")
def student_reports():
    """Student reports page showing last attempt for each problem and performance analytics."""
    try:
        logger.info(f"Student {current_user.id} accessing reports")
        
        # Check if password needs to be changed
        if current_user.must_change_password:
            logger.info(f"Student {current_user.id} redirected to change password from reports")
            flash("You must change your password before accessing the reports.", "warning")
            return redirect(url_for("change_password"))
        
        # Get student's enrolled groups
        student_groups = StudentGroup.query.filter_by(student_id=current_user.id).all()
        
        # If student is not enrolled in any groups, show empty reports page
        if not student_groups:
            logger.info(f"Student {current_user.id} has no enrolled groups for reports")
            return render_template("student_reports.html",
                                 submissions=[], avg_score=0, best_score=0,
                                 unique_problems=0, course_stats={}, courses=[])
        
        # Get courses from enrolled groups
        courses = [sg.group.course for sg in student_groups]
        active_courses = [c for c in courses if c.is_active]
        
        if not active_courses:
            logger.info(f"Student {current_user.id} has no active courses for reports")
            return render_template("student_reports.html",
                                 submissions=[], avg_score=0, best_score=0,
                                 unique_problems=0, course_stats={}, courses=[])
        
        # Get ALL submissions by this student from active courses
        all_submissions = (Submission.query
                          .filter_by(student_id=current_user.id)
                          .join(Problem)
                          .join(Course)
                          .filter(Course.id.in_([c.id for c in active_courses]))
                          .order_by(Submission.created_at.desc())
                          .all())
        
        # Get only the LAST attempt for each problem AND calculate total attempts per problem
        problem_submissions = {}
        problem_attempt_counts = {}
        
        for sub in all_submissions:
            # Count total attempts per problem
            if sub.problem_id not in problem_attempt_counts:
                problem_attempt_counts[sub.problem_id] = 0
            problem_attempt_counts[sub.problem_id] += 1
            
            # Keep track of the latest submission for each problem
            if sub.problem_id not in problem_submissions:
                problem_submissions[sub.problem_id] = sub
            else:
                # Keep the one with higher attempt number (latest) or latest by date
                if (sub.attempt and problem_submissions[sub.problem_id].attempt and 
                    sub.attempt > problem_submissions[sub.problem_id].attempt) or \
                   (sub.created_at > problem_submissions[sub.problem_id].created_at):
                    problem_submissions[sub.problem_id] = sub
        
        # Convert to list for template and add attempt counts
        submissions = []
        for problem_id, submission in problem_submissions.items():
            # Add the total attempt count as an attribute
            submission.total_attempts = problem_attempt_counts[problem_id]
            submissions.append(submission)
        
        # Sort by creation date (most recent first)
        submissions.sort(key=lambda x: x.created_at, reverse=True)
        
        # If no submissions, return empty template
        if not submissions:
            logger.info(f"Student {current_user.id} has no submissions for reports")
            return render_template("student_reports.html",
                                 submissions=[], avg_score=0, best_score=0,
                                 unique_problems=0, course_stats={}, courses=active_courses)
        
        # Calculate overall performance statistics based on problems (not attempts)
        final_scores = [sub.total_score for sub in submissions if sub.total_score is not None]
        avg_score = sum(final_scores) / len(final_scores) if final_scores else 0
        best_score = max(final_scores) if final_scores else 0
        unique_problems = len(submissions)  # Since we have one submission per problem
        
        # Calculate course-wise statistics
        course_stats = {}
        for course in active_courses:
            course_submissions = [sub for sub in submissions if sub.problem.course_id == course.id]
            
            if course_submissions:
                course_scores = [sub.total_score for sub in course_submissions if sub.total_score is not None]
                course_stats[course.code] = {
                    'problems_count': len(course_submissions),  # Count of problems, not attempts
                    'avg_score': sum(course_scores) / len(course_scores) if course_scores else 0,
                    'best_score': max(course_scores) if course_scores else 0,
                    'course_name': course.name
                }
        
        logger.info(f"Student {current_user.id} reports loaded: {unique_problems} unique problems, avg score: {avg_score:.2f}")
        
        return render_template("student_reports.html",
                             submissions=submissions,
                             avg_score=avg_score,
                             best_score=best_score,
                             unique_problems=unique_problems,
                             course_stats=course_stats,
                             courses=active_courses)
                             
    except Exception as e:
        logger.error(f"Error loading student reports for user {current_user.id}: {str(e)}")
        flash("An error occurred while loading your reports.", "danger")
        return render_template("student_reports.html",
                             submissions=[], avg_score=0, best_score=0,
                             unique_problems=0, course_stats={}, courses=[])

# ─── Utility Context Processor ───────────────────────────────────────────────

@app.context_processor
def inject_navigation_data():
    """Inject navigation data into all templates."""
    try:
        nav_data = {}
        
        if current_user.is_authenticated:
            if current_user.role == "student":
                # Count unread notifications or new problems for badge
                student_groups = StudentGroup.query.filter_by(student_id=current_user.id).all()
                if student_groups:
                    courses = [sg.group.course for sg in student_groups]
                    active_courses = [c for c in courses if c.is_active]
                    course_ids = [c.id for c in active_courses]
                    
                    # Count unsolved problems
                    if course_ids:
                        unsolved_count = (Problem.query
                                        .filter(Problem.course_id.in_(course_ids))
                                        .filter(Problem.is_active == True)
                                        .outerjoin(Submission, 
                                                 (Submission.problem_id == Problem.id) & 
                                                 (Submission.student_id == current_user.id))
                                        .filter(Submission.id == None)
                                        .count())
                        nav_data['unsolved_problems'] = unsolved_count
                    
                    # Count total submissions for reports badge
                    total_submissions = Submission.query.filter_by(student_id=current_user.id).count()
                    nav_data['total_submissions'] = total_submissions
        
        return nav_data
        
    except Exception as e:
        logger.error(f"Error injecting navigation data: {str(e)}")
        return {}

# ─── Password Management ─────────────────────────────────────────────────────

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user password with validation and role-based redirects."""
    try:
        logger.info(f"User {current_user.id} ({current_user.role}) accessing password change")
        
        # Ensure must_change_password has a default value
        if not hasattr(current_user, 'must_change_password'):
            current_user.must_change_password = False
            
        if request.method == "POST":
            current_password = request.form.get("current_password", "").strip()
            new_password = request.form.get("new_password", "").strip()
            confirm_password = request.form.get("confirm_password", "").strip()
            
            # Basic validation
            if not new_password:
                logger.warning(f"User {current_user.id} provided empty new password")
                flash("New password cannot be empty.", "danger")
                return render_template("change_password.html")
            
            # Validate current password (only if not forced change)
            if not current_user.must_change_password:
                if not current_password:
                    logger.warning(f"User {current_user.id} missing current password")
                    flash("Current password is required.", "danger")
                    return render_template("change_password.html")
                if not check_password_hash(current_user.password, current_password):
                    logger.warning(f"User {current_user.id} provided incorrect current password")
                    flash("Current password is incorrect.", "danger")
                    return render_template("change_password.html")
            
            # Validate new password
            if len(new_password) < 6:
                logger.warning(f"User {current_user.id} provided password too short")
                flash("New password must be at least 6 characters long.", "danger")
                return render_template("change_password.html")
            
            if new_password != confirm_password:
                logger.warning(f"User {current_user.id} password confirmation mismatch")
                flash("New passwords do not match.", "danger")
                return render_template("change_password.html")
            
            # Update password
            current_user.password = generate_password_hash(new_password)
            current_user.must_change_password = False
            current_user.password_changed_at = datetime.now()
            
            try:
                db.session.commit()
                logger.info(f"Password successfully changed for user {current_user.id}")
                flash("Password changed successfully!", "success")
                
                # Redirect based on role
                if current_user.role == "admin":
                    return redirect(url_for("admin_dashboard"))
                elif current_user.role == "teacher":
                    return redirect(url_for("teacher_dashboard"))
                else:
                    return redirect(url_for("student_dashboard"))
                    
            except Exception as e:
                db.session.rollback()
                logger.error(f"Database error during password change for user {current_user.id}: {str(e)}")
                flash("An error occurred while updating your password. Please try again.", "danger")
                return render_template("change_password.html")
        
        # GET request - render the form
        return render_template("change_password.html")
        
    except Exception as e:
        logger.error(f"Error in change_password route for user {current_user.id}: {str(e)}")
        flash("An unexpected error occurred. Please try again.", "danger")
        return render_template("change_password.html")

@app.route("/student/solve/<int:pid>")
@login_required
def student_solve(pid):
    """Display problem solving interface for students."""
    try:
        logger.info(f"Student {current_user.id} accessing problem {pid}")
        
        # Only students may view this
        if current_user.role != "student":
            logger.warning(f"Non-student user {current_user.id} tried to access student_solve")
            return redirect(url_for("admin_dashboard"))
        
        # Must change password first
        if current_user.must_change_password:
            logger.info(f"Student {current_user.id} redirected to change password")
            flash("You must change your password before accessing problems.", "warning")
            return redirect(url_for("change_password"))
        
        # Load problem or 404
        problem = Problem.query.get_or_404(pid)
        logger.debug(f"Problem {pid} loaded for student {current_user.id}")
        
        # Fetch most recent submission
        last_sub = (
            Submission.query
            .filter_by(student_id=current_user.id, problem_id=pid)
            .order_by(Submission.created_at.desc())
            .first()
        )
        
        # Block if 3 or more attempts used
        if last_sub and last_sub.attempt >= 3:
            logger.warning(f"Student {current_user.id} has exhausted attempts for problem {pid}")
            flash("You have exhausted all attempts for this problem.", "warning")
            return redirect(url_for("student_dashboard"))
        
        # Parse rubric JSON (or fallback to empty dict)
        try:
            rubric_data = json.loads(problem.rubric)
        except (TypeError, ValueError) as e:
            logger.warning(f"Failed to parse rubric for problem {pid}: {str(e)}")
            rubric_data = {}
        
        # Parse pills JSON (or fallback to empty list)
        try:
            pills_data = json.loads(problem.pills) if problem.pills else []
        except (TypeError, ValueError) as e:
            logger.warning(f"Failed to parse pills for problem {pid}: {str(e)}")
            pills_data = []
        
        # Compute attempts left (3 allowed total)
        used = last_sub.attempt if last_sub else 0
        attempts_left = max(0, 3 - used)
        
        logger.info(f"Student {current_user.id} has {attempts_left} attempts left for problem {pid}")
        
        return render_template(
            "student_solve.html",
            problem=problem,
            last_sub=last_sub,
            rubric=rubric_data,
            pills=pills_data,
            attempts_left=attempts_left
        )
        
    except Exception as e:
        logger.error(f'Error in student_solve for problem {pid} by student {current_user.id}: {str(e)}')
        flash('An error occurred while loading the problem.', 'danger')
        return redirect(url_for("student_dashboard"))


@app.route("/api/evaluate", methods=["POST"])
@login_required
def api_evaluate():
    """Evaluate student solution using AI model."""
    try:
        logger.info(f"User {current_user.id} submitting solution for evaluation")
        
        data = request.get_json() or {}
        pid   = data.get("problem_id")
        sp    = data.get("system_prompt")
        stmt  = data.get("problem_statement")
        sol   = data.get("student_solution")

        if not all([pid, sp, stmt, sol]):
            logger.warning(f"User {current_user.id} submitted incomplete evaluation data")
            abort(400, "Missing one of: problem_id, system_prompt, problem_statement, student_solution")

        problem = Problem.query.get(int(pid))
        if not problem:
            logger.warning(f"User {current_user.id} requested evaluation for non-existent problem {pid}")
            abort(404, "Problem not found")

        # 3-attempt limit
        used = Submission.query.filter_by(
            student_id=current_user.id, problem_id=problem.id
        ).count()
        
        if used >= 3:
            logger.warning(f"Student {current_user.id} exceeded attempt limit for problem {pid}")
            return jsonify({"error":"No attempts left"}), 403

        logger.debug(f"Sending evaluation request to AI model for student {current_user.id}, problem {pid}")
        
        messages = [
            {"role":"system","content":sp},
            {"role":"user","content":f"Problem Statement:\n```\n{stmt}\n```\n\nStudent Submission:\n```\n{sol}\n```"}
        ]

        try:
            resp    = openai.chat.completions.create(model=MODEL_NAME, messages=messages)
            content = resp.choices[0].message.content
            result  = json.loads(content)
            logger.debug(f"AI evaluation completed for student {current_user.id}, problem {pid}")
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON from AI model for student {current_user.id}, problem {pid}: {str(e)}")
            return jsonify({"error":"Invalid JSON from model", "raw":content}), 502
        except Exception as e:
            logger.error(f"AI model error for student {current_user.id}, problem {pid}: {str(e)}")
            return jsonify({"error":str(e)}), 500

        # Persist submission
        sub = Submission(
            student_id=current_user.id,
            problem_id=problem.id,
            solution=sol,
            scores=json.dumps(result.get("scores",{})),
            total_score=result.get("total_score",0),
            feedback=json.dumps(result.get("feedback",[])),
            attempt=used+1
        )
        
        db.session.add(sub)
        db.session.commit()
        
        logger.info(f"Submission {sub.id} saved for student {current_user.id}, problem {pid}, score: {result.get('total_score', 0)}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f'Error in api_evaluate for user {current_user.id}: {str(e)}')
        db.session.rollback()
        return jsonify({"error": "An error occurred during evaluation"}), 500


@app.route("/student/report/<int:sid>", endpoint='student_report')
@app.route("/teacher/report/<int:sid>", endpoint='teacher_report')
@login_required
def report_download(sid):
    """Generate and download PDF report for submission."""
    try:
        logger.info(f"User {current_user.id} ({current_user.role}) requesting report for submission {sid}")
        
        # Fetch submission
        sub = Submission.query.get_or_404(sid)
        
        # Authorization check - allow both student owner and teacher
        if current_user.role == "student":
            if sub.student_id != current_user.id:
                logger.warning(f"Student {current_user.id} tried to access unauthorized submission {sid}")
                abort(403)
        elif current_user.role == "teacher":
            # Verify teacher owns the problem/course
            prob = Problem.query.get_or_404(sub.problem_id)
            course = Course.query.filter_by(id=prob.course_id, teacher_id=current_user.id).first()
            if not course:
                logger.warning(f"Teacher {current_user.id} tried to access unauthorized submission {sid}")
                abort(403)
        else:
            logger.warning(f"Unauthorized role {current_user.role} tried to access submission {sid}")
            abort(403)
        
        prob = Problem.query.get_or_404(sub.problem_id)
        logger.debug(f"Generating PDF report for submission {sid}")

        # Buffer + document
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=40, leftMargin=40,
            topMargin=40,   bottomMargin=40
        )

        # Styles
        styles       = getSampleStyleSheet()
        title_style  = ParagraphStyle('title',
                          parent=styles['Title'],
                          alignment=1,
                          spaceAfter=6)
        heading_style= ParagraphStyle('heading2',
                          parent=styles['Heading2'],
                          spaceAfter=6)
                          
        normal       = ParagraphStyle('normal',
                          parent=styles['Normal'],
                          wordWrap='CJK',
                          spaceAfter=4)

        story = []
        # ── Header ─────────────────────────
        story.append(Paragraph("TECHTONIC Evaluation Report", title_style))
        width = letter[0] - doc.leftMargin - doc.rightMargin
        story.append(Table(
            [['']], colWidths=[width], rowHeights=[4],
            style=[('BACKGROUND',(0,0),(-1,-1), colors.HexColor('#0056b3'))]
        ))
        story.append(Spacer(1,12))

        # ── Metadata ───────────────────────
        # Date in DD-MM-YYYY HH:MM
        date_str = sub.created_at.strftime('%d-%m-%Y %H:%M')
        
        # Get student info for teacher view
        student = User.query.get(sub.student_id)
        
        story.append(Paragraph(f"<b>Problem:</b> {prob.title}", normal))
        if current_user.role == "teacher":
            story.append(Paragraph(f"<b>Student:</b> {student.name} ({student.htno})", normal))
        story.append(Paragraph(f"<b>Date:</b> {date_str}", normal))
        story.append(Paragraph(f"<b>Total Score:</b> {sub.total_score} / 100", normal))
        story.append(Spacer(1,12))

        # ── Problem Statement ──────────────
        story.append(Paragraph("Problem Statement", heading_style))
        for line in prob.statement.splitlines():
            story.append(Paragraph(line, normal))
        story.append(Spacer(1,12))

        # ── Student Solution (section-wise) ─
        story.append(Paragraph("Student Solution", heading_style))
        sol_map = json.loads(sub.solution or "{}")
        for category, html_content in sol_map.items():
            # strip out HTML tags to plain text
            text = BeautifulSoup(html_content, 'html.parser').get_text().strip()
            if not text:
                continue  # skip empty sections
            story.append(Paragraph(category, heading_style))
            for ln in text.splitlines():
                story.append(Paragraph(ln, normal))
            story.append(Spacer(1,12))

        # ── Feedback Details ───────────────
        story.append(Paragraph("Feedback Details", heading_style))
        header_style = ParagraphStyle(
            'header', parent=styles['Normal'],
            textColor=colors.white, alignment=1
        )
        feedbacks  = json.loads(sub.feedback or "[]")
        scores_map = json.loads(sub.scores   or "{}")

        table_data = [[
            Paragraph("Category", header_style),
            Paragraph("Feedback", header_style),
            Paragraph("Score", header_style)
        ]]
        for fb in feedbacks:
            cat, msg = fb.split(":",1)
            table_data.append([
                Paragraph(cat.strip(), normal),
                Paragraph(msg.strip(), normal),
                Paragraph(str(scores_map.get(cat.strip(), 0)), normal)
            ])

        col_widths = [2.5*inch, 3.5*inch, 1*inch]
        table = Table(table_data, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0), colors.HexColor('#0056b3')),
            ('TEXTCOLOR',(0,0),(-1,0), colors.white),
            ('ALIGN',(2,1),(2,-1),'CENTER'),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
            ('GRID',(0,0),(-1,-1),0.5, colors.grey),
            ('LEFTPADDING',(0,0),(-1,-1),6),
            ('RIGHTPADDING',(0,0),(-1,-1),6),
            ('TOPPADDING',(0,0),(-1,-1),4),
            ('BOTTOMPADDING',(0,0),(-1,-1),4),
        ]))
        story.append(table)

        # Build & send
        doc.build(story)
        buffer.seek(0)
        
        # Different filename for teacher vs student
        if current_user.role == "teacher":
            filename = f"report_{student.htno}_{sid}.pdf"
        else:
            filename = f"report_{sid}.pdf"
        
        logger.info(f"PDF report generated successfully for submission {sid} by user {current_user.id}")
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=filename,
            mimetype="application/pdf"
        )

    except Exception as e:
        logger.error(f'Error generating PDF report for submission {sid} by user {current_user.id}: {str(e)}')
        abort(500, "Unable to generate report PDF right now.")


# ============================================================================
# TEACHER ROUTES
# ============================================================================

@app.route("/api/teacher/course/<int:course_id>/reset-sessions", methods=["POST"])
@login_required
def reset_course_sessions(course_id):
    """Reset all student sessions for a specific course (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} attempting to reset sessions for course {course_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to reset course sessions")
            return jsonify({"status": "error", "error": "Unauthorized"}), 403
        
        if current_user.must_change_password:
            logger.info(f"Teacher {current_user.id} must change password before resetting sessions")
            return jsonify({"status": "error", "error": "Password change required"}), 400
        
        # Verify teacher owns this course
        course = Course.query.filter_by(
            id=course_id,
            teacher_id=current_user.id
        ).first_or_404()
        
        logger.debug(f"Course {course_id} verified for teacher {current_user.id}")
        
        # Get all groups for this course
        groups = Group.query.filter_by(course_id=course_id).all()
        
        # Get all students in these groups
        student_ids = []
        for group in groups:
            for student_group in group.student_groups:
                student_ids.append(student_group.student_id)
        
        # Remove duplicates
        student_ids = list(set(student_ids))
        
        if not student_ids:
            logger.info(f"No students found in course {course_id} for session reset")
            return jsonify({
                "status": "ok", 
                "message": "No students found in this course to reset sessions."
            })
        
        # Reset sessions for all students
        students = User.query.filter(User.id.in_(student_ids)).all()
        reset_count = 0
        
        for student in students:
            # Generate new session token and set force logout timestamp
            student.session_token = secrets.token_urlsafe(32)
            student.force_logout_at = datetime.now()
            student.is_online=0
            reset_count += 1
        
        # Commit all changes
        db.session.commit()
        
        logger.info(f"Teacher {current_user.id} successfully reset sessions for {reset_count} students in course {course_id}")
        
        return jsonify({
            "status": "ok",
            "message": f"Successfully reset sessions for {reset_count} students. They will be logged out on their next request."
        })
        
    except Exception as e:
        logger.error(f'Error resetting course sessions for course {course_id} by teacher {current_user.id}: {str(e)}')
        db.session.rollback()
        return jsonify({"status": "error", "error": "An error occurred while resetting sessions"}), 500


@app.route('/teacher/group/<int:group_id>/reset_logins', methods=['POST'])
@login_required
def reset_group_logins(group_id):
    """Reset logins for all students in a specific group (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} attempting to reset logins for group {group_id}")
        
        # Verify teacher has access to this group
        group = Group.query.join(Course).filter(
            Group.id == group_id,
            Course.teacher_id == current_user.id
        ).first()
        
        if not group:
            logger.warning(f"Teacher {current_user.id} tried to access unauthorized group {group_id}")
            return jsonify({'success': False, 'message': 'Group not found or access denied'}), 403
        
        students_logged_out = 0
        
        for student in group.students:
            # Invalidate student's session
            student.invalidate_session()
            students_logged_out += 1
        
        db.session.commit()
        
        logger.info(f"Teacher {current_user.id} reset logins for group {group.name} - {students_logged_out} students affected")
        
        return jsonify({
            'success': True, 
            'message': f'Successfully logged out {students_logged_out} students from {group.name}',
            'students_count': students_logged_out
        })
        
    except Exception as e:
        logger.error(f'Error resetting logins for group {group_id} by teacher {current_user.id}: {str(e)}')
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while resetting logins'}), 500


@app.route('/teacher/course/<int:course_id>/login_status', methods=['GET'])
@login_required
def get_course_login_status(course_id):
    """Get login status of students in a course (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} requesting login status for course {course_id}")
        
        course = Course.query.filter_by(id=course_id, teacher_id=current_user.id).first()
        if not course:
            logger.warning(f"Teacher {current_user.id} tried to access unauthorized course {course_id}")
            return jsonify({'error': 'Course not found or access denied'}), 403
        
        # Get active sessions (students logged in in last 30 minutes)
        cutoff_time = datetime.now() - timedelta(minutes=30)
        
        active_students = []
        total_students = 0
        
        for group in course.groups:
            for student in group.students:
                total_students += 1
                if student.current_login and student.current_login > cutoff_time:
                    active_students.append({
                        'id': student.id,
                        'name': student.name,
                        'username': student.username,
                        'group': group.name,
                        'last_login': student.current_login.isoformat() if student.current_login else None
                    })
        
        logger.debug(f"Course {course_id} has {len(active_students)} active students out of {total_students} total")
        
        return jsonify({
            'course_name': course.name,
            'total_students': total_students,
            'active_students': len(active_students),
            'students': active_students
        })
        
    except Exception as e:
        logger.error(f'Error getting login status for course {course_id} by teacher {current_user.id}: {str(e)}')
        return jsonify({'error': 'An error occurred while fetching login status'}), 500


@app.route("/teacher/problem/<int:problem_id>/toggle", methods=["POST"])
@login_required
def teacher_toggle_problem(problem_id):
    """Toggle problem active status (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} attempting to toggle problem {problem_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to toggle problem status")
            return jsonify({"success": False, "message": "Unauthorized"}), 403
        
        problem = Problem.query.get_or_404(problem_id)
        
        # Check if the teacher owns this problem
        if problem.created_by != current_user.id:
            logger.warning(f"Teacher {current_user.id} tried to toggle unauthorized problem {problem_id}")
            return jsonify({"success": False, "message": "Unauthorized"}), 403
        
        # Toggle the active status
        old_status = problem.is_active
        problem.is_active = not problem.is_active
        db.session.commit()
        
        status = "activated" if problem.is_active else "deactivated"
        logger.info(f"Teacher {current_user.id} {status} problem {problem_id} (was {old_status}, now {problem.is_active})")
        
        return jsonify({
            "success": True, 
            "message": f"Problem {status} successfully",
            "is_active": problem.is_active
        })
        
    except Exception as e:
        logger.error(f'Error toggling problem {problem_id} by teacher {current_user.id}: {str(e)}')
        db.session.rollback()
        return jsonify({"success": False, "message": "An error occurred while toggling problem status"}), 500

@app.route("/teacher/problem/<int:problem_id>/delete", methods=["POST"])
@login_required
def teacher_delete_problem(problem_id):
    """Delete a problem (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} attempting to delete problem {problem_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to delete problem")
            return jsonify({"success": False, "message": "Unauthorized"}), 403
        
        problem = Problem.query.get_or_404(problem_id)
        
        # Check if the teacher owns this problem
        if problem.created_by != current_user.id:
            logger.warning(f"Teacher {current_user.id} tried to delete unauthorized problem {problem_id}")
            return jsonify({"success": False, "message": "Unauthorized"}), 403
        
        # Check if there are any submissions
        submission_count = Submission.query.filter_by(problem_id=problem_id).count()
        if submission_count > 0:
            logger.info(f"Delete blocked: Problem {problem_id} has {submission_count} submissions")
            return jsonify({
                "success": False, 
                "message": f"Cannot delete problem. It has {submission_count} submission(s)."
            })
        
        # Delete the problem
        problem_title = problem.title
        db.session.delete(problem)
        db.session.commit()
        
        logger.info(f"Teacher {current_user.id} successfully deleted problem {problem_id} ('{problem_title}')")
        
        return jsonify({
            "success": True, 
            "message": "Problem deleted successfully"
        })
        
    except Exception as e:
        logger.error(f'Error deleting problem {problem_id} by teacher {current_user.id}: {str(e)}')
        db.session.rollback()
        return jsonify({"success": False, "message": "An error occurred while deleting the problem"}), 500


@app.route("/teacher/dashboard")
@login_required
def teacher_dashboard():
    """Teacher dashboard showing courses and problems."""
    try:
        logger.info(f"Teacher {current_user.id} accessing dashboard")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to access teacher dashboard")
            return redirect(url_for("student_dashboard"))
            
        if current_user.must_change_password:
            logger.info(f"Teacher {current_user.id} redirected to change password")
            flash("You must change your password before accessing the dashboard.", "warning")
            return redirect(url_for("change_password"))
        
        # Get teacher's courses and problems (latest first)
        courses = Course.query.filter_by(
            teacher_id=current_user.id, is_active=True
        ).all()
        
        problems = Problem.query.filter_by(
            created_by=current_user.id
        ).order_by(Problem.created_at.desc()).all()
        
        # Get submission counts for each problem
        problem_submission_counts = {}
        for problem in problems:
            count = Submission.query.filter_by(problem_id=problem.id).count()
            problem_submission_counts[problem.id] = count
        
        logger.info(f"Teacher {current_user.id} dashboard loaded: {len(courses)} courses, {len(problems)} problems")
        
        return render_template(
            "teacher_dashboard.html",
            courses=courses,
            problems=problems,
            problem_submission_counts=problem_submission_counts
        )
        
    except Exception as e:
        logger.error(f'Error loading teacher dashboard for user {current_user.id}: {str(e)}')
        flash("An error occurred while loading the dashboard.", "error")
        return redirect(url_for("dashboard"))


@app.route("/teacher/create-problem", methods=["GET","POST"])
@app.route("/teacher/create-problem/<int:course_id>", methods=["GET","POST"])
@login_required
def teacher_create_problem(course_id=None):
    """Create a new problem (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} accessing create problem page (course_id: {course_id})")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to create problem")
            return redirect(url_for("student_dashboard"))
            
        if current_user.must_change_password:
            logger.info(f"Teacher {current_user.id} redirected to change password from create problem")
            flash("You must change your password before creating problems.", "warning")
            return redirect(url_for("change_password"))

        # All active courses for this teacher
        courses = Course.query.filter_by(
            teacher_id=current_user.id, is_active=True
        ).all()

        # If they clicked "Add New Problem" from a specific course page
        selected_course = None
        if course_id:
            selected_course = Course.query.filter_by(
                id=course_id,
                teacher_id=current_user.id,
                is_active=True
            ).first()
            
            if not selected_course:
                logger.warning(f"Teacher {current_user.id} tried to access invalid course {course_id}")
                flash("Invalid course or access denied.", "error")
                return redirect(url_for("teacher_dashboard"))

        # Handle POST request (problem creation logic would go here)
        if request.method == "POST":
            logger.info(f"Teacher {current_user.id} submitting new problem creation")
            # Add your existing POST handling logic here
            pass

        logger.info(f"Teacher {current_user.id} create problem page loaded with {len(courses)} courses")
        
        return render_template(
            "teacher_create_problem.html",
            courses=courses,
            selected_course=selected_course
        )
        
    except Exception as e:
        logger.error(f'Error in create problem for teacher {current_user.id}: {str(e)}')
        flash("An error occurred while loading the create problem page.", "error")
        return redirect(url_for("teacher_dashboard"))



@app.route("/api/teacher/problem/<int:problem_id>/download-solution")
@login_required
def api_download_problem_solution(problem_id):
    """Download problem solution if conditions are met (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} attempting to download solution for problem {problem_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to download solution")
            return jsonify({"error": "Unauthorized"}), 403
        
        # Verify the problem belongs to this teacher
        problem = Problem.query.filter_by(id=problem_id).first_or_404()
        course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first_or_404()
        
        # Check if solution can be downloaded
        if not problem.can_download_solution:
            logger.warning(f"Teacher {current_user.id} tried to download unavailable solution for problem {problem_id}")
            return jsonify({"error": "Solution download not available"}), 403
        
        # Create solution file
        solution_data = {
            "problem_title": problem.title,
            "course_name": course.name,
            "solution": json.loads(problem.solution) if problem.solution else {},
            "generated_at": datetime.now().isoformat(),
            "problem_state": problem.current_state
        }
        
        # Create file in memory
        output = io.StringIO()
        json.dump(solution_data, output, indent=2)
        output.seek(0)
        
        # Convert to bytes
        file_data = io.BytesIO(output.getvalue().encode('utf-8'))
        
        filename = f"solution_{problem.title.replace(' ', '_')}.json"
        
        logger.info(f"Teacher {current_user.id} successfully downloaded solution for problem {problem_id}")
        
        return send_file(
            file_data,
            as_attachment=True,
            download_name=filename,
            mimetype='application/json'
        )
        
    except Exception as e:
        logger.error(f'Error downloading solution for problem {problem_id} by teacher {current_user.id}: {str(e)}')
        return jsonify({"error": "An error occurred while downloading the solution"}), 500


@app.route("/teacher/problem/<int:problem_id>/preview")
@login_required
def teacher_problem_preview(problem_id):
    """Preview a problem (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} previewing problem {problem_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to preview problem")
            return redirect(url_for("student_dashboard"))
        
        # Verify the problem belongs to this teacher
        problem = Problem.query.filter_by(id=problem_id).first_or_404()
        course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first_or_404()
        
        # Check if there are any submissions for this problem
        has_submissions = Submission.query.filter_by(problem_id=problem_id).first() is not None
        
        logger.info(f"Teacher {current_user.id} problem preview loaded: problem {problem_id}, has_submissions: {has_submissions}")
        
        return render_template(
            "teacher_problem_preview.html",
            problem=problem,
            course=course,
            has_submissions=has_submissions
        )
        
    except Exception as e:
        logger.error(f'Error previewing problem {problem_id} for teacher {current_user.id}: {str(e)}')
        flash("An error occurred while loading the problem preview.", "error")
        return redirect(url_for("teacher_dashboard"))


@app.route("/teacher/problem/<int:problem_id>/analytics")
@login_required
def teacher_problem_analytics(problem_id):
    """View analytics for a specific problem based on students' latest attempts (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} accessing analytics for problem {problem_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to access problem analytics")
            return redirect(url_for("student_dashboard"))
        
        # Verify the problem belongs to this teacher
        problem = Problem.query.filter_by(id=problem_id).first_or_404()
        course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first_or_404()
        
        # Get all submissions with student info
        all_submissions = (
            db.session.query(Submission, User)
            .join(User, Submission.student_id == User.id)
            .filter(Submission.problem_id == problem_id)
            .order_by(Submission.created_at.desc())
            .all()
        )
        
        # Group by student and get latest submission for each
        student_latest_submissions = {}
        student_attempt_counts = {}
        
        for submission, user in all_submissions:
            student_id = submission.student_id
            
            # Count attempts per student
            if student_id not in student_attempt_counts:
                student_attempt_counts[student_id] = 0
            student_attempt_counts[student_id] += 1
            
            # Keep only the latest submission per student
            if student_id not in student_latest_submissions:
                submission.student = user
                student_latest_submissions[student_id] = submission
        
        # Convert to list for template
        latest_submissions = list(student_latest_submissions.values())
        
        # Calculate stats based on latest submissions only
        total_attempts = len(all_submissions)
        unique_students = len(latest_submissions)
        
        # Calculate average score based on ALL students who have submitted (including zero scores)
        submissions_with_scores = [s for s in latest_submissions if s.total_score is not None]
        avg_score = sum(s.total_score for s in submissions_with_scores) / len(submissions_with_scores) if submissions_with_scores else 0
        
        # Find highest score among students with valid scores
        scored_submissions = [s for s in latest_submissions if s.total_score is not None and s.total_score > 0]
        highest_score = max((s.total_score for s in scored_submissions), default=0)
        
        # Score distribution based on latest submissions
        score_ranges = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
        students_with_zero_score = 0
        
        for submission in latest_submissions:
            if submission.total_score is None or submission.total_score == 0:
                students_with_zero_score += 1
            else:
                score = submission.total_score
                if score <= 20:
                    score_ranges["0-20"] += 1
                elif score <= 40:
                    score_ranges["21-40"] += 1
                elif score <= 60:
                    score_ranges["41-60"] += 1
                elif score <= 80:
                    score_ranges["61-80"] += 1
                else:
                    score_ranges["81-100"] += 1
        
        # Prepare most attempts data with latest scores
        most_attempts = []
        for student_id, count in student_attempt_counts.items():
            student_submission = student_latest_submissions[student_id]
            most_attempts.append({
                'student': student_submission.student,
                'count': count,
                'latest_score': student_submission.total_score
            })
        
        # Sort by attempt count (descending)
        most_attempts.sort(key=lambda x: x['count'], reverse=True)
        
        logger.info(f"Teacher {current_user.id} analytics loaded for problem {problem_id}: {unique_students} students, {total_attempts} total attempts")
        
        return render_template(
            "teacher_problem_analytics.html",
            problem=problem,
            course=course,
            latest_submissions=latest_submissions,
            total_attempts=total_attempts,
            unique_students=unique_students,
            avg_score=avg_score,
            highest_score=highest_score,
            score_ranges=score_ranges,
            students_with_zero_score=students_with_zero_score,
            most_attempts=most_attempts
        )
        
    except Exception as e:
        logger.error(f'Error loading analytics for problem {problem_id} by teacher {current_user.id}: {str(e)}')
        flash("An error occurred while loading problem analytics.", "error")
        return redirect(url_for("teacher_dashboard"))


@app.route("/teacher/problem/<int:problem_id>/edit")
@login_required
def teacher_edit_problem(problem_id):
    """Edit a problem (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} accessing edit page for problem {problem_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to edit problem")
            flash("Access denied", "error")
            return redirect(url_for("dashboard"))
        
        # Get the problem and verify teacher owns it
        problem = Problem.query.filter_by(id=problem_id).first()
        if not problem:
            logger.warning(f"Teacher {current_user.id} tried to edit non-existent problem {problem_id}")
            flash("Problem not found", "error")
            return redirect(url_for("teacher_dashboard"))
        
        # Check if teacher owns the course this problem belongs to
        course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first()
        if not course:
            logger.warning(f"Teacher {current_user.id} tried to edit unauthorized problem {problem_id}")
            flash("Access denied - you don't own this problem", "error")
            return redirect(url_for("teacher_dashboard"))
        
        # Get all courses for this teacher (for the dropdown)
        courses = Course.query.filter_by(teacher_id=current_user.id).all()
        
        logger.info(f"Teacher {current_user.id} edit page loaded for problem {problem_id}")
        
        return render_template(
            "teacher_edit_problem.html",
            problem=problem,
            courses=courses,
            current_course=course
        )
        
    except Exception as e:
        logger.error(f'Error loading edit page for problem {problem_id} by teacher {current_user.id}: {str(e)}')
        flash("An error occurred while loading the edit page.", "error")
        return redirect(url_for("teacher_dashboard"))


@app.route("/api/update_problem/<int:problem_id>", methods=["POST"])
@login_required
def api_update_problem(problem_id):
    """Update a problem via API (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} attempting to update problem {problem_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to update problem")
            return jsonify({"error": "Only teachers can update problems"}), 403
        
        # Get the problem and verify teacher owns it
        problem = Problem.query.filter_by(id=problem_id).first()
        if not problem:
            logger.warning(f"Teacher {current_user.id} tried to update non-existent problem {problem_id}")
            return jsonify({"error": "Problem not found"}), 404
        
        # Check if teacher owns the course this problem belongs to
        course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first()
        if not course:
            logger.warning(f"Teacher {current_user.id} tried to update unauthorized problem {problem_id}")
            return jsonify({"error": "Access denied"}), 403
        
        form = request.form
        files = request.files
        
        # Verify the new course_id belongs to this teacher
        new_course_id = form.get("course_id")
        new_course = Course.query.filter_by(id=new_course_id, teacher_id=current_user.id).first()
        if not new_course:
            logger.warning(f"Teacher {current_user.id} tried to assign problem to unauthorized course {new_course_id}")
            return jsonify({"error": "Invalid course or access denied"}), 403
        
        # Store old values for logging
        old_title = problem.title
        old_course_id = problem.course_id
        
        # Update problem fields
        problem.title = form["title"]
        problem.statement = form["statement"]
        problem.topics = form["topics_json"]
        problem.rubric = form["rubric_json"]
        problem.pills = form["pills_json"]
        problem.prompt = form["prompt_text"]
        problem.video_url = form.get("video_url", None)
        problem.course_id = new_course_id
        
        # Handle PDF upload
        f = files.get("doc_file")
        if f and allowed_file(f.filename):
            fn = secure_filename(f.filename)
            f.save(os.path.join(app.config["UPLOAD_FOLDER"], fn))
            problem.doc_path = f"uploads/docs/{fn}"
            logger.info(f"New document uploaded for problem {problem_id}: {fn}")
        
        db.session.commit()
        
        logger.info(f"Teacher {current_user.id} successfully updated problem {problem_id}: title '{old_title}' -> '{problem.title}', course {old_course_id} -> {new_course_id}")
        
        return jsonify({"status": "ok"})
        
    except Exception as e:
        logger.error(f'Error updating problem {problem_id} by teacher {current_user.id}: {str(e)}')
        db.session.rollback()
        return jsonify({"error": "An error occurred while updating the problem"}), 500


@app.route("/api/teacher/submission/<int:submission_id>")
@login_required
def api_get_submission(submission_id):
    """Get submission details via API (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} requesting submission details {submission_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to access submission details")
            return jsonify({"status": "error", "error": "Unauthorized"}), 403
        
        # Get submission with student and problem info
        submission = (
            db.session.query(Submission, User, Problem)
            .join(User, Submission.student_id == User.id)
            .join(Problem, Submission.problem_id == Problem.id)
            .filter(Submission.id == submission_id)
            .first()
        )
        
        if not submission:
            logger.warning(f"Teacher {current_user.id} requested non-existent submission {submission_id}")
            return jsonify({"status": "error", "error": "Submission not found"}), 404
        
        submission_obj, student, problem = submission
        
        # Verify the problem belongs to this teacher
        course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first()
        if not course:
            logger.warning(f"Teacher {current_user.id} tried to access unauthorized submission {submission_id}")
            return jsonify({"status": "error", "error": "Unauthorized"}), 403
        
        # Parse scores and feedback if they exist
        scores = json.loads(submission_obj.scores) if submission_obj.scores else {}
        feedback = json.loads(submission_obj.feedback) if submission_obj.feedback else []
        
        logger.info(f"Teacher {current_user.id} successfully retrieved submission {submission_id} details")
        
        return jsonify({
            "status": "ok",
            "submission": {
                "id": submission_obj.id,
                "solution": submission_obj.solution,
                "total_score": submission_obj.total_score,
                "scores": scores,
                "feedback": feedback,
                "attempt": submission_obj.attempt,
                "created_at": submission_obj.created_at.isoformat(),
                "student": {
                    "name": student.name,
                    "htno": student.htno,
                    "username": student.username
                },
                "problem": {
                    "title": problem.title
                }
            }
        })
        
    except Exception as e:
        logger.error(f'Error retrieving submission {submission_id} for teacher {current_user.id}: {str(e)}')
        return jsonify({"status": "error", "error": "An error occurred while retrieving submission details"}), 500
        
@app.route("/api/teacher/submission/<int:submission_id>/download")
@login_required
def api_download_submission(submission_id):
    """Download submission as text file"""
    try:
        logger.info(f"Teacher {current_user.id} attempting to download submission {submission_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to download submission")
            return redirect(url_for("teacher_dashboard"))
        
        # Get submission with student and problem info
        submission = (
            db.session.query(Submission, User, Problem)
            .join(User, Submission.student_id == User.id)
            .join(Problem, Submission.problem_id == Problem.id)
            .filter(Submission.id == submission_id)
            .first()
        )
        
        if not submission:
            logger.warning(f"Submission {submission_id} not found for teacher {current_user.id}")
            flash("Submission not found", "error")
            return redirect(url_for("teacher_dashboard"))
        
        submission_obj, student, problem = submission
        
        # Verify the problem belongs to this teacher
        course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first()
        if not course:
            logger.warning(f"Teacher {current_user.id} tried to access unauthorized submission {submission_id}")
            flash("Unauthorized access", "error")
            return redirect(url_for("teacher_dashboard"))
        
        # Create the file content
        content = f"""Problem: {problem.title}
Student: {student.name} ({student.htno})
Submission Date: {submission_obj.created_at.strftime('%Y-%m-%d %H:%M:%S')}
Attempt: {submission_obj.attempt}
Total Score: {submission_obj.total_score}%

--- SOLUTION ---
{submission_obj.solution}

--- FEEDBACK ---
{submission_obj.feedback or 'No feedback available'}

--- SCORES ---
{submission_obj.scores or 'No detailed scores available'}
"""
        
        # Create response with file download
        response = make_response(content)
        response.headers['Content-Type'] = 'text/plain'
        response.headers['Content-Disposition'] = f'attachment; filename=submission_{submission_id}_{student.htno}.txt'
        
        logger.info(f"Teacher {current_user.id} successfully downloaded submission {submission_id}")
        return response
        
    except Exception as e:
        logger.error(f'Error downloading submission {submission_id} by teacher {current_user.id}: {str(e)}')
        flash(f"Error downloading submission: {str(e)}", "error")
        return redirect(url_for("teacher_dashboard"))


@app.route("/teacher/course/<int:course_id>")
@login_required
def teacher_course_detail(course_id):
    """View detailed course information (teacher only)."""
    try:
        logger.info(f"Teacher {current_user.id} accessing course detail {course_id}")
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to access course detail")
            return redirect(url_for("student_dashboard"))
        if current_user.must_change_password:
            logger.info(f"Teacher {current_user.id} redirected to change password from course detail")
            flash("You must change your password before accessing course details.", "warning")
            return redirect(url_for("change_password"))
        
        # Load course + guard
        course = Course.query.filter_by(
            id=course_id,
            teacher_id=current_user.id
        ).first_or_404()
        
        # All groups & problems for this course
        groups = Group.query.filter_by(course_id=course_id).all()
        problems = Problem.query.filter_by(course_id=course_id).all()
        
        # Per-problem stats
        submission_stats = {}
        for problem in problems:
            stats = (
                db.session.query(
                    Submission.student_id,
                    db.func.max(Submission.total_score).label("best_score"),
                    db.func.count(Submission.id).label("attempts")
                )
                .filter_by(problem_id=problem.id)
                .group_by(Submission.student_id)
                .all()
            )
            submission_stats[problem.id] = {
                "total_students": sum(len(g.students) for g in groups),
                "attempted": len(stats),
                "avg_score": (sum(s.best_score for s in stats) / len(stats)) if stats else 0
            }
        
        # Course-level summary cards
        enrolled_students = sum(len(g.students) for g in groups)
        total_submissions = (
            Submission.query
            .filter(Submission.problem_id.in_([p.id for p in problems]))
            .count()
        )
        
        # Compute average across problems from submission_stats
        if problems:
            average_score = sum(
                submission_stats[p.id]["avg_score"] for p in problems
            ) / len(problems)
        else:
            average_score = 0
        
        logger.info(f"Teacher {current_user.id} course detail loaded: {len(groups)} groups, {len(problems)} problems, {enrolled_students} students")
        
        return render_template(
            "teacher_course_detail.html",
            course=course,
            groups=groups,
            problems=problems,
            submission_stats=submission_stats,
            enrolled_students=enrolled_students,
            total_submissions=total_submissions,
            average_score=average_score
        )
    except Exception as e:
        logger.error(f'Error loading course detail {course_id} for teacher {current_user.id}: {str(e)}')
        flash("An error occurred while loading course details.", "error")
        return redirect(url_for("teacher_dashboard"))

@app.route("/api/teacher/problem/<int:problem_id>/toggle-activity", methods=["POST"])
@login_required
def toggle_problem_activity(problem_id):
    """Toggle problem activity status (start/stop)"""
    try:
        logger.info(f"Teacher {current_user.id} attempting to toggle activity for problem {problem_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to toggle problem activity")
            return jsonify({"status": "error", "error": "Unauthorized"}), 403
        
        if current_user.must_change_password:
            logger.warning(f"Teacher {current_user.id} needs password change before toggling problem activity")
            return jsonify({"status": "error", "error": "Password change required"}), 400
        
        # Get the problem and verify teacher owns the course
        problem = Problem.query.join(Course).filter(
            Problem.id == problem_id,
            Course.teacher_id == current_user.id
        ).first_or_404()
        
        current_time = datetime.now()
        action = ""
        message = ""
        
        if problem.is_active:
            # Stop the activity
            problem.is_active = False
            problem.end_date = current_time  # Set end_date when stopping
            action = "stopped"
            message = f"Activity '{problem.title}' has been stopped. Students can no longer submit solutions."
        else:
            # Start the activity
            problem.is_active = True
            problem.start_date = current_time  # Set start_date when starting
            problem.end_date = None  # Clear end_date if restarting
            action = "started"
            message = f"Activity '{problem.title}' has been started. Students can now access and submit solutions."
        
        db.session.commit()
        
        logger.info(f"Teacher {current_user.id} successfully {action} activity for problem {problem_id} ('{problem.title}')")
        
        return jsonify({
            "status": "ok",
            "action": action,
            "is_active": problem.is_active,
            "start_date": problem.start_date.isoformat() if problem.start_date else None,
            "end_date": problem.end_date.isoformat() if problem.end_date else None,
            "current_state": problem.current_state,
            "message": message
        })
        
    except Exception as e:
        logger.error(f'Error toggling activity for problem {problem_id} by teacher {current_user.id}: {str(e)}')
        db.session.rollback()
        return jsonify({"status": "error", "error": "An error occurred while toggling the activity"}), 500

@app.route("/api/teacher/problem/<int:problem_id>/toggle-download", methods=["POST"])
@login_required
def toggle_solution_download(problem_id):
    """Toggle solution download availability"""
    try:
        logger.info(f"Teacher {current_user.id} attempting to toggle download for problem {problem_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to toggle solution download")
            return jsonify({"status": "error", "error": "Unauthorized"}), 403
        
        if current_user.must_change_password:
            logger.warning(f"Teacher {current_user.id} needs password change before toggling download")
            return jsonify({"status": "error", "error": "Password change required"}), 400
        
        # Get the problem and verify teacher owns the course
        problem = Problem.query.join(Course).filter(
            Problem.id == problem_id,
            Course.teacher_id == current_user.id
        ).first_or_404()
        
        # Toggle download availability - using the correct field name from model
        problem.can_download_solution = not problem.can_download_solution
        
        current_time = datetime.now()
        if problem.can_download_solution:
            action = "enabled"
            message = f"Solution download has been enabled for '{problem.title}'. Students can now download their solutions."
        else:
            action = "disabled"
            message = f"Solution download has been disabled for '{problem.title}'. Students can no longer download solutions."
        
        db.session.commit()
        
        logger.info(f"Teacher {current_user.id} successfully {action} download for problem {problem_id} ('{problem.title}')")
        
        return jsonify({
            "status": "ok",
            "action": action,
            "can_download_solution": problem.can_download_solution,
            "message": message
        })
        
    except Exception as e:
        logger.error(f'Error toggling download for problem {problem_id} by teacher {current_user.id}: {str(e)}')
        db.session.rollback()
        return jsonify({"status": "error", "error": "An error occurred while toggling download availability"}), 500

@app.route("/teacher/problem/<int:problem_id>/submissions")
@login_required
def teacher_problem_submissions(problem_id):
    """View all submissions for a specific problem with enhanced features"""
    try:
        logger.info(f"Teacher {current_user.id} accessing submissions for problem {problem_id}")
        
        if current_user.role != "teacher":
            logger.warning(f"Non-teacher user {current_user.id} tried to access problem submissions")
            return redirect(url_for("student_dashboard"))
        
        if current_user.must_change_password:
            logger.warning(f"Teacher {current_user.id} needs password change before accessing submissions")
            flash("You must change your password before accessing submissions.", "warning")
            return redirect(url_for("change_password"))
        
        # Verify the problem belongs to this teacher
        problem = Problem.query.filter_by(id=problem_id).first_or_404()
        course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first_or_404()
        
        # Get filter parameters
        score_filter = request.args.get('score_filter', 'all')
        sort_by = request.args.get('sort_by', 'latest')
        
        logger.debug(f"Loading submissions with filter: {score_filter}, sort: {sort_by}")
        
        # Get all students enrolled in the course first
        enrolled_students = []
        groups = Group.query.filter_by(course_id=course.id).all()
        for group in groups:
            enrolled_students.extend(group.students)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_enrolled = []
        for student in enrolled_students:
            if student.id not in seen:
                seen.add(student.id)
                unique_enrolled.append(student)
        enrolled_students = unique_enrolled
        
        # Get currently logged in students (online in last 60 minutes)
        cutoff_time = datetime.now() - timedelta(minutes=60)
        logged_in_students_query = User.query.filter(
            User.id.in_([student.id for student in enrolled_students]),
            User.is_online == True,
            User.last_activity >= cutoff_time
        ).all()
        
        # Get latest submissions for logged-in users
        latest_submissions_subquery = (
            db.session.query(
                Submission.student_id,
                func.max(Submission.id).label('latest_id')
            )
            .filter(Submission.problem_id == problem_id)
            .group_by(Submission.student_id)
            .subquery()
        )
        
        # Get submissions for logged-in users
        logged_in_submissions = {}
        submissions_with_users = (
            db.session.query(Submission, User)
            .join(User, Submission.student_id == User.id)
            .join(
                latest_submissions_subquery,
                and_(
                    Submission.student_id == latest_submissions_subquery.c.student_id,
                    Submission.id == latest_submissions_subquery.c.latest_id
                )
            )
            .filter(Submission.problem_id == problem_id)
            .filter(User.id.in_([user.id for user in logged_in_students_query]))
            .all()
        )
        
        # Create a mapping of user_id to submission for logged-in users
        for submission, user in submissions_with_users:
            logged_in_submissions[user.id] = (submission, user)
        
        # Create logged-in users list with their submission status
        logged_in_users_data = []
        for user in logged_in_students_query:
            if user.id in logged_in_submissions:
                # User has submitted
                submission, _ = logged_in_submissions[user.id]
                logged_in_users_data.append((submission, user))
            else:
                # User hasn't submitted - create a placeholder submission object
                class PlaceholderSubmission:
                    def __init__(self):
                        self.id = None
                        self.total_score = 0
                        self.attempt = 0
                        self.created_at = None
                
                placeholder_submission = PlaceholderSubmission()
                logged_in_users_data.append((placeholder_submission, user))
        
        # Apply filters to logged-in users data
        filtered_logged_in_data = []
        for submission, user in logged_in_users_data:
            # Apply score filter
            if score_filter == 'passed' and (submission.total_score is None or submission.total_score < 60):
                continue
            elif score_filter == 'failed' and (submission.total_score is None or submission.total_score >= 60):
                continue
            elif score_filter == 'excellent' and (submission.total_score is None or submission.total_score < 80):
                continue
            
            filtered_logged_in_data.append((submission, user))
        
        # Apply sorting to filtered data
        if sort_by == 'latest':
            filtered_logged_in_data.sort(key=lambda x: x[1].last_activity or datetime.min, reverse=True)
        elif sort_by == 'score_high':
            filtered_logged_in_data.sort(key=lambda x: x[0].total_score or 0, reverse=True)
        elif sort_by == 'score_low':
            filtered_logged_in_data.sort(key=lambda x: x[0].total_score or 0)
        elif sort_by == 'name':
            filtered_logged_in_data.sort(key=lambda x: x[1].name or x[1].username)
        
        # Get all submissions for statistics (not just logged-in users)
        all_latest_submissions_subquery = (
            db.session.query(
                Submission.student_id,
                func.max(Submission.id).label('latest_id')
            )
            .filter(Submission.problem_id == problem_id)
            .group_by(Submission.student_id)
            .subquery()
        )
        
        all_submissions_query = (
            db.session.query(Submission, User)
            .join(User, Submission.student_id == User.id)
            .join(
                all_latest_submissions_subquery,
                and_(
                    Submission.student_id == all_latest_submissions_subquery.c.student_id,
                    Submission.id == all_latest_submissions_subquery.c.latest_id
                )
            )
            .filter(Submission.problem_id == problem_id)
            .all()
        )
        
        # Get submission statistics
        total_submissions = Submission.query.filter_by(problem_id=problem_id).count()
        unique_students = len(set(sub.student_id for sub, user in all_submissions_query))
        
        # Calculate average score from all latest submissions
        avg_score = 0
        if all_submissions_query:
            total_score = sum(sub.total_score for sub, user in all_submissions_query if sub.total_score is not None)
            avg_score = total_score / len(all_submissions_query) if all_submissions_query else 0
        
        # Get best submissions per student (only with score > 0)
        best_submissions_subquery = (
            db.session.query(
                Submission.student_id,
                func.max(Submission.total_score).label('best_score')
            )
            .filter(Submission.problem_id == problem_id)
            .filter(Submission.total_score > 0)
            .group_by(Submission.student_id)
            .subquery()
        )
        
        best_submissions_with_latest = (
            db.session.query(
                Submission.student_id,
                best_submissions_subquery.c.best_score,
                func.max(Submission.id).label('latest_best_id')
            )
            .join(
                best_submissions_subquery,
                and_(
                    Submission.student_id == best_submissions_subquery.c.student_id,
                    Submission.total_score == best_submissions_subquery.c.best_score
                )
            )
            .filter(Submission.problem_id == problem_id)
            .group_by(Submission.student_id, best_submissions_subquery.c.best_score)
            .subquery()
        )
        
        best_submissions_query = (
            db.session.query(Submission, User)
            .join(User, Submission.student_id == User.id)
            .join(
                best_submissions_with_latest,
                Submission.id == best_submissions_with_latest.c.latest_best_id
            )
            .all()
        )
        
        # Find students who haven't submitted
        submitted_student_ids = set(sub.student_id for sub, user in all_submissions_query)
        not_submitted_students = [student for student in enrolled_students if student.id not in submitted_student_ids]
        
        logger.info(f"Teacher {current_user.id} successfully loaded {len(filtered_logged_in_data)} logged-in users for problem {problem_id}")
        
        return render_template(
            "teacher_problem_submissions.html",
            problem=problem,
            course=course,
            submissions=filtered_logged_in_data,  # Pass logged-in users data
            best_submissions=best_submissions_query,
            total_submissions=total_submissions,
            unique_students=unique_students,
            avg_score=avg_score,
            not_submitted_students=not_submitted_students,
            enrolled_count=len(enrolled_students),
            logged_in_count=len(logged_in_students_query),
            current_filter=score_filter,
            current_sort=sort_by,
            can_download_solution=problem.can_download_solution,
            show_logged_in_users=True  # Flag to indicate we're showing logged-in users
        )
        
    except Exception as e:
        logger.error(f'Error loading submissions for problem {problem_id} by teacher {current_user.id}: {str(e)}')
        flash("An error occurred while loading submissions", "error")
        return redirect(url_for("teacher_dashboard"))


@app.template_filter('fromjson')
def fromjson_filter(json_str):
    """Parse JSON string to Python object"""
    try:
        if json_str is None or json_str == '':
            return []
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        logger.warning(f"Failed to parse JSON string: {json_str}")
        return []
@app.route('/debug/routes')
def list_routes():
    import urllib
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        line = urllib.parse.unquote(f"{rule.endpoint}: {rule.rule} ({methods})")
        output.append(line)
    return '<pre>' + '\n'.join(sorted(output)) + '</pre>'

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

# ─── Admin Views ─────────────────────────────────────────────────────────────
@app.route("/admin/create-teacher", methods=["GET", "POST"])
@login_required
def admin_create_teacher():
    if current_user.role != "admin":
        return redirect(url_for("student_dashboard"))
    
    if request.method == "POST":
        username = request.form.get("username")
        temp_password = request.form.get("temp_password")
        name = request.form.get("name")
        
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return render_template("admin_create_teacher.html")
        
        new_teacher = User(
            username=username,
            password=generate_password_hash(temp_password),
            role="teacher",
            name=name,
            must_change_password=True
        )
        
        db.session.add(new_teacher)
        db.session.commit()
        
        flash(f"Teacher '{username}' created successfully.", "success")
        return redirect(url_for("admin_dashboard"))
    
    return render_template("admin_create_teacher.html")

@app.route("/api/download_problem_pdf/<int:problem_id>")
@login_required
def download_problem_pdf(problem_id):
    """Generate and download problem PDF with enhanced HTML styling"""
    problem = Problem.query.get_or_404(problem_id)
    
    # Check access
    if current_user.role == "teacher":
        course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first()
        if not course:
            return jsonify({"error": "Access denied"}), 403
    
    try:
        # Create PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1*inch)
        
        # Enhanced Styles
        styles = getSampleStyleSheet()
        
        # Custom styles for better HTML rendering
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#2C3E50'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=10,
            textColor=HexColor('#34495E'),
            leftIndent=0,
            fontName='Helvetica-Bold'
        )
        
        content_style = ParagraphStyle(
            'CustomContent',
            parent=styles['Normal'],
            fontSize=11,
            spaceAfter=12,
            textColor=HexColor('#2C3E50'),
            alignment=TA_JUSTIFY,
            leftIndent=20,
            lineHeight=1.4
        )
        
        # Enhanced styles for HTML content
        html_content_style = ParagraphStyle(
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
        )
        
        code_style = ParagraphStyle(
            'CodeStyle',
            parent=styles['Normal'],
            fontSize=10,
            fontName='Courier',
            textColor=HexColor('#1B4F72'),
            backColor=HexColor('#F8F9FA'),
            leftIndent=30,
            rightIndent=15,
            spaceAfter=8,
            spaceBefore=4,
            borderColor=HexColor('#D5D8DC'),
            borderWidth=1,
            borderPadding=8
        )
        
        pill_title_style = ParagraphStyle(
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
        )
        
        pill_content_style = ParagraphStyle(
            'PillContent',
            parent=styles['Normal'],
            fontSize=11,
            textColor=HexColor('#2C3E50'),
            leftIndent=25,
            rightIndent=15,
            spaceAfter=10,
            lineHeight=1.4,
            alignment=TA_JUSTIFY
        )
        
        bullet_style = ParagraphStyle(
            'BulletStyle',
            parent=styles['Normal'],
            fontSize=11,
            leftIndent=40,
            bulletIndent=20,
            spaceAfter=6
        )
        
        def clean_html_for_pdf(html_content):
            """Enhanced HTML cleaning with better formatting"""
            if not html_content:
                return ""
            
            # Replace common HTML tags with ReportLab equivalents
            content = html_content
            
            # Handle paragraphs
            content = re.sub(r'<p[^>]*>', '', content)
            content = content.replace('</p>', '<br/><br/>')
            
            # Handle headings
            content = re.sub(r'<h[1-6][^>]*>', '<b><font size="13" color="#2C3E50">', content)
            content = re.sub(r'</h[1-6]>', '</font></b><br/><br/>', content)
            
            # Handle bold and italic
            content = content.replace('<strong>', '<b>').replace('</strong>', '</b>')
            content = content.replace('<em>', '<i>').replace('</em>', '</i>')
            content = content.replace('<b>', '<b><font color="#1B4F72">').replace('</b>', '</font></b>')
            content = content.replace('<i>', '<i><font color="#7D3C98">').replace('</i>', '</font></i>')
            
            # Handle code blocks and inline code
            content = re.sub(r'<pre[^>]*>', '<font name="Courier" size="9" color="#1B4F72" backColor="#F8F9FA">', content)
            content = content.replace('</pre>', '</font><br/>')
            content = re.sub(r'<code[^>]*>', '<font name="Courier" size="10" color="#C0392B" backColor="#FADBD8">', content)
            content = content.replace('</code>', '</font>')
            
            # Handle lists
            content = re.sub(r'<ul[^>]*>', '', content)
            content = content.replace('</ul>', '<br/>')
            content = re.sub(r'<ol[^>]*>', '', content)
            content = content.replace('</ol>', '<br/>')
            content = re.sub(r'<li[^>]*>', '• ', content)
            content = content.replace('</li>', '<br/>')
            
            # Handle line breaks
            content = content.replace('<br>', '<br/>').replace('<br/>', '<br/>')
            
            # Handle blockquotes
            content = re.sub(r'<blockquote[^>]*>', '<i><font color="#5D6D7E" size="10">"', content)
            content = content.replace('</blockquote>', '"</font></i><br/>')
            
            # Clean up multiple line breaks
            content = re.sub(r'(<br/>){3,}', '<br/><br/>', content)
            
            return content.strip()
        
        # Content
        story = []
        
        # Title
        story.append(Paragraph(problem.title, title_style))
        story.append(Spacer(1, 20))
        
        # Course info
        course = Course.query.get(problem.course_id)
        story.append(Paragraph(f"<b>Course:</b> {course.code} - {course.name}", content_style))
        story.append(Paragraph(f"<b>Created:</b> {problem.created_at.strftime('%B %d, %Y')}", content_style))
        story.append(Spacer(1, 20))
        
        # Problem Statement
        story.append(Paragraph("Problem Statement", heading_style))
        clean_statement = clean_html_for_pdf(problem.statement)
        story.append(Paragraph(clean_statement, html_content_style))
        story.append(Spacer(1, 20))
        
        # Knowledge Topics
        story.append(Paragraph("Knowledge Topics", heading_style))
        topics = json.loads(problem.topics)
        for topic in topics:
            story.append(Paragraph(f"• {topic}", bullet_style))
        story.append(Spacer(1, 20))
        
        # Scoring Rubric
        story.append(Paragraph("Scoring Rubric", heading_style))
        rubric = json.loads(problem.rubric)
        
        # Create table for rubric
        rubric_data = [['Assessment Aspect', 'Marks']]
        for aspect, marks in rubric.items():
            rubric_data.append([aspect, f"{marks} marks"])
        
        rubric_table = Table(rubric_data, colWidths=[4*inch, 1.5*inch])
        rubric_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#3498DB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, HexColor('#F8F9FA')])
        ]))
        
        story.append(rubric_table)
        story.append(Spacer(1, 20))
        
        # Knowledge Pills with enhanced styling
        if problem.pills:
            pills = json.loads(problem.pills)
            if pills:
                story.append(Paragraph("Knowledge Pills", heading_style))
                story.append(Spacer(1, 10))
                
                for i, pill in enumerate(pills, 1):
                    # Pill title with enhanced styling
                    pill_title = f"💡 {i}. {pill.get('topic', 'Knowledge Pill')}"
                    story.append(Paragraph(pill_title, pill_title_style))
                    
                    # Pill content with HTML styling
                    pill_content = clean_html_for_pdf(pill.get('content', ''))
                    if pill_content:
                        story.append(Paragraph(pill_content, pill_content_style))
                    story.append(Spacer(1, 15))
                
                story.append(Spacer(1, 20))
        
        # Resources
        resources_added = False
        if problem.doc_path or problem.video_url:
            story.append(Paragraph("Additional Resources", heading_style))
            resources_added = True
            
        if problem.doc_path:
            story.append(Paragraph(f"📄 Supporting Document: {os.path.basename(problem.doc_path)}", bullet_style))
            
        if problem.video_url:
            story.append(Paragraph(f"🎥 Video Tutorial: {problem.video_url}", bullet_style))
            
        if resources_added:
            story.append(Spacer(1, 20))
        
        # Footer
        story.append(Spacer(1, 40))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.grey,
            alignment=TA_CENTER
        )
        story.append(Paragraph(f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", footer_style))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        filename = f"{problem.title.replace(' ', '_')}_Problem.pdf"
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({"error": f"Failed to generate PDF: {str(e)}"}), 500

@app.route("/api/download_solution_pdf/<int:problem_id>")
@login_required
def download_solution_pdf(problem_id):
    """Generate and download solution PDF with enhanced HTML styling and proper access control"""
    try:
        problem = Problem.query.get_or_404(problem_id)
        
        # Check access based on role
        if current_user.role == "teacher":
            # Teachers can access solutions for problems in their courses
            course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first()
            if not course:
                logger.warning(f"Teacher {current_user.id} tried to access solution for problem {problem_id} - not their course")
                return jsonify({"error": "Access denied - not your course"}), 403
        elif current_user.role == "student":
            # Students can only access solutions if explicitly allowed by the problem's can_download_solution field
            if not problem.can_download_solution:
                logger.warning(f"Student {current_user.id} tried to access solution for problem {problem_id} - download not allowed")
                return jsonify({"error": "Solution download is not allowed for this problem"}), 403
            
            # Additional check: Verify student is enrolled in the course containing this problem
            student_groups = StudentGroup.query.filter_by(student_id=current_user.id).all()
            enrolled_course_ids = [sg.group.course_id for sg in student_groups]
            
            if problem.course_id not in enrolled_course_ids:
                logger.warning(f"Student {current_user.id} tried to access solution for problem {problem_id} - not enrolled in course")
                return jsonify({"error": "Access denied - you are not enrolled in this course"}), 403
            
            # Optional: Check if student has submitted this problem (uncomment if required)
            # submission = Submission.query.filter_by(
            #     student_id=current_user.id, 
            #     problem_id=problem_id
            # ).first()
            # if not submission:
            #     logger.warning(f"Student {current_user.id} tried to access solution for problem {problem_id} - no submission found")
            #     return jsonify({"error": "You must submit this problem before accessing the solution"}), 403
        else:
            logger.warning(f"User {current_user.id} with role {current_user.role} tried to access solution for problem {problem_id}")
            return jsonify({"error": "Access denied"}), 403
        
        # Check if solution exists
        if not problem.solution:
            logger.info(f"No solution available for problem {problem_id}")
            return jsonify({"error": "No solution available for this problem"}), 404
        
        # Parse solution data
        try:
            solution_data = json.loads(problem.solution)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}")
            return jsonify({"error": "Invalid solution data format"}), 500
        
        
        # Create PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1*inch)
        
        # Enhanced Styles
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'SolutionTitle',
            parent=styles['Heading1'],
            fontSize=22,
            spaceAfter=30,
            textColor=HexColor('#27AE60'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        section_style = ParagraphStyle(
            'SectionTitle',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=15,
            spaceBefore=20,
            textColor=HexColor('#2C3E50'),
            leftIndent=0,
            fontName='Helvetica-Bold'
        )
        
        problem_section_style = ParagraphStyle(
            'ProblemSectionTitle',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=HexColor('#34495E'),
            leftIndent=0,
            fontName='Helvetica-Bold'
        )
        
        content_style = ParagraphStyle(
            'SolutionContent',
            parent=styles['Normal'],
            fontSize=11,
            spaceAfter=12,
            textColor=HexColor('#2C3E50'),
            alignment=TA_JUSTIFY,
            leftIndent=20,
            lineHeight=1.4
        )
        
        # Enhanced solution content style
        solution_content_style = ParagraphStyle(
            'EnhancedSolutionContent',
            parent=styles['Normal'],
            fontSize=11,
            spaceAfter=10,
            spaceBefore=5,
            textColor=HexColor('#2C3E50'),
            alignment=TA_JUSTIFY,
            leftIndent=25,
            rightIndent=15,
            lineHeight=1.5
        )
        
        pill_title_style = ParagraphStyle(
            'PillTitle',
            parent=styles['Heading3'],
            fontSize=14,
            fontName='Helvetica-Bold',
            textColor=HexColor('#8E44AD'),
            spaceAfter=8,
            spaceBefore=15,
            leftIndent=20
        )
        
        pill_content_style = ParagraphStyle(
            'PillContent',
            parent=styles['Normal'],
            fontSize=11,
            textColor=HexColor('#2C3E50'),
            leftIndent=25,
            rightIndent=15,
            spaceAfter=10,
            lineHeight=1.4,
            alignment=TA_JUSTIFY
        )
        
        bullet_style = ParagraphStyle(
            'BulletStyle',
            parent=styles['Normal'],
            fontSize=11,
            leftIndent=40,
            bulletIndent=20,
            spaceAfter=6
        )
        
        def clean_html_for_pdf(html_content):
            """Enhanced HTML cleaning with better formatting"""
            if not html_content:
                return ""
            
            try:
                # Replace common HTML tags with ReportLab equivalents
                content = str(html_content)
                
                # Handle paragraphs
                content = re.sub(r'<p[^>]*>', '', content)
                content = content.replace('</p>', '<br/><br/>')
                
                # Handle headings
                content = re.sub(r'<h[1-6][^>]*>', '<b><font size="13" color="#2C3E50">', content)
                content = re.sub(r'</h[1-6]>', '</font></b><br/><br/>', content)
                
                # Handle bold and italic with colors
                content = content.replace('<strong>', '<b>').replace('</strong>', '</b>')
                content = content.replace('<em>', '<i>').replace('</em>', '</i>')
                content = content.replace('<b>', '<b>').replace('</b>', '</b>')
                content = content.replace('<i>', '<i>').replace('</i>', '</i>')
                
                # Handle code blocks and inline code
                content = re.sub(r'<pre[^>]*>', '<br/><font name="Courier" size="9">', content)
                content = content.replace('</pre>', '</font><br/><br/>')
                content = re.sub(r'<code[^>]*>', '<font name="Courier" size="10">', content)
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
                content = re.sub(r'<blockquote[^>]*>', '<br/><i>"', content)
                content = content.replace('</blockquote>', '"</i><br/><br/>')
                
                # Handle links (show URL)
                content = re.sub(r'<a[^>]*href="([^"]*)"[^>]*>([^<]*)</a>', r'<u>\2</u> (\1)', content)
                
                # Clean up multiple line breaks
                content = re.sub(r'(<br/>){3,}', '<br/><br/>', content)
                
                # Remove any remaining HTML tags
                content = re.sub(r'<[^>]+>', '', content)
                
                return content.strip()
            except Exception as e:
                logger.error(f"Error cleaning HTML: {str(e)}")
                return str(html_content)  # Return original if cleaning fails
        
        # Content
        story = []
        
        # Title
        story.append(Paragraph(f"{problem.title} - Solution", title_style))
        story.append(Spacer(1, 20))
        
        # Course info
        try:
            course = Course.query.get(problem.course_id)
            if course:
                story.append(Paragraph(f"<b>Course:</b> {course.code} - {course.name}", content_style))
            story.append(Paragraph(f"<b>Created:</b> {problem.created_at.strftime('%B %d, %Y')}", content_style))
            
            # Handle rubric safely
            try:
                rubric = json.loads(problem.rubric) if problem.rubric else {}
                total_marks = sum(rubric.values()) if rubric else 0
                story.append(Paragraph(f"<b>Total Marks:</b> {total_marks}", content_style))
            except (json.JSONDecodeError, AttributeError):
                story.append(Paragraph("<b>Total Marks:</b> Not specified", content_style))
            
            story.append(Spacer(1, 30))
        except Exception as e:
            logger.error(f"Error adding course info: {str(e)}")
        
        # Problem Statement Section
        story.append(Paragraph("Problem Statement", problem_section_style))
        clean_statement = clean_html_for_pdf(problem.statement)
        story.append(Paragraph(clean_statement, content_style))
        story.append(Spacer(1, 20))
        
        # Knowledge Topics
        try:
            if problem.topics:
                story.append(Paragraph("Knowledge Topics", problem_section_style))
                topics = json.loads(problem.topics)
                for topic in topics:
                    story.append(Paragraph(f"• {topic}", bullet_style))
                story.append(Spacer(1, 20))
        except (json.JSONDecodeError, AttributeError) as e:
            logger.error(f"Error processing topics: {str(e)}")
        
        # Scoring Rubric
        try:
            if problem.rubric:
                story.append(Paragraph("Scoring Rubric", problem_section_style))
                rubric = json.loads(problem.rubric)
                
                # Create table for rubric
                rubric_data = [['Assessment Aspect', 'Marks']]
                for aspect, marks in rubric.items():
                    rubric_data.append([str(aspect), f"{marks} marks"])
                
                rubric_table = Table(rubric_data, colWidths=[4*inch, 1.5*inch])
                rubric_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#3498DB')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTSIZE', (0, 1), (-1, -1), 10),
                ]))
                
                story.append(rubric_table)
                story.append(Spacer(1, 30))
        except (json.JSONDecodeError, AttributeError) as e:
            logger.error(f"Error processing rubric: {str(e)}")
        
        # Add Knowledge Pills if available
        try:
            if problem.pills:
                pills = json.loads(problem.pills)
                if pills:
                    story.append(Paragraph("Knowledge Pills", problem_section_style))
                    story.append(Spacer(1, 10))
                    
                    for i, pill in enumerate(pills, 1):
                        pill_title = f"{i}. {pill.get('topic', 'Knowledge Pill')}"
                        story.append(Paragraph(pill_title, pill_title_style))
                        
                        pill_content = clean_html_for_pdf(pill.get('content', ''))
                        if pill_content:
                            story.append(Paragraph(pill_content, pill_content_style))
                        story.append(Spacer(1, 15))
                    
                    story.append(Spacer(1, 20))
        except (json.JSONDecodeError, AttributeError) as e:
            logger.error(f"Error processing pills: {str(e)}")
        
        # Add a page break before solution
        story.append(PageBreak())
        
        # Solution Header
        solution_header_style = ParagraphStyle(
            'SolutionHeader',
            parent=styles['Heading1'],
            fontSize=20,
            spaceAfter=25,
            textColor=HexColor('#27AE60'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        story.append(Paragraph("DETAILED SOLUTION", solution_header_style))
        story.append(Spacer(1, 20))
        
        # Solution sections with enhanced styling
        sections = solution_data.get('sections', [])
        for i, section in enumerate(sections):
            try:
                # Section header with marks and styling
                marks = section.get('marks', 0)
                marks_badge = f"[{marks} marks]" if marks else ""
                aspect = section.get('aspect', 'Section')
                section_title = f"{i+1}. {aspect} {marks_badge}"
                story.append(Paragraph(section_title, section_style))
                
                # Section content with enhanced HTML processing
                content = section.get('content', '')
                cleaned_content = clean_html_for_pdf(content)
                
                if cleaned_content:
                    story.append(Paragraph(cleaned_content, solution_content_style))
                story.append(Spacer(1, 20))
                
                # Add page break between major sections (except last)
                if i < len(sections) - 1 and i % 2 == 1:
                    story.append(PageBreak())
            except Exception as e:
                logger.error(f"Error processing section {i}: {str(e)}")
                continue
        
        # Footer
        story.append(Spacer(1, 40))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.grey,
            alignment=TA_CENTER
        )
        story.append(Paragraph(f"Solution generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", footer_style))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        # Create safe filename
        safe_title = re.sub(r'[^\w\s-]', '', problem.title)
        safe_title = re.sub(r'[-\s]+', '_', safe_title)
        filename = f"{safe_title}_Solution.pdf"
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"Error in download_solution_pdf: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Failed to generate solution PDF: {str(e)}"}), 500


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
@app.route("/admin/edit-group/<int:group_id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_edit_group(group_id):
    """Edit group and manage students."""
    try:
        logger.info(f"Admin {current_user.id} accessing edit group {group_id}")
        
        # Get group with related data
        group = Group.query.get_or_404(group_id)
        
        if request.method == "POST":
            # Update group name
            name = request.form.get("name", "").strip()
            
            if not name:
                flash("Group name is required.", "danger")
                return redirect(url_for("admin_edit_group", group_id=group_id))
            
            # Check if name already exists for this course (excluding current group)
            existing = Group.query.filter_by(
                name=name, 
                course_id=group.course_id
            ).filter(Group.id != group_id).first()
            
            if existing:
                flash("A group with this name already exists in this course.", "danger")
                return redirect(url_for("admin_edit_group", group_id=group_id))
            
            # Update group name
            group.name = name
            db.session.commit()
            
            logger.info(f"Group {group_id} name updated to '{name}' by admin {current_user.id}")
            flash(f"Group name updated to '{name}' successfully.", "success")
            return redirect(url_for("admin_edit_group", group_id=group_id))
        
        # GET request - get available students (not in this group)
        current_student_ids = [sg.student_id for sg in group.student_groups]
        available_students = User.query.filter(
            User.role == 'student',
            User.status == 'active',
            ~User.id.in_(current_student_ids) if current_student_ids else True
        ).order_by(User.name, User.username).all()
        
        return render_template(
            "admin_edit_group.html", 
            group=group,
            available_students=available_students
        )
        
    except Exception as e:
        logger.error(f"Edit group error: {str(e)}")
        db.session.rollback()
        flash("Error loading group details.", "error")
        return redirect(url_for("admin_dashboard"))


@app.route("/admin/group/<int:group_id>/add-student", methods=["POST"])
@login_required
@role_required("admin")
def admin_add_student_to_group(group_id):
    """Add student to group via AJAX."""
    try:
        logger.info(f"Admin {current_user.id} adding student to group {group_id}")
        
        # Get JSON data
        data = request.get_json()
        if not data or not data.get('student_id'):
            return jsonify({'success': False, 'message': 'Student ID is required'})
        
        student_id = data.get('student_id')
        
        # Validate group exists
        group = Group.query.get_or_404(group_id)
        
        # Validate student exists and is active
        student = User.query.filter_by(
            id=student_id, 
            role='student', 
            status='active'
        ).first()
        
        if not student:
            return jsonify({'success': False, 'message': 'Invalid student selected'})
        
        # Check if student is already in this group
        existing = StudentGroup.query.filter_by(
            student_id=student_id,
            group_id=group_id
        ).first()
        
        if existing:
            return jsonify({'success': False, 'message': 'Student is already in this group'})
        
        # Add student to group
        new_enrollment = StudentGroup(
            student_id=student_id,
            group_id=group_id
        )
        db.session.add(new_enrollment)
        db.session.commit()
        
        logger.info(f"Student {student_id} added to group {group_id} by admin {current_user.id}")
        
        return jsonify({
            'success': True,
            'message': 'Student added successfully',
            'student': {
                'id': student.id,
                'name': student.name,
                'username': student.username,
                'htno': student.htno
            },
            'enrolled_date': new_enrollment.enrolled_at.strftime('%d-%m-%Y')
        })
        
    except Exception as e:
        logger.error(f"Add student to group error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error adding student to group'})


@app.route("/admin/group/<int:group_id>/remove-student", methods=["POST"])
@login_required
@role_required("admin")
def admin_remove_student_from_group(group_id):
    """Remove student from group via AJAX."""
    try:
        logger.info(f"Admin {current_user.id} removing student from group {group_id}")
        
        # Get JSON data
        data = request.get_json()
        if not data or not data.get('student_id'):
            return jsonify({'success': False, 'message': 'Student ID is required'})
        
        student_id = data.get('student_id')
        
        # Validate group exists
        group = Group.query.get_or_404(group_id)
        
        # Find and remove student enrollment
        enrollment = StudentGroup.query.filter_by(
            student_id=student_id,
            group_id=group_id
        ).first()
        
        if not enrollment:
            return jsonify({'success': False, 'message': 'Student is not in this group'})
        
        # Get student details before removing
        student = enrollment.student
        
        # Remove enrollment
        db.session.delete(enrollment)
        db.session.commit()
        
        logger.info(f"Student {student_id} removed from group {group_id} by admin {current_user.id}")
        
        return jsonify({
            'success': True,
            'message': 'Student removed successfully',
            'student': {
                'id': student.id,
                'name': student.name,
                'username': student.username,
                'htno': student.htno
            }
        })
        
    except Exception as e:
        logger.error(f"Remove student from group error: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error removing student from group'})


@app.route("/admin/delete-group/<int:group_id>", methods=["POST"])
@login_required
@role_required("admin")
def admin_delete_group(group_id):
    """Delete group and all student enrollments."""
    try:
        logger.info(f"Admin {current_user.id} deleting group {group_id}")
        
        # Get group
        group = Group.query.get_or_404(group_id)
        group_name = group.name
        
        # Delete group (cascade will handle student_groups)
        db.session.delete(group)
        db.session.commit()
        
        logger.info(f"Group '{group_name}' (ID: {group_id}) deleted by admin {current_user.id}")
        flash(f"Group '{group_name}' deleted successfully.", "success")
        
        return redirect(url_for("admin_dashboard"))
        
    except Exception as e:
        logger.error(f"Delete group error: {str(e)}")
        db.session.rollback()
        flash("Error deleting group.", "error")
        return redirect(url_for("admin_dashboard"))


# Optional: Bulk import students to group
@app.route("/admin/group/<int:group_id>/bulk-import", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_bulk_import_students(group_id):
    """Bulk import students to group via CSV."""
    try:
        logger.info(f"Admin {current_user.id} accessing bulk import for group {group_id}")
        
        group = Group.query.get_or_404(group_id)
        
        if request.method == "POST":
            # Handle CSV file upload
            if 'csv_file' not in request.files:
                flash('No file selected', 'danger')
                return redirect(url_for('admin_bulk_import_students', group_id=group_id))
            
            file = request.files['csv_file']
            if file.filename == '':
                flash('No file selected', 'danger')
                return redirect(url_for('admin_bulk_import_students', group_id=group_id))
            
            if not file.filename.endswith('.csv'):
                flash('Please upload a CSV file', 'danger')
                return redirect(url_for('admin_bulk_import_students', group_id=group_id))
            
            try:
                # Read CSV content
                stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
                csv_input = csv.reader(stream)
                
                # Skip header row
                next(csv_input, None)
                
                added_count = 0
                error_count = 0
                errors = []
                
                for row_num, row in enumerate(csv_input, start=2):
                    if not row or len(row) < 1:
                        continue
                    
                    username_or_htno = row[0].strip()
                    if not username_or_htno:
                        continue
                    
                    # Find student by username or htno
                    student = User.query.filter(
                        User.role == 'student',
                        User.status == 'active',
                        (User.username == username_or_htno) | (User.htno == username_or_htno)
                    ).first()
                    
                    if not student:
                        errors.append(f"Row {row_num}: Student '{username_or_htno}' not found")
                        error_count += 1
                        continue
                    
                    # Check if already in group
                    existing = StudentGroup.query.filter_by(
                        student_id=student.id,
                        group_id=group_id
                    ).first()
                    
                    if existing:
                        errors.append(f"Row {row_num}: Student '{username_or_htno}' already in group")
                        error_count += 1
                        continue
                    
                    # Add to group
                    new_enrollment = StudentGroup(
                        student_id=student.id,
                        group_id=group_id
                    )
                    db.session.add(new_enrollment)
                    added_count += 1
                
                db.session.commit()
                
                # Show results
                if added_count > 0:
                    flash(f'Successfully added {added_count} students to the group.', 'success')
                
                if error_count > 0:
                    error_msg = f'{error_count} errors occurred:\n' + '\n'.join(errors[:10])
                    if len(errors) > 10:
                        error_msg += f'\n... and {len(errors) - 10} more errors'
                    flash(error_msg, 'warning')
                
                logger.info(f"Bulk import completed: {added_count} added, {error_count} errors")
                return redirect(url_for('admin_edit_group', group_id=group_id))
                
            except Exception as e:
                logger.error(f"CSV processing error: {str(e)}")
                flash('Error processing CSV file', 'danger')
                return redirect(url_for('admin_bulk_import_students', group_id=group_id))
        
        # GET request - show import form
        return render_template('admin_bulk_import_students.html', group=group)
        
    except Exception as e:
        logger.error(f"Bulk import error: {str(e)}")
        db.session.rollback()
        flash("Error accessing bulk import.", "error")
        return redirect(url_for("admin_edit_group", group_id=group_id))

# Add these imports at the top of your file if not already present:
# import csv
# import io
# from flask import session
# from werkzeug.security import generate_password_hash

@app.route("/admin/bulk_create_users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def bulk_create_users():
    """Bulk create users with CSV upload and validation"""
    try:
        logger.info(f"Admin {current_user.id} accessing bulk create users")
        
        if request.method == "POST":
            action = request.form.get("action", "validate")
            
            if action == "validate":
                # Initial CSV upload and validation
                csv_file = request.files.get("csv_file")
                
                if not csv_file or csv_file.filename == '':
                    flash("Please upload a CSV file.", "error")
                    return redirect(url_for("bulk_create_users"))
                
                try:
                    # Read and parse CSV
                    file_content = csv_file.read().decode('utf-8')
                    csv_reader = csv.reader(io.StringIO(file_content))
                    
                    preview_data = []
                    errors = []
                    warnings = []
                    valid_rows = 0
                    
                    # Get all existing usernames and group names for validation
                    existing_users = {user.username for user in User.query.all()}
                    existing_groups = {group.name: group for group in Group.query.all()}
                    
                    for row_num, row in enumerate(csv_reader, 1):
                        # Skip empty rows
                        if not row or all(cell.strip() == '' for cell in row):
                            continue
                        
                        row_data = {
                            'row_num': row_num,
                            'raw_data': row,
                            'errors': [],
                            'warnings': [],
                            'status': 'valid'
                        }
                        
                        # Validate CSV format
                        if len(row) != 5:
                            row_data['errors'].append("Invalid format - expected 5 columns (username,name,password,groupname,role)")
                            row_data['status'] = 'error'
                        else:
                            username, name, password, groupname, role = [cell.strip() for cell in row]
                            
                            row_data.update({
                                'username': username,
                                'name': name,
                                'password': password,
                                'groupname': groupname,
                                'role': role
                            })
                            
                            # Validate required fields
                            if not username:
                                row_data['errors'].append("Username is required")
                            if not name:
                                row_data['errors'].append("Name is required")  
                            if not password:
                                row_data['errors'].append("Password is required")
                            if not groupname:
                                row_data['errors'].append("Group name is required")
                            if not role:
                                row_data['errors'].append("Role is required")
                            
                            # Validate role
                            if role and role not in ['student', 'teacher', 'admin']:
                                row_data['errors'].append("Role must be 'student', 'teacher', or 'admin'")
                            
                            # Validate password length
                            if password and len(password) < 6:
                                row_data['errors'].append("Password must be at least 6 characters")
                            
                            # Check for existing username
                            if username and username in existing_users:
                                row_data['warnings'].append(f"Username '{username}' already exists - will be added to group only")
                            
                            # Check if group exists
                            if groupname and groupname not in existing_groups:
                                row_data['warnings'].append(f"Group '{groupname}' doesn't exist - will be created")
                            
                            if row_data['errors']:
                                row_data['status'] = 'error'
                            elif row_data['warnings']:
                                row_data['status'] = 'warning'
                        
                        preview_data.append(row_data)
                        if row_data['status'] != 'error':
                            valid_rows += 1
                    
                    # Store preview data in session for processing
                    session['csv_preview_data'] = preview_data
                    session['csv_valid_rows'] = valid_rows
                    
                    return render_template("bulk_create_users.html", 
                                         preview_data=preview_data,
                                         valid_rows=valid_rows,
                                         total_rows=len(preview_data),
                                         show_preview=True)
                
                except Exception as csv_error:
                    logger.error(f"CSV processing error: {str(csv_error)}")
                    flash(f"Error processing CSV file: {str(csv_error)}", "error")
                    return redirect(url_for("bulk_create_users"))
            
            elif action == "process":
                # Process the validated data
                preview_data = session.get('csv_preview_data', [])
                if not preview_data:
                    flash("No data to process. Please upload CSV again.", "error")
                    return redirect(url_for("bulk_create_users"))
                
                created_users = 0
                created_groups = 0
                added_to_groups = 0
                skipped = 0
                errors = []
                
                try:
                    # Get existing groups
                    existing_groups = {group.name: group for group in Group.query.all()}
                    
                    for row_data in preview_data:
                        if row_data['status'] == 'error':
                            continue
                        
                        try:
                            username = row_data['username']
                            name = row_data['name']
                            password = row_data['password']
                            groupname = row_data['groupname']
                            role = row_data['role']
                            
                            # Create or get group
                            if groupname not in existing_groups:
                                # Create new group (need course_id - using first available course or create default)
                                default_course = Course.query.first()
                                if not default_course:
                                    # Create a default course if none exists
                                    default_course = Course(
                                        name="Default Course",
                                        code="DEFAULT",
                                        description="Default course for bulk imports",
                                        teacher_id=current_user.id
                                    )
                                    db.session.add(default_course)
                                    db.session.flush()
                                
                                new_group = Group(
                                    name=groupname,
                                    course_id=default_course.id
                                )
                                db.session.add(new_group)
                                db.session.flush()
                                existing_groups[groupname] = new_group
                                created_groups += 1
                            
                            group = existing_groups[groupname]
                            
                            # Check if user exists
                            existing_user = User.query.filter_by(username=username).first()
                            
                            if existing_user:
                                # Check if already in group
                                existing_enrollment = StudentGroup.query.filter_by(
                                    student_id=existing_user.id,
                                    group_id=group.id
                                ).first()
                                
                                if existing_enrollment:
                                    skipped += 1
                                    continue
                                else:
                                    # Add existing user to group (only for students)
                                    if existing_user.role == 'student':
                                        student_group = StudentGroup(
                                            student_id=existing_user.id,
                                            group_id=group.id
                                        )
                                        db.session.add(student_group)
                                        added_to_groups += 1
                                    else:
                                        skipped += 1
                            else:
                                # Create new user
                                new_user = User(
                                    username=username,
                                    password=generate_password_hash(password),
                                    role=role,
                                    name=name,
                                    htno=username,  # username same as hall ticket
                                    must_change_password=True,
                                    created_at=datetime.now()
                                )
                                db.session.add(new_user)
                                db.session.flush()
                                created_users += 1
                                
                                # Add student to group
                                if role == 'student':
                                    student_group = StudentGroup(
                                        student_id=new_user.id,
                                        group_id=group.id
                                    )
                                    db.session.add(student_group)
                                    added_to_groups += 1
                        
                        except Exception as row_error:
                            logger.error(f"Row processing error: {str(row_error)}")
                            errors.append(f"Row {row_data['row_num']}: {str(row_error)}")
                            continue
                    
                    # Commit all changes
                    db.session.commit()
                    
                    # Clear session data
                    session.pop('csv_preview_data', None)
                    session.pop('csv_valid_rows', None)
                    
                    # Prepare success message
                    success_parts = []
                    if created_users > 0:
                        success_parts.append(f"{created_users} users created")
                    if created_groups > 0:
                        success_parts.append(f"{created_groups} groups created")
                    if added_to_groups > 0:
                        success_parts.append(f"{added_to_groups} users added to groups")
                    
                    if success_parts:
                        success_msg = f"Successfully: {', '.join(success_parts)}"
                        flash(success_msg, "success")
                    
                    if skipped > 0:
                        flash(f"Skipped {skipped} entries (already exist/enrolled)", "info")
                    
                    if errors:
                        flash(f"Errors in {len(errors)} rows", "warning")
                    
                    logger.info(f"Bulk user creation completed by admin {current_user.id}: "
                              f"{created_users} users, {created_groups} groups, {added_to_groups} enrollments")
                    
                    return redirect(url_for("manage_users"))
                
                except Exception as process_error:
                    logger.error(f"Processing error: {str(process_error)}")
                    db.session.rollback()
                    flash(f"Error processing data: {str(process_error)}", "error")
                    return redirect(url_for("bulk_create_users"))
        
        # GET request - show form
        return render_template("bulk_create_users.html", show_preview=False)
        
    except Exception as e:
        logger.error(f"Bulk create users error: {str(e)}")
        flash("Error accessing bulk user creation page.", "error")
        return redirect(url_for("admin_dashboard"))
   
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)