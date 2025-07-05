# app.py
import os
import json
import openai
import csv
import secrets
from sqlalchemy import func, and_
from flask import (
    Flask, render_template, redirect, url_for, flash,
    request, jsonify, abort, send_from_directory
)
from flask_cors import CORS
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from flask import (
    abort,
    send_file,
    current_app
)
from config import (
    SECRET_KEY, SQLALCHEMY_DATABASE_URI,
    OPENAI_API_KEY, OPENAI_MODEL,
    UPLOAD_FOLDER, ALLOWED_EXTENSIONS
)

from models import *
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import io
import json
from flask import abort, send_file, current_app
from flask_login import login_required, current_user
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from bs4 import BeautifulSoup
from flask_migrate import Migrate
# Add these imports at the top of your app.py file if they're missing
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from datetime import datetime, timezone
import logging
from datetime import timedelta
# Make sure you have these imports from your models
from models import db, User, Course, Group, Problem, Submission
from flask import request, render_template, redirect, url_for, flash, session
from flask_login import login_user, current_user
from werkzeug.security import check_password_hash
from flask import session, flash, redirect, url_for, request, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user, logout_user, login_user, UserMixin
from werkzeug.security import check_password_hash
# Set up logging to help debug issues
logging.basicConfig(level=logging.DEBUG)
# Fix your original route - add the missing import and fix the route decorator
from flask import make_response
import json
from io import BytesIO
import tempfile
import os
import json
import openai
from flask import jsonify, request, send_file
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from io import BytesIO
import tempfile
from datetime import datetime
import re
from flask import render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import json
import io
import csv

# Configure logging
# ─── App Init ────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # Session expires after 24 hours
app.logger.setLevel(logging.DEBUG)
# Ensure upload dir
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db.init_app(app)
CORS(app)

openai.api_key = OPENAI_API_KEY
MODEL_NAME     = OPENAI_MODEL

# ─── Login Manager ───────────────────────────────────────────────────────────
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ─── Error Handler ───────────────────────────────────────────────────────────
@app.errorhandler(HTTPException)
def handle_http_exception(e):
    return jsonify({"error": e.description}), e.code

# ─── Helpers ─────────────────────────────────────────────────────────────────
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ─── Create Tables ───────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()

# ─── Authentication ──────────────────────────────────────────────────────────
@app.route("/")
def root():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"]
        p = generate_password_hash(request.form["password"])
        r = request.form["role"]
        n = request.form.get("name", "")  # Full name
        h = request.form.get("htno", "")  # Hall ticket number
        
        user = User(username=u, password=p, role=r, name=n, htno=h)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.before_request
def check_forced_logout():
    """Check if user has been force logged out"""
    if current_user.is_authenticated:
        # Check if session token matches and user hasn't been force logged out
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
            # Clear the session and logout
            session.clear()
            logout_user()
            flash("Your session has been terminated by an administrator.", "warning")
            return redirect(url_for('login'))

@app.before_request
def check_session_validity():
    """Check if user's session is still valid"""
    if current_user.is_authenticated:
        stored_token = session.get('user_session_token')
        if not stored_token or stored_token != current_user.session_token:
            # Session is invalid, logout user
            logout_user()
            session.clear()
            if request.is_json:
                return jsonify({'error': 'Session expired', 'redirect': url_for('login')}), 401
            else:
                flash('Your session has expired. Please log in again.', 'warning')
                return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    # If user is already logged in, redirect to appropriate dashboard
    if current_user.is_authenticated:
        if current_user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        elif current_user.role == "teacher":
            return redirect(url_for("teacher_dashboard"))
        else:
            return redirect(url_for("student_dashboard"))
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
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
            session['login_time'] = datetime.utcnow()  # Store as timezone-naive datetime
            
            # Login the user with remember=True for persistent sessions
            login_user(user, remember=True)
            
            # Set session to permanent
            session.permanent = True
            
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
    
    return render_template("login.html")
            
@app.route("/logout")
@login_required
def logout():
    logout_user()
    #flash("Logged out.", "info")
    return redirect(url_for("login"))
#-----Create user Route-------------------

@app.route("/admin/manage_users")
@login_required
def manage_users():
    if current_user.role != "admin":
        return redirect(url_for("student_dashboard"))
    
    # Get all users with pagination
    page = request.args.get('page', 1, type=int)
    per_page = 20  # Show 20 users per page
    
    users = User.query.filter(User.role != 'admin').paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template("manage_users.html", users=users)

# Updated Route
@app.route("/admin/edit_user/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    if current_user.role != "admin":
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
            flash(f"User {user.username} updated successfully", "success")
            return redirect(url_for("manage_users"))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating user: {str(e)}", "danger")
    
    return render_template("edit_user.html", user=user)


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != "admin":
        return redirect(url_for("student_dashboard"))
    
    user = User.query.get_or_404(user_id)
    
    # Don't allow deleting admin accounts
    if user.role == "admin":
        flash("Cannot delete admin accounts", "danger")
        return redirect(url_for("manage_users"))
    
    try:
        # Delete associated records first
        StudentGroup.query.filter_by(student_id=user.id).delete()
        Submission.query.filter_by(student_id=user.id).delete()
        
        # If user is a teacher, handle their courses
        if user.role == "teacher":
            Course.query.filter_by(teacher_id=user.id).delete()
        
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.username} deleted successfully", "success")
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting user: {str(e)}", "danger")
    
    return redirect(url_for("manage_users"))

@app.route("/admin/create_user", methods=["GET", "POST"])
@login_required
def create_user():
    if current_user.role != "admin":
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
            flash(f"User {username} created successfully", "success")
            return redirect(url_for("manage_users"))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating user: {str(e)}", "danger")
    
    return render_template("create_user.html")

@app.route("/admin/bulk_create_users", methods=["GET", "POST"])
@login_required
def bulk_create_users():
    if current_user.role != "admin":
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
            
            if created_count > 0:
                flash(f"Successfully created {created_count} users", "success")
            
            if errors:
                flash(f"Errors encountered: {'; '.join(errors)}", "warning")
            
            return redirect(url_for("manage_users"))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating users: {str(e)}", "danger")
    
    return render_template("bulk_create_users.html")

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

@app.route("/admin/create-course", methods=["GET", "POST"])
@login_required
def admin_create_course():
    if current_user.role != "admin":
        return redirect(url_for("student_dashboard"))
    
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        description = request.form.get("description")
        teacher_id = request.form.get("teacher_id")
        
        if Course.query.filter_by(code=code).first():
            flash("Course code already exists.", "danger")
            return render_template("admin_create_course.html", teachers=User.query.filter_by(role="teacher").all())
        
        new_course = Course(
            name=name,
            code=code,
            description=description,
            teacher_id=teacher_id
        )
        
        db.session.add(new_course)
        db.session.commit()
        
        flash(f"Course '{name}' created successfully.", "success")
        return redirect(url_for("admin_dashboard"))
    
    teachers = User.query.filter_by(role="teacher").all()
    return render_template("admin_create_course.html", teachers=teachers)

@app.route("/admin/create-group", methods=["GET", "POST"])
@login_required
def admin_create_group():
    if current_user.role != "admin":
        return redirect(url_for("student_dashboard"))
    
    if request.method == "POST":
        name = request.form.get("name")
        course_id = request.form.get("course_id")
        
        new_group = Group(name=name, course_id=course_id)
        db.session.add(new_group)
        db.session.commit()
        
        flash(f"Group '{name}' created successfully.", "success")
        return redirect(url_for("admin_dashboard"))
    
    courses = Course.query.filter_by(is_active=True).all()
    return render_template("admin_create_group.html", courses=courses)

@app.route("/admin/import-students", methods=["GET", "POST"])
@login_required
def admin_import_students():
    if current_user.role != "admin":
        return redirect(url_for("student_dashboard"))
    
    if request.method == "POST":
        group_id = request.form.get("group_id")
        csv_file = request.files.get("csv_file")
        
        if not group_id:
            flash("Please select a group.", "error")
            return redirect(url_for("admin_import_students"))
        
        if not csv_file or csv_file.filename == '':
            flash("Please upload a CSV file.", "error")
            return redirect(url_for("admin_import_students"))
        
        group = Group.query.get_or_404(group_id)
        
        # Read and parse CSV file
        try:
            # Read file content
            file_content = csv_file.read().decode('utf-8')
            csv_reader = csv.reader(io.StringIO(file_content))
            
            imported = 0
            added_to_group = 0
            errors = []
            skipped = []
            
            for row_num, row in enumerate(csv_reader, 1):
                # Skip empty rows
                if not row or all(cell.strip() == '' for cell in row):
                    continue
                
                if len(row) != 3:
                    errors.append(f"Row {row_num}: Invalid format - expected 3 columns (htno,name,password)")
                    continue
                
                htno, name, password = [cell.strip() for cell in row]
                
                if not htno or not name or not password:
                    errors.append(f"Row {row_num}: Missing required data - htno: '{htno}', name: '{name}', password: '{password}'")
                    continue
                
                # Check if student already exists
                existing_student = User.query.filter_by(htno=htno).first()
                
                if existing_student:
                    # Student exists, check if already in this group
                    existing_enrollment = StudentGroup.query.filter_by(
                        student_id=existing_student.id, 
                        group_id=group_id
                    ).first()
                    
                    if existing_enrollment:
                        skipped.append(f"Row {row_num}: Student {htno} ({name}) already enrolled in this group")
                        continue
                    else:
                        # Add existing student to group
                        try:
                            student_group = StudentGroup(
                                student_id=existing_student.id, 
                                group_id=group_id
                            )
                            db.session.add(student_group)
                            added_to_group += 1
                        except Exception as e:
                            errors.append(f"Row {row_num}: Error adding existing student {htno} to group - {str(e)}")
                            continue
                else:
                    # Create new student
                    try:
                        student = User(
                            username=htno,  # Using HTNO as username
                            password=generate_password_hash(password),
                            role="student",
                            name=name,
                            htno=htno,
                            must_change_password=True
                        )
                        db.session.add(student)
                        db.session.flush()  # Get the student ID
                        
                        # Add to group
                        student_group = StudentGroup(
                            student_id=student.id, 
                            group_id=group_id
                        )
                        db.session.add(student_group)
                        imported += 1
                    except Exception as e:
                        errors.append(f"Row {row_num}: Error creating student {htno} - {str(e)}")
                        continue
            
            # Commit all changes
            try:
                db.session.commit()
                
                # Prepare success message
                success_parts = []
                if imported > 0:
                    success_parts.append(f"{imported} new students created and added")
                if added_to_group > 0:
                    success_parts.append(f"{added_to_group} existing students added to group")
                
                if success_parts:
                    success_msg = f"Successfully processed: {', '.join(success_parts)} to group '{group.name}'"
                    flash(success_msg, "success")
                
                # Show warnings for skipped entries
                if skipped:
                    flash(f"Skipped {len(skipped)} entries (already enrolled): {'; '.join(skipped[:3])}" + 
                          (f" and {len(skipped)-3} more..." if len(skipped) > 3 else ""), "info")
                
                # Show errors
                if errors:
                    flash(f"Errors encountered: {'; '.join(errors[:3])}" + 
                          (f" and {len(errors)-3} more..." if len(errors) > 3 else ""), "warning")
                
            except Exception as e:
                db.session.rollback()
                flash(f"Error saving to database: {str(e)}", "error")
                
        except Exception as e:
            flash(f"Error processing CSV file: {str(e)}", "error")
        
        return redirect(url_for("admin_import_students"))
    
    # GET request - show form
    groups = Group.query.options(
        db.joinedload(Group.course),
        db.joinedload(Group.student_groups).joinedload(StudentGroup.student)
    ).all()
    
    return render_template("admin_import_students.html", groups=groups)

@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        return redirect(url_for("student_dashboard"))
    
    courses = Course.query.order_by(Course.created_at.desc()).all()
    teachers = User.query.filter_by(role="teacher").all()
    students = User.query.filter_by(role="student").all()
    groups = Group.query.all()
    
    return render_template("admin_dashboard.html", 
                         courses=courses, teachers=teachers, 
                         students=students, groups=groups)

@app.route("/admin/create-student", methods=["GET", "POST"])
@login_required
def admin_create_student():
    if current_user.role != "admin":
        return redirect(url_for("student_dashboard"))
    
    if request.method == "POST":
        username = request.form.get("username")
        temp_password = request.form.get("temp_password")
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return render_template("admin_create_student.html")
        
        # Create new student with temporary password
        new_student = User(
            username=username,
            password=generate_password_hash(temp_password),
            role="student",
            must_change_password=True  # Force password change on first login
        )
        
        db.session.add(new_student)
        db.session.commit()
        
        flash(f"Student '{username}' created successfully. They must change their password on first login.", "success")
        return redirect(url_for("admin_dashboard"))
    
    return render_template("admin_create_student.html")

# Render the form
@app.route("/admin/create_problem")
@login_required
def admin_create_problem():
    if current_user.role != "admin":
        return redirect(url_for("student_dashboard"))
    return render_template("admin_create.html")



@app.route("/api/generate_solution", methods=["POST"])
@login_required
def api_generate_solution():
    """Generate solution for a problem using GPT"""
    if current_user.role != "teacher":
        return jsonify({"error": "Only teachers can generate solutions"}), 403
    
    try:
        data = request.get_json() or {}
        problem_statement = data.get('problem_statement', '')
        rubric = data.get('rubric', {})  # Dict with aspect: marks
        evaluation_prompt = data.get('evaluation_prompt', '')
        topics = data.get('topics', [])
        
        if not problem_statement or not rubric:
            return jsonify({"error": "Problem statement and rubric are required"}), 400
        
        # Construct system prompt for solution generation
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
        
        print(system_prompt)  # For debugging like in generate_pills
        
        resp = openai.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": "Generate the comprehensive solution as specified."}
            ]
        )
        
        content = resp.choices[0].message.content.strip()
        
        # Try to extract JSON if wrapped in code blocks
        if content.startswith("```json"):
            content = content[7:-3].strip()
        elif content.startswith("```"):
            content = content[3:-3].strip()
        
        parsed = json.loads(content)
        solution_data = parsed.get("solution", {})
        sections = solution_data.get("sections", [])
        
        # Validate the structure of sections
        for section in sections:
            if not all(key in section for key in ["aspect", "marks", "content"]):
                return jsonify({"error": "Invalid section structure from model"}), 502
        
        # Fallback: create structured solution if parsing fails or sections is empty
        if not sections:
            sections = [
                {
                    "aspect": aspect,
                    "marks": marks,
                    "content": f"<p>Solution for {aspect} ({marks} marks):</p><div>{content}</div>"
                }
                for aspect, marks in rubric.items()
            ]
        
        return jsonify({
            "solution": {"sections": sections},
            "total_sections": len(sections)
        })
        
    except json.JSONDecodeError as e:
        return jsonify({
            "error": "Invalid JSON from model", 
            "raw": resp.choices[0].message.content,
            "json_error": str(e)
        }), 502
    except Exception as e:
        return jsonify({"error": f"Failed to generate solution: {str(e)}"}), 500

@app.route("/api/save_problem", methods=["POST"])
@login_required
def api_save_problem():
    """Updated save problem API to include solution"""
    if current_user.role != "teacher":
        return jsonify({"error": "Only teachers can create problems"}), 403
    
    form = request.form
    files = request.files
    course_id = form.get("course_id")
    
    # Verify teacher owns this course
    course = Course.query.filter_by(id=course_id, teacher_id=current_user.id).first()
    if not course:
        return jsonify({"error": "Invalid course or access denied"}), 403
    
    problem = Problem(
        title=form["title"],
        statement=form["statement"],
        topics=form["topics_json"],
        rubric=form["rubric_json"],
        pills=form["pills_json"],
        prompt=form["prompt_text"],
        solution=form.get("solution_json"),  # New field
        video_url=form.get("video_url", None),
        course_id=course_id,
        created_by=current_user.id,
        is_active=0
    )
    
    # PDF upload
    f = files.get("doc_file")
    if f and allowed_file(f.filename):
        fn = secure_filename(f.filename)
        upload_path = os.path.join(app.config["UPLOAD_FOLDER"], fn)
        f.save(upload_path)
        problem.doc_path = f"uploads/docs/{fn}"
    
    db.session.add(problem)
    db.session.commit()
    
    return jsonify({"status": "ok"})

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
    """Generate and download solution PDF with enhanced HTML styling"""
    problem = Problem.query.get_or_404(problem_id)
    
    # Check access
    if current_user.role == "teacher":
        course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first()
        if not course:
            return jsonify({"error": "Access denied"}), 403
    
    if not problem.solution:
        return jsonify({"error": "No solution available for this problem"}), 404
    
    try:
        solution_data = json.loads(problem.solution)
        
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
            fontName='Helvetica-Bold',
            backColor=HexColor('#E8F6F3'),
            borderColor=HexColor('#27AE60'),
            borderWidth=1,
            borderPadding=8
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
            lineHeight=1.5,
            backColor=HexColor('#FDFEFE'),
            borderColor=HexColor('#D5DBDB'),
            borderWidth=0.5,
            borderPadding=10
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
        
        # Content
        story = []
        
        # Title
        story.append(Paragraph(f"{problem.title} - Solution", title_style))
        story.append(Spacer(1, 20))
        
        # Course info
        course = Course.query.get(problem.course_id)
        story.append(Paragraph(f"<b>Course:</b> {course.code} - {course.name}", content_style))
        story.append(Paragraph(f"<b>Created:</b> {problem.created_at.strftime('%B %d, %Y')}", content_style))
        story.append(Paragraph(f"<b>Total Marks:</b> {sum(json.loads(problem.rubric).values())}", content_style))
        story.append(Spacer(1, 30))
        
        # Problem Statement Section
        story.append(Paragraph("📋 Problem Statement", problem_section_style))
        clean_statement = clean_html_for_pdf(problem.statement)
        story.append(Paragraph(clean_statement, content_style))
        story.append(Spacer(1, 20))
        
        # Knowledge Topics
        story.append(Paragraph("🎯 Knowledge Topics", problem_section_style))
        topics = json.loads(problem.topics)
        for topic in topics:
            story.append(Paragraph(f"• {topic}", bullet_style))
        story.append(Spacer(1, 20))
        
        # Scoring Rubric
        story.append(Paragraph("📊 Scoring Rubric", problem_section_style))
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
        story.append(Spacer(1, 30))
        
        # Add Knowledge Pills if available
        if problem.pills:
            pills = json.loads(problem.pills)
            if pills:
                story.append(Paragraph("💡 Knowledge Pills", problem_section_style))
                story.append(Spacer(1, 10))
                
                for i, pill in enumerate(pills, 1):
                    pill_title = f"💡 {i}. {pill.get('topic', 'Knowledge Pill')}"
                    story.append(Paragraph(pill_title, pill_title_style))
                    
                    pill_content = clean_html_for_pdf(pill.get('content', ''))
                    if pill_content:
                        story.append(Paragraph(pill_content, pill_content_style))
                    story.append(Spacer(1, 15))
                
                story.append(Spacer(1, 20))
        
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
            fontName='Helvetica-Bold',
            backColor=HexColor('#E8F6F3'),
            borderColor=HexColor('#27AE60'),
            borderWidth=2,
            borderPadding=10
        )
        story.append(Paragraph("✅ DETAILED SOLUTION", solution_header_style))
        story.append(Spacer(1, 20))
        
        # Solution sections with enhanced styling
        sections = solution_data.get('sections', [])
        for i, section in enumerate(sections):
            # Section header with marks and styling
            marks_badge = f"[{section.get('marks', 0)} marks]"
            section_title = f"🔍 {i+1}. {section.get('aspect', 'Section')} {marks_badge}"
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
        
        filename = f"{problem.title.replace(' ', '_')}_Solution.pdf"
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({"error": f"Failed to generate solution PDF: {str(e)}"}), 500


# ─── API: generate_pills ─────────────────────────────────────────────────────
@app.route("/api/generate_pills", methods=["POST"])
@login_required
def generate_pills():
    data = request.get_json() or {}
    topics = data.get("topics")
    problem = data.get("problem_statement") or data.get("statement")
    use_problem_context = data.get("use_problem_context", True)  # Default to True
    
    if not isinstance(topics, list) or not topics:
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
    print(system_prompt)
    try:
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
                return jsonify({"error": "Invalid pill structure from model"}), 502
        
        return jsonify({
            "pills": pills,
            "used_problem_context": use_problem_context and bool(problem),
            "total_pills": len(pills)
        })
        
    except json.JSONDecodeError as e:
        return jsonify({
            "error": "Invalid JSON from model", 
            "raw": resp.choices[0].message.content,
            "json_error": str(e)
        }), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── API: generate_prompt ─────────────────────────────────────────────────────
@app.route("/api/generate_prompt", methods=["POST"])
@login_required
def generate_prompt():
    data = request.get_json() or {}
    for key in ("base_prompt", "problem_statement", "pill_topics", "rubric"):
        if key not in data:
            abort(400, f"Missing '{key}' in payload")
    
    problem = data["problem_statement"].strip()
    topics = data["pill_topics"]
    rubric = data["rubric"]
    
    if not isinstance(topics, list) or not topics:
        abort(400, "'pill_topics' must be a non-empty list")
    if not isinstance(rubric, dict) or not rubric:
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
    return jsonify({"system_prompt": prompt_text})



@app.route('/admin/delete_problem/<int:id>')
@login_required
def admin_delete_problem(id):
    # Only admins may delete
    if current_user.role != 'admin':
        flash('Access denied: only administrators can delete problems.', 'danger')
        return redirect(url_for('student_dashboard'))

    prob = Problem.query.get(id)
    if not prob:
        flash('Problem not found.', 'warning')
        return redirect(url_for('admin_dashboard'))

    try:
        db.session.delete(prob)
        db.session.commit()
        flash('Problem deleted successfully.', 'success')
    except Exception as e:
        current_app.logger.error('Error deleting problem %s: %s', id, e)
        flash('Students Submissions Found. Could not delete problem', 'danger')

    return redirect(url_for('admin_dashboard'))


# ─── Student Views ─────────────────────────────────────────────────────────── 

@app.route("/student/dashboard")
@login_required
def student_dashboard():
    if current_user.role not in ["student"]:
        if current_user.role == "teacher":
            return redirect(url_for("teacher_dashboard"))
        return redirect(url_for("admin_dashboard"))
    
    if current_user.must_change_password:
        flash("You must change your password before accessing the dashboard.", "warning")
        return redirect(url_for("change_password"))
    
    # Get student's enrolled groups
    student_groups = StudentGroup.query.filter_by(student_id=current_user.id).all()
    
    # If student is not enrolled in any groups, show empty dashboard
    if not student_groups:
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
    
    return render_template("student_dashboard.html",
                         problems=problems, subs=subs, courses=active_courses)

@app.route("/student/reports")
@login_required
def student_reports():
    """Student reports page showing last attempt for each problem and performance analytics"""
    
    # Check if user is a student
    if current_user.role not in ["student"]:
        if current_user.role == "teacher":
            return redirect(url_for("teacher_dashboard"))
        return redirect(url_for("admin_dashboard"))
    
    # Check if password needs to be changed
    if current_user.must_change_password:
        flash("You must change your password before accessing the reports.", "warning")
        return redirect(url_for("change_password"))
    
    # Get student's enrolled groups
    student_groups = StudentGroup.query.filter_by(student_id=current_user.id).all()
    
    # If student is not enrolled in any groups, show empty reports page
    if not student_groups:
        return render_template("student_reports.html",
                             submissions=[], avg_score=0, best_score=0,
                             unique_problems=0, course_stats={}, courses=[])
    
    # Get courses from enrolled groups
    courses = [sg.group.course for sg in student_groups]
    active_courses = [c for c in courses if c.is_active]
    
    if not active_courses:
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
    
    return render_template("student_reports.html",
                         submissions=submissions,
                         avg_score=avg_score,
                         best_score=best_score,
                         unique_problems=unique_problems,
                         course_stats=course_stats,
                         courses=active_courses)


# Helper route for updating the navigation (if you want to add reports link)
@app.context_processor
def inject_navigation_data():
    """Inject navigation data into all templates"""
    
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
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    try:
        # Ensure must_change_password has a default value
        if not hasattr(current_user, 'must_change_password'):
            current_user.must_change_password = False
            
        if request.method == "POST":
            current_password = request.form.get("current_password", "").strip()
            new_password = request.form.get("new_password", "").strip()
            confirm_password = request.form.get("confirm_password", "").strip()
            
            # Basic validation
            if not new_password:
                flash("New password cannot be empty.", "danger")
                return render_template("change_password.html")
            
            # Validate current password (only if not forced change)
            if not current_user.must_change_password:
                if not current_password:
                    flash("Current password is required.", "danger")
                    return render_template("change_password.html")
                if not check_password_hash(current_user.password, current_password):
                    flash("Current password is incorrect.", "danger")
                    return render_template("change_password.html")
            
            # Validate new password
            if len(new_password) < 6:
                flash("New password must be at least 6 characters long.", "danger")
                return render_template("change_password.html")
            
            if new_password != confirm_password:
                flash("New passwords do not match.", "danger")
                return render_template("change_password.html")
            
            # Update password
            current_user.password = generate_password_hash(new_password)
            current_user.must_change_password = False
            current_user.password_changed_at = datetime.utcnow()
            
            try:
                db.session.commit()
                flash("Password changed successfully!", "success")
                
                # Redirect based on role
                if current_user.role == "admin":
                    return redirect(url_for("admin_dashboard"))
                else:
                    return redirect(url_for("student_dashboard"))
                    
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Database error during password change: {str(e)}")
                flash("An error occurred while updating your password. Please try again.", "danger")
                return render_template("change_password.html")
        
        # GET request - render the form
        return render_template("change_password.html")
        
    except Exception as e:
        app.logger.error(f"Error in change_password route: {str(e)}")
        flash("An unexpected error occurred. Please try again.", "danger")
        return render_template("change_password.html")


@app.route("/student/solve/<int:pid>")
@login_required
def student_solve(pid):
    # Only students may view this
    if current_user.role != "student":
        return redirect(url_for("admin_dashboard"))
    
    # Must change password first
    if current_user.must_change_password:
        flash("You must change your password before accessing problems.", "warning")
        return redirect(url_for("change_password"))
    
    # Load problem or 404
    problem = Problem.query.get_or_404(pid)
    
    # Fetch most recent submission
    last_sub = (
        Submission.query
        .filter_by(student_id=current_user.id, problem_id=pid)
        .order_by(Submission.created_at.desc())
        .first()
    )
    
    # Block if 3 or more attempts used
    if last_sub and last_sub.attempt >= 3:
        flash("You have exhausted all attempts for this problem.", "warning")
        return redirect(url_for("student_dashboard"))
    
    # Parse rubric JSON (or fallback to empty dict)
    try:
        rubric_data = json.loads(problem.rubric)
    except (TypeError, ValueError):
        rubric_data = {}
    
    # Parse pills JSON (or fallback to empty list)
    try:
        pills_data = json.loads(problem.pills) if problem.pills else []
    except (TypeError, ValueError):
        pills_data = []
    
    # Compute attempts left (3 allowed total)
    used = last_sub.attempt if last_sub else 0
    attempts_left = max(0, 3 - used)
    
    return render_template(
        "student_solve.html",
        problem=problem,
        last_sub=last_sub,
        rubric=rubric_data,
        pills=pills_data,
        attempts_left=attempts_left
    )


@app.route("/api/evaluate", methods=["POST"])
@login_required
def api_evaluate():
    import json
    from flask import request, abort, jsonify

    data = request.get_json() or {}
    pid   = data.get("problem_id")
    sp    = data.get("system_prompt")
    stmt  = data.get("problem_statement")
    sol   = data.get("student_solution")

    if not all([pid, sp, stmt, sol]):
        abort(400, "Missing one of: problem_id, system_prompt, problem_statement, student_solution")

    problem = Problem.query.get(int(pid))
    if not problem:
        abort(404, "Problem not found")

    # 3-attempt limit
    used = Submission.query.filter_by(
        student_id=current_user.id, problem_id=problem.id
    ).count()
    if used >= 3:
        return jsonify({"error":"No attempts left"}), 403

    messages = [
        {"role":"system","content":sp},
        {"role":"user","content":f"Problem Statement:\n```\n{stmt}\n```\n\nStudent Submission:\n```\n{sol}\n```"}
    ]

    try:
        resp    = openai.chat.completions.create(model=MODEL_NAME, messages=messages)
        content = resp.choices[0].message.content
        result  = json.loads(content)
    except json.JSONDecodeError:
        return jsonify({"error":"Invalid JSON from model", "raw":content}), 502
    except Exception as e:
        return jsonify({"error":str(e)}), 500

    # Persist
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

    return jsonify(result)

@app.route("/student/report/<int:sid>", endpoint='student_report')
@app.route("/teacher/report/<int:sid>", endpoint='teacher_report')
@login_required
def report_download(sid):
    # Fetch submission
    sub = Submission.query.get_or_404(sid)
    
    # Authorization check - allow both student owner and teacher
    if current_user.role == "student":
        if sub.student_id != current_user.id:
            abort(403)
    elif current_user.role == "teacher":
        # Verify teacher owns the problem/course
        prob = Problem.query.get_or_404(sub.problem_id)
        course = Course.query.filter_by(id=prob.course_id, teacher_id=current_user.id).first()
        if not course:
            abort(403)
    else:
        abort(403)
    
    prob = Problem.query.get_or_404(sub.problem_id)

    try:
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
            
        return send_file(
            buffer,
            as_attachment=True,
            download_name=filename,
            mimetype="application/pdf"
        )

    except Exception:
        current_app.logger.exception("PDF generation failed for %s", sid)
        abort(500, "Unable to generate report PDF right now.")

# ============================================================================
# TEACHER ROUTES
# ============================================================================

@app.route("/api/teacher/course/<int:course_id>/reset-sessions", methods=["POST"])
@login_required
def reset_course_sessions(course_id):
    """Reset all student sessions for a specific course"""
    if current_user.role != "teacher":
        return jsonify({"status": "error", "error": "Unauthorized"}), 403
    
    if current_user.must_change_password:
        return jsonify({"status": "error", "error": "Password change required"}), 400
    
    try:
        # Verify teacher owns this course
        course = Course.query.filter_by(
            id=course_id,
            teacher_id=current_user.id
        ).first_or_404()
        
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
            student.force_logout_at = datetime.utcnow()
            reset_count += 1
        
        # Commit all changes
        db.session.commit()
        
        return jsonify({
            "status": "ok",
            "message": f"Successfully reset sessions for {reset_count} students. They will be logged out on their next request."
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "error": str(e)}), 500

# Route to reset logins for a specific group
@app.route('/teacher/group/<int:group_id>/reset_logins', methods=['POST'])
@login_required
def reset_group_logins(group_id):
    """Reset logins for all students in a specific group"""
    
    # Verify teacher has access to this group
    group = Group.query.join(Course).filter(
        Group.id == group_id,
        Course.teacher_id == current_user.id
    ).first()
    
    if not group:
        return jsonify({'success': False, 'message': 'Group not found or access denied'}), 403
    
    try:
        students_logged_out = 0
        
        for student in group.students:
            # Invalidate student's session
            student.invalidate_session()
            students_logged_out += 1
        
        # Log the action
        app.logger.info(f"Teacher {current_user.username} reset logins for group {group.name} - {students_logged_out} students affected")
        
        return jsonify({
            'success': True, 
            'message': f'Successfully logged out {students_logged_out} students from {group.name}',
            'students_count': students_logged_out
        })
        
    except Exception as e:
        app.logger.error(f"Error resetting logins for group {group_id}: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while resetting logins'}), 500

# Route to get course login status
@app.route('/teacher/course/<int:course_id>/login_status', methods=['GET'])
@login_required
def get_course_login_status(course_id):
    """Get login status of students in a course"""
    
    course = Course.query.filter_by(id=course_id, teacher_id=current_user.id).first()
    if not course:
        return jsonify({'error': 'Course not found or access denied'}), 403
    
    # Get active sessions (students logged in in last 30 minutes)
    cutoff_time = datetime.utcnow() - timedelta(minutes=30)
    
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
    
    return jsonify({
        'course_name': course.name,
        'total_students': total_students,
        'active_students': len(active_students),
        'students': active_students
    })

@app.route("/teacher/problem/<int:problem_id>/toggle", methods=["POST"])
@login_required
def teacher_toggle_problem(problem_id):
    if current_user.role != "teacher":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    problem = Problem.query.get_or_404(problem_id)
    
    # Check if the teacher owns this problem
    if problem.created_by != current_user.id:
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    # Toggle the active status
    problem.is_active = not problem.is_active
    db.session.commit()
    
    status = "activated" if problem.is_active else "deactivated"
    return jsonify({
        "success": True, 
        "message": f"Problem {status} successfully",
        "is_active": problem.is_active
    })

@app.route("/teacher/problem/<int:problem_id>/delete", methods=["POST"])
@login_required
def teacher_delete_problem(problem_id):
    if current_user.role != "teacher":
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    problem = Problem.query.get_or_404(problem_id)
    
    # Check if the teacher owns this problem
    if problem.created_by != current_user.id:
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    
    # Check if there are any submissions
    submission_count = Submission.query.filter_by(problem_id=problem_id).count()
    if submission_count > 0:
        return jsonify({
            "success": False, 
            "message": f"Cannot delete problem. It has {submission_count} submission(s)."
        })
    
    # Delete the problem
    db.session.delete(problem)
    db.session.commit()
    
    return jsonify({
        "success": True, 
        "message": "Problem deleted successfully"
    })

# Update your existing teacher_dashboard route to order problems by creation date
@app.route("/teacher/dashboard")
@login_required
def teacher_dashboard():
    if current_user.role != "teacher":
        return redirect(url_for("student_dashboard"))
    if current_user.must_change_password:
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
    
    return render_template(
        "teacher_dashboard.html",
        courses=courses,
        problems=problems,
        problem_submission_counts=problem_submission_counts
    )

@app.route("/teacher/create-problem", methods=["GET","POST"])
@app.route("/teacher/create-problem/<int:course_id>", methods=["GET","POST"])
@login_required
def teacher_create_problem(course_id=None):
    if current_user.role != "teacher":
        return redirect(url_for("student_dashboard"))
    if current_user.must_change_password:
        flash("You must change your password before creating problems.", "warning")
        return redirect(url_for("change_password"))

    # All active courses for this teacher
    courses = Course.query.filter_by(
        teacher_id=current_user.id, is_active=True
    ).all()

    # If they clicked “Add New Problem” from a specific course page
    selected_course = None
    if course_id:
        selected_course = Course.query.filter_by(
            id=course_id,
            teacher_id=current_user.id,
            is_active=True
        ).first()

    # (Handle POST here the same as before, omitted for brevity)
    # …

    return render_template(
        "teacher_create_problem.html",
        courses=courses,
        selected_course=selected_course
    )

@app.route("/teacher/course/<int:course_id>")
@login_required
def teacher_course_detail(course_id):
    if current_user.role != "teacher":
        return redirect(url_for("student_dashboard"))
    if current_user.must_change_password:
        flash("You must change your password before accessing course details.", "warning")
        return redirect(url_for("change_password"))

    # Load course + guard
    course = Course.query.filter_by(
        id=course_id,
        teacher_id=current_user.id
    ).first_or_404()

    # All groups & problems for this course
    groups   = Group.query.filter_by(course_id=course_id).all()
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
            "attempted":      len(stats),
            "avg_score":      (sum(s.best_score for s in stats) / len(stats)) if stats else 0
        }

    # Course-level summary cards
    enrolled_students = sum(len(g.students) for g in groups)

    total_submissions = (
        Submission.query
        .filter(Submission.problem_id.in_([p.id for p in problems]))
        .count()
    )

    # **FIX**: compute average across problems from submission_stats
    if problems:
        average_score = sum(
            submission_stats[p.id]["avg_score"] for p in problems
        ) / len(problems)
    else:
        average_score = 0

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





@app.route("/api/teacher/problem/<int:problem_id>/download-solution")
@login_required
def api_download_problem_solution(problem_id):
    """Download problem solution if conditions are met"""
    if current_user.role != "teacher":
        return jsonify({"error": "Unauthorized"}), 403
    
    # Verify the problem belongs to this teacher
    problem = Problem.query.filter_by(id=problem_id).first_or_404()
    course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first_or_404()
    
    # Check if solution can be downloaded
    if not problem.can_download_solution:
        return jsonify({"error": "Solution download not available"}), 403
    
    # Create solution file
    solution_data = {
        "problem_title": problem.title,
        "course_name": course.name,
        "solution": json.loads(problem.solution) if problem.solution else {},
        "generated_at": datetime.utcnow().isoformat(),
        "problem_state": problem.current_state
    }
    
    # Create file in memory
    output = io.StringIO()
    json.dump(solution_data, output, indent=2)
    output.seek(0)
    
    # Convert to bytes
    file_data = io.BytesIO(output.getvalue().encode('utf-8'))
    
    filename = f"solution_{problem.title.replace(' ', '_')}.json"
    
    return send_file(
        file_data,
        as_attachment=True,
        download_name=filename,
        mimetype='application/json'
    )



@app.route("/teacher/problem/<int:problem_id>/preview")
@login_required
def teacher_problem_preview(problem_id):
    """Preview a problem"""
    if current_user.role != "teacher":
        return redirect(url_for("student_dashboard"))
    
    # Verify the problem belongs to this teacher
    problem = Problem.query.filter_by(id=problem_id).first_or_404()
    course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first_or_404()
    
    # Check if there are any submissions for this problem
    has_submissions = Submission.query.filter_by(problem_id=problem_id).first() is not None
    
    return render_template(
        "teacher_problem_preview.html",
        problem=problem,
        course=course,
        has_submissions=has_submissions
    )

@app.route("/teacher/problem/<int:problem_id>/analytics")
@login_required
def teacher_problem_analytics(problem_id):
    """View analytics for a specific problem based on students' latest attempts"""
    if current_user.role != "teacher":
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
    
    # Calculate average score based on students who have a score
    scored_submissions = [s for s in latest_submissions if s.total_score is not None and s.total_score > 0]
    avg_score = sum(s.total_score for s in scored_submissions) / len(scored_submissions) if scored_submissions else 0
    
    # Find highest score among students with score > 0
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
    
# Add this route to your Flask app
@app.route("/teacher/problem/<int:problem_id>/edit")
@login_required
def teacher_edit_problem(problem_id):
    if current_user.role != "teacher":
        flash("Access denied", "error")
        return redirect(url_for("dashboard"))
    
    # Get the problem and verify teacher owns it
    problem = Problem.query.filter_by(id=problem_id).first()
    if not problem:
        flash("Problem not found", "error")
        return redirect(url_for("teacher_dashboard"))
    
    # Check if teacher owns the course this problem belongs to
    course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first()
    if not course:
        flash("Access denied - you don't own this problem", "error")
        return redirect(url_for("teacher_dashboard"))
    
    # Get all courses for this teacher (for the dropdown)
    courses = Course.query.filter_by(teacher_id=current_user.id).all()
    
    return render_template(
        "teacher_edit_problem.html",
        problem=problem,
        courses=courses,
        current_course=course
    )

# Add this route for updating the problem
@app.route("/api/update_problem/<int:problem_id>", methods=["POST"])
@login_required
def api_update_problem(problem_id):
    if current_user.role != "teacher":
        return jsonify({"error": "Only teachers can update problems"}), 403
    
    # Get the problem and verify teacher owns it
    problem = Problem.query.filter_by(id=problem_id).first()
    if not problem:
        return jsonify({"error": "Problem not found"}), 404
    
    # Check if teacher owns the course this problem belongs to
    course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first()
    if not course:
        return jsonify({"error": "Access denied"}), 403
    
    form = request.form
    files = request.files
    
    # Verify the new course_id belongs to this teacher
    new_course_id = form.get("course_id")
    new_course = Course.query.filter_by(id=new_course_id, teacher_id=current_user.id).first()
    if not new_course:
        return jsonify({"error": "Invalid course or access denied"}), 403
    
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
    
    db.session.commit()
    return jsonify({"status": "ok"})

@app.route("/api/teacher/submission/<int:submission_id>")
@login_required
def api_get_submission(submission_id):
    """Get submission details via API"""
    if current_user.role != "teacher":
        return jsonify({"status": "error", "error": "Unauthorized"}), 403
    
    try:
        # Get submission with student and problem info
        submission = (
            db.session.query(Submission, User, Problem)
            .join(User, Submission.student_id == User.id)
            .join(Problem, Submission.problem_id == Problem.id)
            .filter(Submission.id == submission_id)
            .first()
        )
        
        if not submission:
            return jsonify({"status": "error", "error": "Submission not found"}), 404
        
        submission_obj, student, problem = submission
        
        # Verify the problem belongs to this teacher
        course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first()
        if not course:
            return jsonify({"status": "error", "error": "Unauthorized"}), 403
        
        # Parse scores and feedback if they exist
        scores = json.loads(submission_obj.scores) if submission_obj.scores else {}
        feedback = json.loads(submission_obj.feedback) if submission_obj.feedback else []
        
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
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route("/api/teacher/submission/<int:submission_id>/download")
@login_required
def api_download_submission(submission_id):
    """Download submission as text file"""
    if current_user.role != "teacher":
        return redirect(url_for("teacher_dashboard"))
    
    try:
        # Get submission with student and problem info
        submission = (
            db.session.query(Submission, User, Problem)
            .join(User, Submission.student_id == User.id)
            .join(Problem, Submission.problem_id == Problem.id)
            .filter(Submission.id == submission_id)
            .first()
        )
        
        if not submission:
            flash("Submission not found", "error")
            return redirect(url_for("teacher_dashboard"))
        
        submission_obj, student, problem = submission
        
        # Verify the problem belongs to this teacher
        course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first()
        if not course:
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
        
        return response
        
    except Exception as e:
        flash(f"Error downloading submission: {str(e)}", "error")
        return redirect(url_for("teacher_dashboard"))

@app.route("/api/teacher/problem/<int:problem_id>/start", methods=["POST"])
@login_required
def start_problem(problem_id):
    """Activate a problem (set is_active=True)"""
    if current_user.role != "teacher":
        return jsonify({"status": "error", "error": "Unauthorized"}), 403
    
    if current_user.must_change_password:
        return jsonify({"status": "error", "error": "Password change required"}), 400
    
    try:
        # Get the problem and verify teacher owns the course
        problem = Problem.query.join(Course).filter(
            Problem.id == problem_id,
            Course.teacher_id == current_user.id
        ).first_or_404()
        
        if problem.is_active:
            return jsonify({"status": "error", "error": "Problem is already active"}), 400
        
        # Activate the problem
        problem.is_active = True
        db.session.commit()
        
        return jsonify({
            "status": "ok",
            "message": f"Problem '{problem.title}' has been activated and is now visible to students."
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/teacher/problem/<int:problem_id>/stop", methods=["POST"])
@login_required
def stop_problem(problem_id):
    """Deactivate a problem (set is_active=False)"""
    if current_user.role != "teacher":
        return jsonify({"status": "error", "error": "Unauthorized"}), 403
    
    if current_user.must_change_password:
        return jsonify({"status": "error", "error": "Password change required"}), 400
    
    try:
        # Get the problem and verify teacher owns the course
        problem = Problem.query.join(Course).filter(
            Problem.id == problem_id,
            Course.teacher_id == current_user.id
        ).first_or_404()
        
        if not problem.is_active:
            return jsonify({"status": "error", "error": "Problem is already inactive"}), 400
        
        # Deactivate the problem
        problem.is_active = False
        db.session.commit()
        
        return jsonify({
            "status": "ok",
            "message": f"Problem '{problem.title}' has been deactivated and is now hidden from students."
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route("/teacher/problem/<int:problem_id>/submissions")
@login_required
def teacher_problem_submissions(problem_id):
    """View all submissions for a specific problem with enhanced features"""
    if current_user.role != "teacher":
        return redirect(url_for("student_dashboard"))
    if current_user.must_change_password:
        flash("You must change your password before accessing submissions.", "warning")
        return redirect(url_for("change_password"))
    
    # Verify the problem belongs to this teacher
    problem = Problem.query.filter_by(id=problem_id).first_or_404()
    course = Course.query.filter_by(id=problem.course_id, teacher_id=current_user.id).first_or_404()
    
    # Get filter parameters
    score_filter = request.args.get('score_filter', 'all')
    sort_by = request.args.get('sort_by', 'latest')
    
    # Get latest submissions per student - Fixed subquery
    latest_submissions_subquery = (
        db.session.query(
            Submission.student_id,
            func.max(Submission.id).label('latest_id')  # Use max ID instead of timestamp
        )
        .filter(Submission.problem_id == problem_id)
        .group_by(Submission.student_id)
        .subquery()
    )
    
    # Get latest submissions with user data - Fixed join
    submissions_query = (
        db.session.query(Submission, User)
        .join(User, Submission.student_id == User.id)
        .join(
            latest_submissions_subquery,
            and_(
                Submission.student_id == latest_submissions_subquery.c.student_id,
                Submission.id == latest_submissions_subquery.c.latest_id  # Join on ID
            )
        )
        .filter(Submission.problem_id == problem_id)
    )
    
    # Apply score filter
    if score_filter == 'passed':
        submissions_query = submissions_query.filter(Submission.total_score >= 60)
    elif score_filter == 'failed':
        submissions_query = submissions_query.filter(Submission.total_score < 60)
    elif score_filter == 'excellent':
        submissions_query = submissions_query.filter(Submission.total_score >= 80)
    
    # Apply sorting
    if sort_by == 'latest':
        submissions_query = submissions_query.order_by(Submission.created_at.desc())
    elif sort_by == 'score_high':
        submissions_query = submissions_query.order_by(Submission.total_score.desc())
    elif sort_by == 'score_low':
        submissions_query = submissions_query.order_by(Submission.total_score.asc())
    elif sort_by == 'name':
        submissions_query = submissions_query.order_by(User.name.asc())
    
    submissions = submissions_query.all()
    
    # Get submission statistics
    total_submissions = Submission.query.filter_by(problem_id=problem_id).count()
    unique_students = len(set(sub.student_id for sub, user in submissions))
    
    # FIXED: Calculate average score from latest submissions (not best submissions)
    avg_score = 0
    if submissions:
        # Calculate average from latest submissions
        total_score = sum(sub.total_score for sub, user in submissions if sub.total_score is not None)
        avg_score = total_score / len(submissions) if submissions else 0
    
    # Get best submissions per student (only with score > 0) - For display purposes
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
    
    # Get the actual best submissions with latest ID for ties
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
    
    # Get all students enrolled in the course
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
    
    # Get currently logged in students (online in last 30 minutes)
    cutoff_time = datetime.utcnow() - timedelta(minutes=60)
    logged_in_students = User.query.filter(
        User.id.in_([student.id for student in enrolled_students]),
        User.is_online == True,
        User.last_activity >= cutoff_time
    ).count()
    
    # Find students who haven't submitted
    submitted_student_ids = set(sub.student_id for sub, user in submissions)
    not_submitted_students = [student for student in enrolled_students if student.id not in submitted_student_ids]
    
    return render_template(
        "teacher_problem_submissions.html",
        problem=problem,
        course=course,
        submissions=submissions,
        best_submissions=best_submissions_query,
        total_submissions=total_submissions,
        unique_students=unique_students,
        avg_score=avg_score,
        not_submitted_students=not_submitted_students,
        enrolled_count=len(enrolled_students),
        logged_in_count=logged_in_students,
        current_filter=score_filter,
        current_sort=sort_by,
        can_download_solution=problem.can_download_solution
    )





@app.template_filter('fromjson')
def fromjson_filter(json_str):
    """Parse JSON string to Python object"""
    try:
        if json_str is None or json_str == '':
            return []
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return []
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
