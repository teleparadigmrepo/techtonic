# Updated models.py with new fields and relationships

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from flask_login import UserMixin
from datetime import datetime, timezone
import pytz
import secrets
import json

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'teacher', or 'student'
    name = db.Column(db.String(200))  # Full name for students
    htno = db.Column(db.String(50))  # Hall ticket number for students
    status = db.Column(db.String(20), default='active')  # 'active' or 'inactive'
    must_change_password = db.Column(db.Boolean, default=False)
    password_changed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Session management fields
    session_token = db.Column(db.String(200), default=lambda: secrets.token_urlsafe(32))
    force_logout_at = db.Column(db.DateTime)  # When user was force logged out
    
    # Login tracking fields
    last_login = db.Column(db.DateTime)
    current_login = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0)
    is_online = db.Column(db.Boolean, default=False)  # NEW: Track online status
    last_activity = db.Column(db.DateTime)  # NEW: Track last activity
    
    # Relationships
    submissions = db.relationship('Submission', backref='student', lazy=True)
    taught_courses = db.relationship('Course', backref='teacher', lazy=True)
    created_problems = db.relationship('Problem', backref='creator', lazy=True)
    
    def invalidate_session(self):
        """Generate new session token to invalidate current sessions"""
        self.session_token = secrets.token_urlsafe(32)
        self.force_logout_at = datetime.utcnow()
        db.session.commit()
    
    def update_login_info(self):
        """Update login timestamps and count"""
        self.last_login = self.current_login
        self.current_login = datetime.utcnow()
        self.login_count = (self.login_count or 0) + 1
        self.is_online = True
        self.last_activity = datetime.utcnow()
        db.session.commit()
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()
        db.session.commit()
    
    def set_offline(self):
        """Set user as offline"""
        self.is_online = False
        db.session.commit()

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    groups = db.relationship('Group', backref='course', lazy=True, cascade='all, delete-orphan')
    problems = db.relationship('Problem', backref='course', lazy=True)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    student_groups = db.relationship('StudentGroup', backref='group', lazy=True, cascade='all, delete-orphan')
    
    @property
    def students(self):
        return [sg.student for sg in self.student_groups]

class StudentGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    student = db.relationship('User', backref='student_groups')
    
    # Unique constraint
    __table_args__ = (db.UniqueConstraint('student_id', 'group_id', name='unique_student_group'),)

class Problem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    statement = db.Column(db.Text, nullable=False)
    topics = db.Column(db.Text, nullable=False)  # JSON list
    rubric = db.Column(db.Text, nullable=False)  # JSON dict
    pills = db.Column(db.Text)  # JSON list
    prompt = db.Column(db.Text)  # Generated evaluator prompt
    solution = db.Column(db.Text)  # Generated solution JSON
    doc_path = db.Column(db.String(300))  # Path to uploaded PDF
    video_url = db.Column(db.String(300))  # YouTube URL
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=False)
    can_download_solution= db.Column(db.Boolean, default=False)
    # NEW: Problem timing fields
    start_date = db.Column(db.DateTime)  # When problem becomes available
    end_date = db.Column(db.DateTime)    # When problem closes
    
    # Relationships
    submissions = db.relationship('Submission', backref='problem', lazy=True)
    
    @property
    def current_state(self):
        """Get current state of the problem"""
        now = datetime.utcnow()
        if not self.is_active:
            return 'inactive'
        if self.start_date and now < self.start_date:
            return 'pending'
        if self.end_date and now > self.end_date:
            return 'stopped'
        return 'active'


class Submission(db.Model):
    __tablename__ = 'submission'
    __table_args__ = (
        db.Index('ix_submission_user_problem', 'student_id', 'problem_id'),
        db.Index('ix_submission_created_at', 'created_at'),
    )

    id           = db.Column(db.Integer, primary_key=True)
    student_id   = db.Column(db.Integer, db.ForeignKey('user.id'),    nullable=False)
    problem_id   = db.Column(db.Integer, db.ForeignKey('problem.id'), nullable=False)
    solution     = db.Column(db.Text,   nullable=False)
    scores       = db.Column(db.Text)   # JSON dict of scores
    feedback     = db.Column(db.Text)   # JSON list of feedback
    total_score  = db.Column(db.Float)
    attempt      = db.Column(db.Integer, default=1)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

