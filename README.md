<!-- Project Title -->
# Techtonic

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)  
[![Flask](https://img.shields.io/badge/flask-2.0-green)](https://flask.palletsprojects.com/)    
[![First Commit](https://img.shields.io/badge/first%20commit-26%20Jun%202025-orange)](https://github.com/teleparadigmrepo/techtonic/commit)

> **Techtonic** — a role-based, AI-powered learning platform  
> Developed by **Teleparadigm**  
> First commit: **26 June 2025**

---

## 🚀 Features

- **Role-Based Access**  
  - **Admin**: onboard users, create courses & groups, bulk-import students, manage roles, view global dashboard  
  - **Teacher**: author & toggle AI-augmented problems, generate solutions & “knowledge pills,” export PDFs, reset sessions, review analytics  
  - **Student**: enroll in groups, solve problems (max 3 attempts), receive instant AI feedback, track progress  

- **AI Integration**  
  - Automated evaluation & scoring via OpenAI GPT  
  - Structured solution JSON & downloadable PDFs  
  - HTML “knowledge pills” for bite-sized learning  

- **Security & Session Control**  
  - Passwords hashed with Werkzeug  
  - Per-user session tokens for forced logout  
  - CSRF protection, secure file uploads, strict role checks  

- **Analytics & Reporting**  
  - Per-problem and per-course performance metrics  
  - Real-time login status (last 30 min) for live classroom oversight  

---

## 📦 Installation

1. **Clone the repo**  
   ```bash
   git clone https://github.com/teleparadigmrepo/techtonic.git
   cd techtonic
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt


  ```techtonic/
  ├── app.py                      # Main Flask application
  ├── config.py                   # Configuration & env loading
  ├── models.py                   # SQLAlchemy models
  ├── templates/                  # Jinja2 templates
  ├── static/                     # CSS, JS, images
  ├── migrations/                 # Flask-Migrate files
  └── requirements.txt            # Python dependencies


🎓 Usage Examples

    Admin

        /admin/dashboard → overview of users, courses, groups

        /admin/bulk_create_users → paste CSV of htno,name,password

    Teacher

        /teacher/create-problem → define new problem (inactive by default)

        /teacher/problem/<id>/toggle → publish/unpublish instantly

        /api/generate_solution → AJAX call for GPT-powered solution

    Student

        /student/dashboard → view assigned problems

        /student/solve/<pid> → submit answer (max 3 attempts)

        Instant feedback & downloadable solution PDF
