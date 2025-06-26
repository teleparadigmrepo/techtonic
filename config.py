# config.py
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Flask settings
SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret')
SQLALCHEMY_DATABASE_URI = os.getenv(
    'DATABASE_URL',
    'mysql+pymysql://root:root@localhost/techtonic'
)
SQLALCHEMY_TRACK_MODIFICATIONS = False

# OpenAI settings
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
OPENAI_MODEL     = os.getenv('OPENAI_MODEL', 'o3-mini-2025-01-31')

# Uploads
UPLOAD_FOLDER     = os.path.join(BASE_DIR, 'static', 'uploads', 'docs')
ALLOWED_EXTENSIONS = {'pdf'}
