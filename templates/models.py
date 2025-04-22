from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    role = db.Column(db.String(20), nullable=False)  # 'admin' or 'employee'
    full_name = db.Column(db.String(150), nullable=True)  # Full name
    faculty = db.Column(db.String(150), nullable=True)  # Faculty
    position = db.Column(db.String(150), nullable=True)  # Position
    photo = db.Column(db.String(200), nullable=True)  # Profile photo filename
