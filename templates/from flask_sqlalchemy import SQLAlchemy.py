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



from datetime import datetime
from sqlalchemy import Enum

class Zayavka(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)  # Equipment or Repair
    description = db.Column(db.Text, nullable=False)
    status = db.Column(
        db.String(20),
        default='ожидает',
        nullable=False
    )  # Default status
    created_at = db.Column(db.DateTime, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file = db.Column(db.String(200), nullable=True)
    user = db.relationship('User', backref=db.backref('zayavki', lazy=True))
    comment = db.Column(db.Text, nullable=True)  # User comment
    rating = db.Column(db.Integer, nullable=True)  # User rating (1-5)
    confirmed_by_user = db.Column(db.Boolean, default=False)  # User confirmation for archive

    def set_status(self, new_status):
        valid_statuses = ['ожидает', 'принято', 'сделано', 'отказано']
        if new_status.lower() not in valid_statuses:
            raise ValueError(f"Invalid status: {new_status}")
        self.status = new_status.lower()

class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    zayavka_id = db.Column(db.Integer, db.ForeignKey('zayavka.id'), nullable=True)
    user = db.relationship('User', backref=db.backref('actions', lazy=True))
    zayavka = db.relationship('Zayavka', backref=db.backref('actions', lazy=True))