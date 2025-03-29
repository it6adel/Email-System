# database.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import func

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    # Store the GPG Key Fingerprint (unique identifier)
    gpg_fingerprint = db.Column(db.String(40), nullable=True, unique=True, index=True)

    # Relationships for sent and received emails
    sent_emails = db.relationship('Email', foreign_keys='Email.sender_id', backref='sender', lazy='dynamic')
    received_emails = db.relationship('Email', foreign_keys='Email.recipient_id', backref='recipient', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(120), nullable=False)
    # Stores GPG encrypted block (ASCII armored) or plaintext
    body = db.Column(db.Text, nullable=False)
    # 'GPG' or 'None'
    encryption_type = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f'<Email {self.id} from {self.sender_id} to {self.recipient_id}>'

def init_db(app):
    """Initializes the database (creates tables if they don't exist)."""
    # Use app.app_context() to ensure the application context is active
    # for database operations during initialization.
    with app.app_context():
        db.create_all() # This is idempotent, only creates tables not already present
    print("Database initialized (tables created if they didn't exist).")