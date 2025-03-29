# config.py
import os

# BASE_DIR defined at the module level
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Secret key is essential for sessions and Flask-Login
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-insecure-default-key-change-me' # CHANGE THIS!

    # Database configuration (SQLite file in the base directory)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(BASE_DIR, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Optional: Specify GPG executable path and home directory
    # If None, python-gnupg tries to find them automatically.
    # Set these if gpg isn't in your PATH or you want a specific keyring.
    # Example Env Vars:
    # export GPG_BINARY='/usr/bin/gpg'
    # export GPG_HOME='/home/user/.gnupg'
    GPG_BINARY = os.environ.get('GPG_BINARY') # e.g., 'C:/Program Files (x86)/GnuPG/bin/gpg.exe' or '/usr/bin/gpg'
    GPG_HOME = os.environ.get('GPG_HOME')     # e.g., os.path.join(BASE_DIR, '.gnupg-app-keyring') or None to use default user keyring