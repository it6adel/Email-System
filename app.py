
import os
import sys 
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from urllib.parse import urlparse

# Assuming config.py is in the same directory
from config import Config
from database import db, User, Email, init_db
# Import the GPG helper module
import gnupg_helper

# --- App Initialization ---
app = Flask(__name__)
app.config.from_object(Config)
# Use Flask's built-in logger
app.logger.setLevel(os.environ.get('FLASK_LOG_LEVEL', 'INFO'))

# --- Initialize GPG ---
gpg = None 
gpg_init_args = {} 

# Get potential paths from config (which reads from environment variables)
gpg_binary_path = app.config.get('GPG_BINARY')
gpg_home_path = app.config.get('GPG_HOME')


if gpg_binary_path:
    app.logger.info(f"Using GPG_BINARY from config: {gpg_binary_path}")
    gpg_init_args['gpgbinary'] = gpg_binary_path
if gpg_home_path:
    app.logger.info(f"Using GPG_HOME from config: {gpg_home_path}")
    gpg_init_args['gnupghome'] = gpg_home_path



try:
    # Pass arguments using dictionary unpacking (**).
    # If dict is empty, no optional args are passed to initialize_gpg.
    gpg = gnupg_helper.initialize_gpg(**gpg_init_args)
except Exception as e:
    # Log the critical failure but allow app to continue (GPG features will fail)
    app.logger.critical(f"CRITICAL: GPG failed to initialize during app startup: {e}. Encryption/decryption will fail.")
    
# --- End GPG Initialization ---


# --- Database Setup ---
db.init_app(app)
# Call init_db to ensure tables are created within app context
init_db(app)


# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Route name for the login page
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
@app.route('/index')
@app.route('/inbox')
@login_required
def index():
    """Inbox view."""
    emails = Email.query.filter_by(recipient_id=current_user.id).order_by(Email.timestamp.desc()).all()
    return render_template('index.html', title='Inbox', emails=emails, box_type='Inbox')

@app.route('/sent')
@login_required
def sent():
    """Sent items view."""
    emails = Email.query.filter_by(sender_id=current_user.id).order_by(Email.timestamp.desc()).all()
    return render_template('sent.html', title='Sent Items', emails=emails, box_type='Sent')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember_me') is not None

        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

        login_user(user, remember=remember)
        app.logger.info(f"User '{username}' logged in successfully.")
        flash(f'Welcome back, {user.username}!', 'success')

        next_page = request.args.get('next')
        # Security check: Ensure next_page is internal
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)

    return render_template('login.html', title='Login')

@app.route('/logout')
@login_required
def logout():
    app.logger.info(f"User '{current_user.username}' logged out.")
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password2 = request.form.get('password2')

        
        if not username or not password or not password2:
             flash('All fields are required!', 'warning')
             return redirect(url_for('register'))
        if password != password2:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already taken. Please choose another.', 'warning')
            return redirect(url_for('register'))

        # Create new user (no GPG key association yet)
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        try:
            db.session.commit()
            app.logger.info(f"New user '{username}' registered successfully.")
            flash(f'Registration successful for {username}. Please log in and add your GPG key via Profile.', 'success')
            return redirect(url_for('login')) # Redirect to login after successful registration
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {e}', 'danger')
            app.logger.error(f"Database error during registration for '{username}': {e}", exc_info=True)
            return redirect(url_for('register'))

    # GET request
    return render_template('register.html', title='Register')

# Route to manage GPG key association
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        public_key_data = request.form.get('gpg_public_key')
        if not public_key_data or not public_key_data.strip():
            flash('Please paste your GPG public key block.', 'warning')
            return redirect(url_for('profile'))

        # Check if GPG service is available before proceeding
        if not gpg:
             flash('GPG Service is not available. Cannot import key at this time.', 'danger')
             return redirect(url_for('profile'))

        try:
            # Attempt to import the provided key data
            fingerprint, message = gnupg_helper.import_key(gpg, public_key_data)

            if fingerprint:
                app.logger.info(f"Attempting to associate fingerprint {fingerprint} with user {current_user.username}")
                # Check if this fingerprint is already linked to a *different* user
                existing_user = User.query.filter(User.gpg_fingerprint == fingerprint, User.id != current_user.id).first()
                if existing_user:
                    flash(f'Error: This GPG key fingerprint ({fingerprint[:16]}...) is already associated with user "{existing_user.username}". Keys must be unique.', 'danger')
                    app.logger.warning(f"User {current_user.username} tried to register fingerprint {fingerprint} already used by {existing_user.username}")
                else:
                    # Update the current user's fingerprint
                    current_user.gpg_fingerprint = fingerprint
                    db.session.commit()
                    flash(f'GPG key imported and associated successfully! Fingerprint: {fingerprint}', 'success')
                    app.logger.info(f"Successfully associated fingerprint {fingerprint} with user {current_user.username}")
            else:
                # Import failed, message contains details from gnupg_helper
                flash(f'GPG Key import failed: {message}', 'danger')
                app.logger.warning(f"GPG key import failed for user {current_user.username}. Reason: {message}")

        except Exception as e:
            db.session.rollback() # Rollback DB changes on any unexpected error
            flash(f'An unexpected error occurred while importing the key: {e}', 'danger')
            app.logger.error(f"Unexpected GPG Key import error for user {current_user.username}: {e}", exc_info=True)

        return redirect(url_for('profile'))

    # GET request shows the profile page
    return render_template('profile.html', title='Profile')


@app.route('/compose', methods=['GET', 'POST'])
@login_required
def compose():
    # GET request: Show compose form with list of potential recipients
    if request.method == 'GET':
        users = User.query.filter(User.id != current_user.id).order_by(User.username).all()
        return render_template('compose.html', title='Compose', users=users)

    # POST request: Handle form submission
    recipient_username = request.form.get('recipient')
    subject = request.form.get('subject', '').strip() # Default to empty string and strip whitespace
    body = request.form.get('body', '').strip()
    encrypt = request.form.get('encrypt_gpg') == 'on' # Checkbox value

    # Basic validation
    if not recipient_username or not subject or not body:
         flash('Recipient, Subject, and Body are required.', 'warning')
         # Re-populate users for the form on error
         users = User.query.filter(User.id != current_user.id).order_by(User.username).all()
         # Pass back the entered data to re-populate the form
         return render_template('compose.html', title='Compose', users=users, s_recipient=recipient_username, s_subject=subject, s_body=body, s_encrypt=encrypt)

    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        flash(f'Recipient user "{recipient_username}" not found.', 'danger')
        users = User.query.filter(User.id != current_user.id).order_by(User.username).all()
        return render_template('compose.html', title='Compose', users=users, s_recipient=recipient_username, s_subject=subject, s_body=body, s_encrypt=encrypt)

    if recipient.id == current_user.id:
        flash('You cannot send an email to yourself using this system.', 'warning')
        users = User.query.filter(User.id != current_user.id).order_by(User.username).all()
        return render_template('compose.html', title='Compose', users=users, s_recipient=recipient_username, s_subject=subject, s_body=body, s_encrypt=encrypt)

    # Prepare email data
    email_body_to_store = body
    encryption_type = 'None'

    if encrypt:
        # Check GPG service availability
        if not gpg:
             flash('GPG Service is not available. Cannot encrypt message.', 'danger')
             return redirect(url_for('compose')) # Or render template with error

        # Check if recipient has a registered GPG key
        if not recipient.gpg_fingerprint:
            flash(f'Recipient "{recipient.username}" has not registered a GPG key. Cannot send encrypted message.', 'warning')
            users = User.query.filter(User.id != current_user.id).order_by(User.username).all()
            return render_template('compose.html', title='Compose', users=users, s_recipient=recipient_username, s_subject=subject, s_body=body, s_encrypt=encrypt)

        try:
            # Encrypt using the helper function and recipient's fingerprint
            email_body_to_store = gnupg_helper.encrypt_message(gpg, body, recipient.gpg_fingerprint)
            encryption_type = 'GPG'
            app.logger.info(f"Message from {current_user.username} to {recipient.username} encrypted with GPG.")
            flash(f'Email will be sent encrypted with GPG to {recipient.username}.', 'info') # Give feedback before commit
        except Exception as e:
            flash(f'An error occurred during GPG encryption: {e}', 'danger')
            app.logger.error(f"GPG Encryption error from {current_user.username} to {recipient.username}: {e}", exc_info=True)
            # Re-show form on encryption error
            users = User.query.filter(User.id != current_user.id).order_by(User.username).all()
            return render_template('compose.html', title='Compose', users=users, s_recipient=recipient_username, s_subject=subject, s_body=body, s_encrypt=encrypt)

    # Save the email (encrypted or plaintext) to the database
    try:
        email = Email(
            sender_id=current_user.id,
            recipient_id=recipient.id,
            subject=subject,
            body=email_body_to_store,
            encryption_type=encryption_type,
        )
        db.session.add(email)
        db.session.commit()
        app.logger.info(f"Email (ID: {email.id}) from {current_user.username} to {recipient.username} saved (Enc: {encryption_type}).")
        flash(f'Email sent successfully to {recipient.username}.', 'success')
        return redirect(url_for('sent'))
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while saving the email to the database: {e}', 'danger')
        app.logger.error(f"Database error saving email from {current_user.username} to {recipient.username}: {e}", exc_info=True)
        # Re-show form on DB error
        users = User.query.filter(User.id != current_user.id).order_by(User.username).all()
        return render_template('compose.html', title='Compose', users=users, s_recipient=recipient_username, s_subject=subject, s_body=body, s_encrypt=encrypt)


@app.route('/view/<int:email_id>')
@login_required
def view_email(email_id):
    email = Email.query.get_or_404(email_id)

    # Ensure the current user is either the sender or the recipient
    if email.sender_id != current_user.id and email.recipient_id != current_user.id:
        flash('You do not have permission to view this email.', 'danger')
        return redirect(url_for('index'))

    decrypted_body = "[Failed to process email content]" # Default error
    is_recipient = (email.recipient_id == current_user.id)

    if email.encryption_type == 'None':
        decrypted_body = email.body
        app.logger.debug(f"Viewing plaintext email ID: {email_id}")
    elif email.encryption_type == 'GPG':
        if is_recipient:
            app.logger.debug(f"Attempting decryption for email ID: {email_id} by recipient {current_user.username}")
            if not gpg:
                decrypted_body = "[GPG Service unavailable - Cannot decrypt]"
                flash("Cannot decrypt: GPG service is not running.", "warning")
            else:
                # !!! SECURITY ASSUMPTION !!!
                # Relies on user's private key being accessible to the GPG instance
                # (via gpg-agent or unlocked key) without explicit passphrase input here.
                try:
                    # Passphrase is None, relying on external handling (e.g., gpg-agent)
                    decrypted_body = gnupg_helper.decrypt_message(gpg, email.body, passphrase=None)
                    app.logger.info(f"Successfully decrypted email ID: {email_id} for user {current_user.username}")
                except Exception as e:
                    # Provide the error message and show the encrypted block for debugging
                    error_message = f"[GPG Decryption Failed: {e}]"
                    decrypted_body = f"{error_message}\n\n-----Encrypted Content-----\n{email.body}"
                    app.logger.warning(f"GPG Decryption failed for user {current_user.username}, email {email_id}: {e}", exc_info=True) # Log traceback
                    flash(f"Failed to decrypt message. Error: {e}. Ensure your GPG key is available and unlocked.", "warning")
        else: # Sender viewing GPG encrypted email
            decrypted_body = f"[Encrypted with GPG for {email.recipient.username} - Only the recipient can decrypt]\n\n-----BEGIN PGP MESSAGE-----\n{email.body[:200]}...\n-----END PGP MESSAGE-----"
            app.logger.debug(f"Sender {current_user.username} viewing GPG encrypted email ID: {email_id}")
    else:
        decrypted_body = f"[Unknown or unsupported encryption type: {email.encryption_type}]"
        app.logger.error(f"Encountered unknown encryption type '{email.encryption_type}' for email ID: {email_id}")


    return render_template('view_email.html', title=f"View Email: {email.subject}", email=email, decrypted_body=decrypted_body, is_recipient=is_recipient)

# --- Run the App ---
if __name__ == '__main__':
    # You might want to add a check here if GPG is absolutely critical
    if gpg is None:
         app.logger.warning("GPG failed to initialize during startup. Running without GPG capabilities.")
         # For development, maybe allow running without GPG:
         # if os.environ.get("FLASK_ENV") != "development-no-gpg":
         #    print("ERROR: GPG failed to initialize. Set FLASK_ENV=development-no-gpg to run without GPG (encryption/decryption will fail).", file=sys.stderr)
         #    sys.exit(1) # Or exit
    # Use debug=True only for development
    # Use host='0.0.0.0' to make it accessible on your network (use with caution)
    app.run(debug=True, host='127.0.0.1') # host='127.0.0.1' is default and safer