# Local Encrypted Email System (GnuPG Edition)

**Version:** 1.0 (GnuPG Backend)

## 1. Overview

This application provides a **minimalist, local-only email system** built with the Flask web framework for Python. It allows registered users within the system to send messages to each other. The key feature is the integration with **GnuPG (GPG)**, enabling users to optionally encrypt messages using the recipient's public GPG key.

**Key Characteristics & Limitations:**

*   **Local System:** This system **does not** connect to the internet or external email servers (like Gmail, Outlook). It only facilitates communication between users registered *within this specific application instance*.
*   **GnuPG Dependency:** Requires GnuPG to be installed and correctly configured on the system running the Flask application.
*   **External Key Management:** Users are responsible for generating and managing their own GPG key pairs using standard GPG tools. The application only stores the public key fingerprint and imports the public key block into its own operational keyring.
*   **Decryption Model (Security Critical):** For a user to view an encrypted email, the Flask application process must have access to that user's corresponding **private GPG key** via the system's GnuPG setup (e.g., through `gpg-agent` caching the passphrase or using an unprotected key). **This model is suitable only for single-user local execution or trusted environments and is inherently insecure for typical multi-user web server deployments.**
*   **Minimalist UI:** Features a simple, dark-themed web interface.

---

## 2. Features

*   User Registration
*   User Login / Logout (Session-based)
*   User Profile Management (Associating a GPG public key with the account)
*   Email Composition (To other registered users)
*   Optional GPG Encryption (Per message, requires recipient to have a registered key)
*   Inbox (View received messages)
*   Sent Items (View sent messages)
*   Email Viewing (Automatic decryption attempt for GPG-encrypted messages if recipient)

---

## 3. Technology Stack

*   **Backend:** Python 3 (Tested with 3.11+)
*   **Framework:** Flask
*   **Database:** SQLite (via Flask-SQLAlchemy)
*   **Authentication:** Flask-Login
*   **Encryption:** GnuPG (external dependency) via `python-gnupg` library
*   **Templating:** Jinja2
*   **Frontend:** HTML, CSS (minimalist dark theme)

---

## 4. Prerequisites

Before installing and running the application, ensure you have the following installed on your system (Linux/WSL recommended, macOS/Windows possible with GPG setup):

1.  **Python:** Version 3.11 or later is recommended.
2.  **Pip:** Python package installer (usually comes with Python).
3.  **Virtual Environment Tool:** `venv` (built into Python 3).
4.  **GnuPG (GPG):** The GnuPG software suite must be installed and runnable from the command line (test with `gpg --version`).
5.  **(Linux/WSL Build Only)** If `pip` needs to build `python-gnupg` or other dependencies from source:
    *   `build-essential` (provides C/C++ compiler like `gcc`)
    *   `python3-dev` (provides Python C header files)
    *   Install using your package manager (e.g., `sudo apt update && sudo apt install build-essential python3-dev` on Debian/Ubuntu).

---

## 5. Installation and Setup

1.  **Clone or Download:** Obtain the project files (e.g., using `git clone` or downloading a zip).
2.  **Navigate to Directory:** Open your terminal or command prompt and change into the project's root directory (e.g., `cd local_email_system`).
3.  **Create Virtual Environment:**
    ```bash
    python3 -m venv venv
    # Or on Windows: python -m venv venv
    ```
4.  **Activate Virtual Environment:**
    *   **Linux/macOS:** `source venv/bin/activate`
    *   **Windows (cmd):** `.\venv\Scripts\activate.bat`
    *   **Windows (PowerShell):** `.\venv\Scripts\Activate.ps1`
    *   > You should see `(.venv)` at the beginning of your prompt.
5.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
6.  **Generate GPG Keys (Users):** Ensure each user who will use the system has generated their own GPG key pair using `gpg --full-generate-key`. They will need to export their *public* key later.
7.  **Configure Environment Variables:**
    *   **`SECRET_KEY` (Mandatory):** Set a strong, random secret key for Flask session security.
        ```bash
        # Linux/macOS Example:
        export SECRET_KEY='your_super_secret_random_string_here'

        # Windows PowerShell Example:
        $env:SECRET_KEY='your_super_secret_random_string_here'
        ```
    *   **`GPG_BINARY` (Optional):** Set the full path to the `gpg` executable if it's not in your system's PATH.
        ```bash
        # Example:
        export GPG_BINARY='/usr/bin/gpg'
        ```
    *   **`GPG_HOME` (Optional):** Set the path to the GPG home directory the application should use. If not set, `python-gnupg` usually defaults to the user's standard GPG directory (e.g., `~/.gnupg`). Using a separate directory for the app can isolate its keyring but requires managing key imports into that specific directory.
        ```bash
        # Example using default:
        # (Leave unset)

        # Example using custom:
        export GPG_HOME='/path/to/app-gpg-keyring'
        ```
8.  **Initialize Database:** The database file (`app.db`) and tables will be created automatically the first time the application runs, triggered by the `init_db(app)` call within `app.py`.
9.  **Run the Server:**
    ```bash
    flask run
    ```
    > *(For development, `flask run` is fine. For different deployment scenarios, use a production WSGI server like Gunicorn or Waitress).*
10. **Access:** Open your web browser and navigate to `http://127.0.0.1:5000` (or the address provided by Flask).

---

## 6. Configuration

Application configuration is handled via the `Config` class in `config.py` and environment variables:

*   `SECRET_KEY`: **Crucial for security.** Should be a long, random, unpredictable string. Best set via environment variable.
*   `SQLALCHEMY_DATABASE_URI`: Defines the database connection. Defaults to a SQLite file named `app.db` in the project's base directory.
*   `GPG_BINARY`: Overrides the default path detection for the `gpg` executable. Set via environment variable `GPG_BINARY`.
*   `GPG_HOME`: Overrides the default GPG home directory (`~/.gnupg`). Set via environment variable `GPG_HOME`.

---

## 7. Usage Guide

1.  **Registration:**
    *   Navigate to `/register`.
    *   Enter a unique username and a password (with confirmation).
    *   Upon success, you'll be redirected to log in. You still need to add your GPG key via the Profile page.
2.  **Login:**
    *   Navigate to `/login`.
    *   Enter your registered username and password.
    *   Upon success, you'll be redirected to your Inbox.
3.  **Profile & GPG Key:**
    *   After logging in, click the "Profile/GPG Key" link in the navbar.
    *   To receive encrypted emails, you MUST associate your GPG public key.
    *   **Export your Public Key:** Open your terminal and run `gpg --export --armor YOUR_EMAIL_OR_KEYID` (replace with the identifier for your key).
    *   **Copy Key Block:** Copy the *entire* text output, including the `-----BEGIN...` and `-----END...` lines.
    *   **Paste and Import:** Paste the copied block into the text area on the Profile page and click "Import Key".
    *   If successful, your GPG key fingerprint will be displayed. The application has now imported your public key into its keyring and linked the fingerprint to your account.
4.  **Composing Email:**
    *   Click "Compose" in the navbar.
    *   Select a registered user from the "Recipient" dropdown.
    *   Enter a Subject and Body.
    *   **Encryption:**
        *   To send **plaintext**, leave the "Encrypt with GPG" box unchecked.
        *   To send **encrypted**, check the "Encrypt with GPG" box. This requires the selected recipient to have already registered their GPG key via their profile. If they haven't, sending will likely fail or be prevented.
    *   Click "Send Email".
5.  **Viewing Emails (Inbox/Sent):**
    *   Navigate to "Inbox" or "Sent" via the navbar.
    *   Emails are listed with sender/recipient, subject, date, and encryption type ('None' or 'GPG').
    *   Click an email's subject to view its content.
6.  **Viewing Email Content:**
    *   **Plaintext:** The message body is displayed directly.
    *   **GPG Encrypted (as Recipient):** The application automatically attempts to decrypt the message using the GnuPG instance.
        *   **Success:** The decrypted plaintext is shown. This requires your private key to be available and unlocked (e.g., via `gpg-agent`).
        *   **Failure:** An error message like `[GPG Decryption Failed: ...]` is shown, often followed by the raw encrypted block. See Troubleshooting section.
    *   **GPG Encrypted (as Sender):** You cannot decrypt messages encrypted for someone else. The view will show a placeholder indicating the message is encrypted and who it's for.

---

## 8. GnuPG Integration Details

*   **Key Storage:** The application **does not** store user private keys. It only stores the 40-character **fingerprint** of the user's GPG key in the database (`user.gpg_fingerprint`). When a user uploads their public key block via the profile, the application uses `python-gnupg` to import this public key into the GPG keyring being used by the application process (controlled by `GPG_HOME` or the system default).
*   **Encryption:** When sending an encrypted message, the app looks up the recipient's fingerprint from the database, confirms the corresponding public key exists in its keyring, and calls `gpg.encrypt()` targeting that fingerprint.
*   **Decryption:** When viewing an encrypted message as the recipient, the app calls `gpg.decrypt()` on the stored encrypted block. This call relies entirely on the external GPG setup: GPG must find the correct private key (associated with the key ID embedded in the encrypted message) within the keyring it's configured to use and must be able to unlock it if necessary (typically via `gpg-agent`). **The Flask app does not handle passphrases directly.**

---

## 9. Security Considerations

> **Warning:** This application is designed primarily for local execution and educational purposes. Apply standard web security practices if adapting for wider use.

*   **LOCAL SYSTEM ONLY:** This application is designed for local testing or trusted environments. It lacks many security features of production web applications and does not interact with the public internet email system.
*   **GPG PRIVATE KEY ACCESS (CRITICAL):** The biggest security consideration. For decryption to work, the **Flask application process must effectively have access to the users' private GPG keys**. In a typical web server scenario where one Flask process serves multiple users, this is extremely dangerous, as a compromise of the server process could expose all accessible private keys. **Only run this in environments where this access model is understood and accepted (e.g., the user running the Flask app *is* the owner of the GPG key being used).**
*   **SECRET_KEY:** Protect your `SECRET_KEY` environment variable. If compromised, attackers could forge session cookies and potentially log in as any user.
*   **Input Sanitization:** Basic measures are taken (like `strip()`), but a production application would need much more rigorous input validation and output escaping to prevent XSS and other attacks.
*   **No Email Verification:** The system assumes usernames map to trusted local entities. There is no verification step like in public email systems.
*   **Dependencies:** Keep Flask, `python-gnupg`, and other dependencies updated to patch security vulnerabilities. Keep GnuPG itself updated.

---

## 10. Troubleshooting

*   **GPG Initialization Failed (`FileNotFoundError`, `expected str...`):**
    *   Verify GnuPG is installed (`gpg --version`).
    *   Ensure `gpg` is in the system PATH or set `GPG_BINARY` env var correctly.
    *   Check permissions and existence if using a custom `GPG_HOME`.
*   **GPG Key Import Failed:**
    *   Check you copied the *entire* public key block (`-----BEGIN...` to `-----END...`).
    *   Ensure you didn't paste the *private* key.
    *   Check Flask logs for detailed errors from GnuPG.
*   **GPG Decryption Failed:**
    *   Is `gpg-agent` running and configured?
    *   Is the required private key in the keyring used by the Flask app? (`gpg --list-secret-keys`).
    *   If key is passphrase protected, is it unlocked? Try a manual GPG operation (`echo "test" | gpg -u YOUR_KEY_ID --clearsign`) to cache the passphrase via the agent.
    *   Check Flask logs for specific errors from `gpg.decrypt()`.
*   **"Recipient has not registered a GPG key" error during Compose:** Recipient needs to log in and add their key via `/profile`.

---

## 11. Future Enhancements

*   Reply functionality (pre-filling recipient/subject).
*   Support for attachments (potentially GPG-encrypted).
*   Improved UI feedback and asynchronous operations.
*   More robust error handling and user guidance.
*   Key server integration (optional fetching of public keys).
*   (Major) Re-architecting decryption for a more secure multi-user model (e.g., client-side decryption).

---

## 12. File Structure
/local_email_system
├── .venv/ # Virtual environment directory
├── static/
│ └── css/
│ └── style.css # Stylesheet
├── templates/
│ ├── base.html # Base template
│ ├── login.html
│ ├── register.html
│ ├── index.html # Inbox
│ ├── compose.html
│ ├── sent.html
│ ├── view_email.html
│ ├── profile.html # GPG Key Management page
│ └── _flash_messages.html # Partial for flash messages
├── app.py # Main Flask application logic, routes
├── config.py # Configuration settings
├── database.py # Database models (User, Email), init function
├── gnupg_helper.py # Helper functions for GnuPG interactions
├── requirements.txt # Python dependencies
└── app.db # SQLite database file (created on first run)
