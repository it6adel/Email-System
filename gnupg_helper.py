# gnupg_helper.py
import gnupg
import logging
import os # Import os for path checks if needed, though not strictly used in this version

# Configure logging for GnuPG interactions
# Set level to DEBUG for detailed GPG command info, WARNING for less noise
logging.basicConfig(level=logging.INFO) # Set base config for logging
log = logging.getLogger(__name__) # Get logger for this module
logging.getLogger("gnupg").setLevel(logging.WARNING) # Keep GPG lib logs less verbose unless debugging

# Accept keyword arguments, default to None if not provided
def initialize_gpg(gnupghome=None, gpgbinary=None, verbose=False):
    """
    Initializes and returns a GPG instance using python-gnupg.
    Handles optional specification of gnupghome and gpgbinary paths.
    """
    log.info(f"Attempting to initialize GPG...")
    log.info(f"Requested GPG Home: {gnupghome}")
    log.info(f"Requested GPG Binary: {gpgbinary}")

    try:
        # Pass the arguments directly to the GPG constructor
        # python-gnupg should handle None values reasonably by trying defaults
        gpg = gnupg.GPG(gnupghome=gnupghome, gpgbinary=gpgbinary, verbose=verbose)
        gpg.encoding = 'utf-8' # Ensure consistent encoding

        # Test listing keys to confirm GPG is working and get version
        version_info = gpg.version
        log.info(f"GPG initialized successfully. Version: {version_info}")
        # Use gpg.gnupghome which reports the actual path being used by the library
        log.info(f"Using GPG Home Directory: {gpg.gnupghome}")
        return gpg

    except FileNotFoundError:
        # This specific error occurs if the GPG executable itself cannot be found
        tried_path_msg = f"Specified path: {gpgbinary}" if gpgbinary else "Not found in system PATH"
        log.error(f"GPG executable not found. {tried_path_msg}. Ensure GPG is installed and accessible, or set GPG_BINARY env var.")
        # Reraise the specific error so the app knows GPG isn't available
        raise
    except Exception as e:
        # Catch other potential initialization errors (permissions, bad homedir, etc.)
        log.error(f"Failed to initialize GPG: {e}", exc_info=True) # Log full traceback
        # Check if the error message matches the specific type error we saw before
        if "expected str, bytes or os.PathLike object, not NoneType" in str(e):
             log.error("This specific error often means an invalid path (like None) was passed unexpectedly. Check GPG_BINARY/GPG_HOME environment variables.")
        # Reraise the exception to indicate failure
        raise

def import_key(gpg, key_data):
    """Imports a public key into the GPG keyring."""
    if not gpg:
        raise ValueError("GPG not initialized")
    log.info("Attempting to import GPG key...")
    import_result = gpg.import_keys(key_data)
    # Log the raw results from the ImportResult object for debugging
    log.debug(f"GPG import raw results: {import_result.results}")
    log.debug(f"GPG import fingerprints: {import_result.fingerprints}")
    log.debug(f"GPG import count: {import_result.count}")
    log.debug(f"GPG import stderr: {import_result.stderr}") # Check stderr for GPG errors

    # ---- CORRECTED SUCCESS CHECK ----
    # Check if count is zero OR fingerprints list is empty.
    # Also check stderr for potential explicit GPG errors even if count > 0 sometimes.
    if import_result.count == 0 or not import_result.fingerprints:
        log.warning(f"Failed to import GPG key. Count: {import_result.count}, Fingerprints: {import_result.fingerprints}, Status: {import_result.results}, stderr: {import_result.stderr}")

        # Try to provide a more helpful message based on stderr
        status_message = f"Import failed. GPG Status: {import_result.results}."
        # Check if stderr has content before trying to access it
        if import_result.stderr:
             stderr_lower = import_result.stderr.lower()
             if "no valid openpgp data found" in stderr_lower:
                 status_message = "Import failed: The provided text does not appear to be a valid GPG key block."
             elif "secret key found" in stderr_lower or "secret key imported" in stderr_lower:
                  status_message = "Import failed: Private key detected. Please paste the PUBLIC key block only."
             elif "key DUMMYKEYRING" in import_result.stderr: # Error related to dummy keyring
                   status_message = "Import failed: There might be an issue with the GPG keyring setup or permissions."
             else:
                  # Generic stderr message
                  stderr_snippet = (import_result.stderr[:150] + '...') if len(import_result.stderr) > 150 else import_result.stderr
                  status_message += f" Details: {stderr_snippet}"
        elif import_result.count == 0:
             # Handle case where stderr might be empty but count is still 0
             status_message = "Import failed: No key data processed or recognized."

        return None, status_message
    # ---- END CORRECTED CHECK ----

    # If we get here, import seems successful based on count and fingerprints
    # Assuming only one key is imported at a time for simplicity
    fingerprint = import_result.fingerprints[0]
    log.info(f"Successfully imported key with fingerprint: {fingerprint}")
    return fingerprint, "Key imported successfully."


def find_key(gpg, identifier):
    """Finds a public key by email or fingerprint in the GPG keyring."""
    if not gpg:
         raise ValueError("GPG not initialized")
    log.debug(f"Searching for GPG key with identifier: {identifier}")
    try:
        # Set secret=False to only search public keys
        keys = gpg.list_keys(keys=identifier, secret=False)
        if not keys:
            log.warning(f"No GPG public key found for identifier: {identifier}")
            return None
        # Return the fingerprint of the first match
        fingerprint = keys[0]['fingerprint']
        log.debug(f"Found key fingerprint: {fingerprint}")
        return fingerprint
    except Exception as e:
        log.error(f"Error searching for GPG key {identifier}: {e}", exc_info=True)
        return None # Indicate failure

def encrypt_message(gpg, message, recipient_fingerprint):
    """Encrypts a message for a specific recipient fingerprint."""
    if not gpg:
         raise ValueError("GPG not initialized")
    log.info(f"Attempting to encrypt message for recipient fingerprint: {recipient_fingerprint}")

    # Optional but good practice: Verify recipient key exists before encrypting
    recipient_keys = gpg.list_keys(keys=recipient_fingerprint, secret=False) # Check public keys
    if not recipient_keys:
        log.error(f"Recipient GPG public key with fingerprint {recipient_fingerprint} not found in keyring. Cannot encrypt.")
        raise ValueError(f"Recipient GPG public key {recipient_fingerprint} not found in keyring.")

    # Encrypt the message (ASCII armored output is default)
    # always_trust=True bypasses trustdb checks; useful for simple cases,
    # but in real systems, proper trust management is better.
    encrypted_data = gpg.encrypt(message.encode('utf-8'), recipient_fingerprint, always_trust=True)

    # Check the 'ok' attribute for encryption results
    if not encrypted_data.ok:
        log.error(f"GPG encryption failed: Status='{encrypted_data.status}', stderr='{encrypted_data.stderr}'")
        raise RuntimeError(f"GPG encryption failed: {encrypted_data.status}. Details: {encrypted_data.stderr}")

    log.info("GPG encryption successful.")
    return str(encrypted_data) # Return the ASCII armored string

def decrypt_message(gpg, encrypted_data_str, passphrase=None):
    """
    Decrypts a GPG message.
    Relies on the private key being available in the GPG keyring used by the app.
    Passphrase handling relies on gpg-agent or explicit passing (less secure).
    """
    if not gpg:
         raise ValueError("GPG not initialized")
    log.info("Attempting to decrypt GPG message...")

    # Passphrase argument is available but often better handled by gpg-agent
    decrypted_data = gpg.decrypt(encrypted_data_str, passphrase=passphrase)

    # Check the 'ok' attribute for decryption results
    if not decrypted_data.ok:
        log.warning(f"GPG decryption failed: Status='{decrypted_data.status}', stderr='{decrypted_data.stderr}'")
        # Provide more context if possible
        error_msg = f"GPG decryption failed: Status '{decrypted_data.status}'."
        # Check if stderr has content before trying to access it
        if decrypted_data.stderr:
            stderr_lower = decrypted_data.stderr.lower()
            if "bad passphrase" in stderr_lower or "decryption failed" in stderr_lower :
                 error_msg += " Check if key is locked or passphrase is correct (if passed)."
            elif "secret key not available" in stderr_lower:
                 error_msg += " Ensure the correct private key is in the GPG keyring being used."
            else:
                # Limit length of stderr in message to avoid huge errors shown to user
                stderr_snippet = (decrypted_data.stderr[:100] + '...') if len(decrypted_data.stderr) > 100 else decrypted_data.stderr
                error_msg += f" Details: {stderr_snippet}"
        else:
            # Add a generic note if stderr is empty but status indicates failure
             error_msg += " No specific details available from GPG."


        raise RuntimeError(error_msg)

    # If decryption was successful
    log.info(f"GPG decryption successful. Fingerprint: {decrypted_data.fingerprint}, Key ID: {decrypted_data.key_id}")
    # The decrypted data is in decrypted_data.data (as bytes)
    return decrypted_data.data.decode('utf-8') # Return the decrypted string