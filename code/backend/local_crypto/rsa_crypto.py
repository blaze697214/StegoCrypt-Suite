import os
import sys
import shutil
from pathlib import Path
from typing import Optional
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Ensure Backend is on sys.path for local script execution
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from validation.inputs import non_empty_string

# Store keys in user's home directory for better security
KEY_DIR = Path.home() / ".stegocrypt_keys"
KEY_DIR.mkdir(exist_ok=True)

PRIVATE_KEY_FILE = KEY_DIR / "private_rsa.pem"
PUBLIC_KEY_FILE = KEY_DIR / "public_rsa.pem"

def generate_rsa_keys(output_dir: Optional[str] = None):
    """
    Generates a new RSA key pair.
    If output_dir is provided, saves keys to that directory.
    Otherwise, saves to the default location.
    """
    key = RSA.generate(2048)
    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()

    if output_dir:
        dest_dir = Path(output_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        private_key_path = dest_dir / "private_rsa.pem"
        public_key_path = dest_dir / "public_rsa.pem"
    else:
        private_key_path = PRIVATE_KEY_FILE
        public_key_path = PUBLIC_KEY_FILE

    with open(private_key_path, 'wb') as f:
        f.write(private_key_pem)
    with open(public_key_path, 'wb') as f:
        f.write(public_key_pem)

    # Also update the default key location if a custom directory is used
    if output_dir:
        with open(PRIVATE_KEY_FILE, 'wb') as f:
            f.write(private_key_pem)
        with open(PUBLIC_KEY_FILE, 'wb') as f:
            f.write(public_key_pem)
            
    return private_key_path, public_key_path

def load_keys():
    """Loads RSA keys from the default location, generating them if they don't exist."""
    try:
        if not PRIVATE_KEY_FILE.exists() or not PUBLIC_KEY_FILE.exists():
            generate_rsa_keys()
        
        with open(PRIVATE_KEY_FILE, 'rb') as f:
            private_key = RSA.import_key(f.read())
        with open(PUBLIC_KEY_FILE, 'rb') as f:
            public_key = RSA.import_key(f.read())
        return private_key, public_key
    except Exception as e:
        raise e

def encrypt_with_rsa(public_key, message: str) -> bytes:
    """Encrypt plaintext string using the public key and return raw bytes."""
    non_empty_string(message, "message")
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    return ciphertext

def decrypt_with_rsa(private_key, ciphertext: bytes) -> str:
    """Decrypt ciphertext bytes using the private key and return plaintext string."""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext).decode('utf-8')

def import_keys(pub_file: str, priv_file: str):
    """Imports RSA keys from the specified files."""
    pub_path = Path(pub_file).resolve()
    priv_path = Path(priv_file).resolve()

    if not pub_path.exists() or not priv_path.exists():
        raise FileNotFoundError("One or both key files not found.")

    # Avoid copying if the source and destination are the same file
    if pub_path != PUBLIC_KEY_FILE.resolve():
        shutil.copyfile(pub_path, PUBLIC_KEY_FILE)
    
    if priv_path != PRIVATE_KEY_FILE.resolve():
        shutil.copyfile(priv_path, PRIVATE_KEY_FILE)

def export_keys(output_dir: str):
    """Exports the current RSA keys to the specified directory."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if not PRIVATE_KEY_FILE.exists() or not PUBLIC_KEY_FILE.exists():
        raise FileNotFoundError("No keys found to export. Generate them first.")

    shutil.copyfile(PRIVATE_KEY_FILE, output_path / "private_rsa.pem")
    shutil.copyfile(PUBLIC_KEY_FILE, output_path / "public_rsa.pem")