import os, sys
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Ensure Backend is on sys.path for local script execution
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from validation.inputs import non_empty_string

# Store keys in user's home directory for better security
KEY_DIR = Path.home() / ".stegocrypt_keys"
KEY_DIR.mkdir(exist_ok=True)

AES_KEY_FILE = KEY_DIR / "aes_key.bin"
AES_SALT_FILE = KEY_DIR / "aes_salt.bin"

def get_key_from_password(password):
    """Derive AES key from password using PBKDF2"""
    salt = get_random_bytes(16)
    key = PBKDF2(password.encode(), salt, dkLen=16, count=100000)
    return key, salt

def save_aes_key(key, salt):
    """Save AES key and salt to files"""
    with open(AES_KEY_FILE, 'wb') as f:
        f.write(key)
    with open(AES_SALT_FILE, 'wb') as f:
        f.write(salt)

def load_aes_key():
    """Load existing AES key if available"""
    if AES_KEY_FILE.exists() and AES_SALT_FILE.exists():
        with open(AES_KEY_FILE, 'rb') as f:
            key = f.read()
        with open(AES_SALT_FILE, 'rb') as f:
            salt = f.read()
        return key, salt
    return None, None

def generate_new_aes_key():
    """Generate and save new AES key"""
    key = get_random_bytes(16)
    salt = get_random_bytes(16)
    save_aes_key(key, salt)
    return key, salt

def encrypt_aes(key, plaintext):
    """Encrypt plaintext and return raw bytes (nonce + tag + ciphertext)"""
    non_empty_string(plaintext, "plaintext")
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return cipher.nonce + tag + ciphertext

def decrypt_aes(key, ciphertext_bytes):
    """Decrypt ciphertext bytes and return plaintext string"""
    nonce, tag, ciphertext = ciphertext_bytes[:16], ciphertext_bytes[16:32], ciphertext_bytes[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def main():
    try:
        print("🔐 AES Key Management")
        print("1. Use existing key")
        print("2. Generate new key")
        print("3. Use password")

        choice = input("Choose option (1-3): ").strip()

        if choice == '1':
            key, salt = load_aes_key()
            if key is None:
                print("❌ No existing key found. Generating new one...")
                key, salt = generate_new_aes_key()
            print("✅ Using existing key")

        elif choice == '2':
            key, salt = generate_new_aes_key()
            print("✅ New AES key generated and saved")
            print(f"🔑 Key (hex): {key.hex()}")

        elif choice == '3':
            password = input("Enter password: ").strip()
            if not password:
                print("❌ Empty password. Generating random key instead.")
                key, salt = generate_new_aes_key()
            else:
                key, salt = get_key_from_password(password)
                save_aes_key(key, salt)
                print("✅ Key derived from password and saved")

        else:
            print("❌ Invalid choice. Generating random key...")
            key, salt = generate_new_aes_key()

        while True:
            print("\n--- AES MENU ---")
            print("1. Encrypt Text")
            print("2. Decrypt Text")
            print("3. Exit")
            choice = input("Enter choice: ")

            if choice == '1':
                text = input("Enter text to encrypt: ").strip()
                try:
                    encrypted = encrypt_aes(key, text)
                    print("✅ Encrypted (raw bytes):", encrypted.hex())
                    print("   Length:", len(encrypted), "bytes")
                except Exception as e:
                    print(f"❌ Encryption failed: {e}")

            elif choice == '2':
                encrypted_hex = input("Enter encrypted text (hex): ").strip()
                try:
                    encrypted = bytes.fromhex(encrypted_hex)
                    decrypted = decrypt_aes(key, encrypted)
                    print("✅ Decrypted:", decrypted)
                except Exception as e:
                    print(f"❌ Decryption failed: {e}")

            elif choice == '3':
                print("👋 Exiting.")
                break

            else:
                print("❌ Invalid choice! Please enter 1, 2, or 3.")

    except KeyboardInterrupt:
        print("\n\n👋 Exiting.")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == '__main__':
    main()