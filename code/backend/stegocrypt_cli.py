#!/usr/bin/env python3
"""
StegoCrypt Suite - Command Line Interface
Direct process communication interface for Flutter frontend
"""

import os
import sys
import json
import hashlib

# Set stdout and stderr to utf-8
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr.encoding != 'utf-8':
    sys.stderr.reconfigure(encoding='utf-8')
import argparse
import tempfile
import base64
from pathlib import Path
from typing import Optional

# Add backend directory to path for imports
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Import existing modules
from steganography.image_stego import encode_image, decode_image
from steganography.audio_stego import encode_audio, decode_audio
from steganography.video_stego import (
    encode_video,
    decode_video,
)
from steganography.text_stego import (
    encode_text_data,
    decode_text_data,
)
from hashing import hash_message, verify_hash, get_supported_algorithms
from logs import log_operation, get_logs, get_log_stats
from local_crypto.aes_crypto import encrypt_aes, decrypt_aes, get_key_from_password
from Crypto.Protocol.KDF import PBKDF2
from local_crypto.rsa_crypto import (
    generate_rsa_keys,
    encrypt_with_rsa,
    decrypt_with_rsa,
    import_keys,
    export_keys,
    load_keys,
)
from validation.inputs import non_empty_string
from validation.errors import ValidationError

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.keymanager_state.json')

def save_key_manager_state(km):
    """Save KeyManager state to disk using JSON"""
    try:
        # Import SecureBuffer if needed
        from file_security.file_security import SecureBuffer
        
        state = {
            'public_key': base64.b64encode(km.public_key).decode('utf-8') if km.public_key else None,
            'public_fingerprint': km.public_fingerprint,
            'private_keys': {k: base64.b64encode(v.to_bytes()).decode('utf-8') for k, v in km.private_keys.items()},
            'private_fingerprints': km.private_fingerprints
        }
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
        print(f"DEBUG - State saved: {len(state['private_keys'])} private keys, public_key: {km.public_key is not None}", file=sys.stderr)
    except Exception as e:
        print(f"DEBUG - Failed to save state: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)

def load_key_manager_state(km):
    """Load KeyManager state from disk using JSON"""
    try:
        if os.path.exists(STATE_FILE):
            from file_security.file_security import SecureBuffer
            
            with open(STATE_FILE, 'r') as f:
                state = json.load(f)
            
            km.public_key = base64.b64decode(state['public_key'].encode('utf-8')) if state.get('public_key') else None
            km.public_fingerprint = state.get('public_fingerprint')
            km.private_fingerprints = state.get('private_fingerprints', {})
            
            # Restore SecureBuffers
            for key_id, key_b64 in state.get('private_keys', {}).items():
                key_bytes = base64.b64decode(key_b64.encode('utf-8'))
                km.private_keys[key_id] = SecureBuffer.from_bytes(key_bytes)
            
            print(f"DEBUG - State loaded: {len(km.private_keys)} private keys, public_key: {km.public_key is not None}", file=sys.stderr)
            return True
    except Exception as e:
        print(f"DEBUG - Failed to load state: {e}", file=sys.stderr)
        # Clear corrupted state file
        try:
            if os.path.exists(STATE_FILE):
                os.remove(STATE_FILE)
        except:
            pass
    return False

def clear_key_manager_state():
    """Clear persisted state (call on app start)"""
    try:
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
            print("DEBUG - State file cleared", file=sys.stderr)
    except Exception as e:
        print(f"DEBUG - Failed to clear state: {e}", file=sys.stderr)

# Lazily initialize the file security backend to avoid heavy imports or side-effects
# at module import time (these caused the project to fail when importing this module).
file_security_manager = None

# Global singleton instance that persists across CLI calls
_key_manager_instance = None

def get_key_manager():
    """Return a persistent KeyManager singleton instance"""
    global _key_manager_instance
    
    if _key_manager_instance is None:
        try:
            from file_security.file_security import KeyManager
            _key_manager_instance = KeyManager()
            # Try to load existing state
            load_key_manager_state(_key_manager_instance)
            print("DEBUG - KeyManager created successfully", file=sys.stderr)
        except ImportError as e:
            error_message = f"KeyManager import failed: {str(e)}"
            class _MissingKeyManager:
                def __getattr__(self, name):
                    raise RuntimeError(f"Key manager unavailable: {error_message}")
            _key_manager_instance = _MissingKeyManager()
        except Exception as e:
            error_message = f"KeyManager initialization failed: {str(e)}"
            class _MissingKeyManager:
                def __getattr__(self, name):
                    raise RuntimeError(f"Key manager unavailable: {error_message}")
            _key_manager_instance = _MissingKeyManager()
    else:
        print(f"DEBUG - Using existing KeyManager (has {len(getattr(_key_manager_instance, 'private_keys', {}))} private keys)", file=sys.stderr)
    
    return _key_manager_instance

def get_file_security_manager():
    """Return a lazily-instantiated X25519FileEncryption instance.

    If the underlying backend cannot be imported/initialized, a stub object
    is returned that raises a clear RuntimeError when any attribute is used.
    This prevents import-time failures while still providing informative
    errors when file-security operations are attempted.
    """
    global file_security_manager
    if file_security_manager is None:
        try:
            from file_security.file_security import X25519FileEncryption
            file_security_manager = X25519FileEncryption()
        except BaseException as e:
            # Some modules (e.g., file_security) call sys.exit() on missing
            # dependencies which raises SystemExit (not Exception). Catch
            # BaseException so we can return an informative stub instead of
            # letting the import terminate the process.
            # Try to detect a missing-cryptography situation and surface a
            # helpful message to the caller.
            detected_msg = None
            try:
                # quick probe for the cryptography package
                import cryptography.hazmat.primitives  # type: ignore
            except Exception as probe_e:
                detected_msg = f"Missing dependency: {probe_e}. Install with: pip install cryptography"
            if not detected_msg:
                detected_msg = str(e)

            class _MissingFileSecurity:
                def __getattr__(self, name):
                    raise RuntimeError(f"File security backend unavailable: {detected_msg}")

            file_security_manager = _MissingFileSecurity()
    return file_security_manager
    

def encrypt_message(message: str, method: str, password: Optional[str] = None) -> str:
    """Encrypt message using specified method"""
    try:
        non_empty_string(message, "message")
        non_empty_string(method, "method")

        if method.upper() == "AES":
            if not password:
                raise ValueError("Password is required for AES encryption")
            key, salt = get_key_from_password(password)
            encrypted_data = encrypt_aes(key, message)
            payload = salt + encrypted_data
            # return encrypted_data
            return base64.b64encode(payload).decode('utf-8')

        elif method.upper() == "RSA":
            _, public_key = load_keys()
            if not public_key:
                generate_rsa_keys()
                _, public_key = load_keys()
            
            encrypted_data = encrypt_with_rsa(public_key, message)
            return base64.b64encode(encrypted_data).decode('utf-8')

        else:
            raise ValueError(f"Unsupported encryption method: {method}")

    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")


def decrypt_message(ciphertext: str, method: str, password: Optional[str] = None) -> str:
    """Decrypt message using specified method"""
    try:
        non_empty_string(ciphertext, "ciphertext")
        non_empty_string(method, "method")
        
        encrypted_data = base64.b64decode(ciphertext)

        if method.upper() == "AES":
            if not password:
                raise ValueError("Password is required for AES decryption")
            try:
                if len(encrypted_data) >= 48:
                    salt = encrypted_data[:16]
                    body = encrypted_data[16:]
                    key = PBKDF2(password.encode(), salt, dkLen=16, count=100000)
                    return decrypt_aes(key, body)
                else:
                    key, _ = get_key_from_password(password)
                    return decrypt_aes(key, encrypted_data)
            except Exception:
                key, _ = get_key_from_password(password)
                return decrypt_aes(key, encrypted_data)

        elif method.upper() == "RSA":
            private_key, _ = load_keys()
            if not private_key:
                raise ValueError("RSA private key not found. Cannot decrypt.")
            return decrypt_with_rsa(private_key, encrypted_data)

        else:
            raise ValueError(f"Unsupported decryption method: {method}")

    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def process_image_encode(args):
    """Process image encoding request"""
    try:
        log_operation("ENCODE_IMAGE", "STARTED", {"filename": os.path.basename(args.input_file)})
        
        # Encrypt the message first
        password = args.password if hasattr(args, 'password') else None
        encrypted_message = encrypt_message(args.message, args.algorithm, password)
        
        # Encode the encrypted message into the image and get the bytes
        encoded_image_bytes = encode_image(args.input_file, encrypted_message)
        
        # Base64 encode the bytes to send as a string in JSON
        encoded_image_base64 = base64.b64encode(encoded_image_bytes).decode('utf-8')
        
        output_filename = args.output_file
        if not output_filename.lower().endswith('.png'):
            output_filename += '.png'

        log_operation("ENCODE_IMAGE", "SUCCESS", {"filename": os.path.basename(output_filename)})
        return {
            "status": "success",
            "success": True,
            "message": "Message successfully encoded into image",
            "image_data": encoded_image_base64,
            "filename": os.path.basename(output_filename),
        }
        
    except Exception as e:
        details = {"error": str(e)}
        if hasattr(args, 'input_file') and args.input_file:
            details["filename"] = os.path.basename(args.input_file)
        log_operation("ENCODE_IMAGE", "FAILED", details)
        return {"status": "error", "success": False, "message": str(e)}

def process_image_decode(args):
    """Process image decoding request"""
    try:
        log_operation("DECODE_IMAGE", "STARTED", {"filename": os.path.basename(args.input_file)})
        
        # Decode the message from the image
        decoded_text = decode_image(args.input_file)
        
        if decoded_text is None:
            log_operation(
                "DECODE_IMAGE",
                "FAILED",
                {
                    "reason": "No hidden message found",
                    "filename": os.path.basename(args.input_file),
                },
            )
            return {"status": "error", "success": False, "message": "No hidden message found in image"}
        
        # Decrypt the message
        password = args.password if hasattr(args, 'password') else None
        decrypted_message = decrypt_message(decoded_text, args.algorithm, password)
        
        log_operation("DECODE_IMAGE", "SUCCESS", {"filename": os.path.basename(args.input_file)})
        return {
            "status": "success",
            "success": True,
            "message": decrypted_message,
            "ciphertext": decoded_text,
        }
        
    except Exception as e:
        details = {"error": str(e)}
        if hasattr(args, 'input_file') and args.input_file:
            details["filename"] = os.path.basename(args.input_file)
        log_operation("DECODE_IMAGE", "FAILED", details)
        return {"status": "error", "success": False, "message": str(e)}

def process_audio_encode(args):
    """Process audio encoding request"""
    try:
        log_operation("ENCODE_AUDIO", "STARTED", {"filename": os.path.basename(args.input_file)})
        
        password = args.password if hasattr(args, 'password') else None
        encrypted_message = encrypt_message(args.message, args.algorithm, password)
        
        encoded_audio_bytes = encode_audio(args.input_file, encrypted_message)
        
        encoded_audio_base64 = base64.b64encode(encoded_audio_bytes).decode('utf-8')
        
        log_operation("ENCODE_AUDIO", "SUCCESS", {"filename": os.path.basename(args.output_file)})
        return {
            "status": "success",
            "success": True,
            "message": "Message successfully encoded into audio",
            "audio_data": encoded_audio_base64,
            "filename": os.path.basename(args.output_file),
        }
        
    except Exception as e:
        details = {"error": str(e)}
        if hasattr(args, 'input_file') and args.input_file:
            details["filename"] = os.path.basename(args.input_file)
        log_operation("ENCODE_AUDIO", "FAILED", details)
        return {"status": "error", "success": False, "message": str(e)}

def process_audio_decode(args):
    """Process audio decoding request"""
    try:
        log_operation("DECODE_AUDIO", "STARTED", {"filename": os.path.basename(args.input_file)})
        
        decoded_text = decode_audio(args.input_file)
        
        if decoded_text is None:
            log_operation(
                "DECODE_AUDIO",
                "FAILED",
                {
                    "reason": "No hidden message found",
                    "filename": os.path.basename(args.input_file),
                },
            )
            return {"status": "error", "success": False, "message": "No hidden message found in audio"}
        
        password = args.password if hasattr(args, 'password') else None
        decrypted_message = decrypt_message(decoded_text, args.algorithm, password)
        
        log_operation("DECODE_AUDIO", "SUCCESS", {"filename": os.path.basename(args.input_file)})
        return {
            "status": "success",
            "success": True,
            "message": decrypted_message,
            "ciphertext": decoded_text,
        }
        
    except Exception as e:
        details = {"error": str(e)}
        if hasattr(args, 'input_file') and args.input_file:
            details["filename"] = os.path.basename(args.input_file)
        log_operation("DECODE_AUDIO", "FAILED", details)
        return {"status": "error", "success": False, "message": str(e)}

def process_video_encode(args):
    """Process video encoding request"""
    try:
        log_operation("ENCODE_VIDEO", "STARTED", {"filename": os.path.basename(args.input_file)})
        
        # Encrypt the message first
        password = args.password if hasattr(args, 'password') else None
        encrypted_message = encrypt_message(args.message, args.algorithm, password)
        
        # Encode the encrypted message into the video and get the bytes
        encoded_video_bytes = encode_video(args.input_file, encrypted_message)
        
        # Base64 encode the bytes to send as a string in JSON
        encoded_video_base64 = base64.b64encode(encoded_video_bytes).decode('utf-8')
        
        log_operation("ENCODE_VIDEO", "SUCCESS", {"filename": os.path.basename(args.output_file)})
        return {
            "status": "success",
            "success": True,
            "message": "Message successfully encoded into video",
            "video_data": encoded_video_base64,
            "filename": os.path.basename(args.output_file),
        }
        
    except Exception as e:
        details = {"error": str(e)}
        if hasattr(args, 'input_file') and args.input_file:
            details["filename"] = os.path.basename(args.input_file)
        log_operation("ENCODE_VIDEO", "FAILED", details)
        return {"status": "error", "success": False, "message": str(e)}

def process_video_decode(args):
    """Process video decoding request"""
    try:
        log_operation("DECODE_VIDEO", "STARTED", {"filename": os.path.basename(args.input_file)})
        
        # Decode the message from the video
        with open(args.input_file, "rb") as f:
            video_bytes = f.read()

        decoded_text = decode_video(video_bytes)
        
        if decoded_text is None:
            log_operation(
                "DECODE_VIDEO",
                "FAILED",
                {
                    "reason": "No hidden message found",
                    "filename": os.path.basename(args.input_file),
                },
            )
            return {"status": "error", "success": False, "message": "No hidden message found in video"}
        
        # Decrypt the message
        password = args.password if hasattr(args, 'password') else None
        decrypted_message = decrypt_message(decoded_text, args.algorithm, password)
        
        log_operation("DECODE_VIDEO", "SUCCESS", {"filename": os.path.basename(args.input_file)})
        return {
            "status": "success",
            "success": True,
            "message": decrypted_message,
            "ciphertext": decoded_text,
        }
        
    except Exception as e:
        details = {"error": str(e)}
        if hasattr(args, 'input_file') and args.input_file:
            details["filename"] = os.path.basename(args.input_file)
        log_operation("DECODE_VIDEO", "FAILED", details)
        return {"status": "error", "success": False, "message": str(e)}

def process_text_encode(args):
    """Process text encoding request"""
    try:
        log_operation("ENCODE_TEXT", "STARTED", {"filename": os.path.basename(args.input_file)})

        password = args.password if hasattr(args, 'password') else None
        encrypted_message = encrypt_message(args.message, args.algorithm, password)

        with open(args.input_file, 'r', encoding='utf-8') as f:
            cover_text = f.read()

        encoded_text = encode_text_data(encrypted_message, cover_text)
        
        encoded_text_base64 = base64.b64encode(encoded_text.encode('utf-8')).decode('utf-8')

        log_operation("ENCODE_TEXT", "SUCCESS", {"filename": os.path.basename(args.output_file)})
        return {
            "status": "success",
            "success": True,
            "message": "Message successfully encoded into text",
            "text_data": encoded_text_base64,
            "filename": os.path.basename(args.output_file),
        }

    except Exception as e:
        details = {"error": str(e)}
        if hasattr(args, 'input_file') and args.input_file:
            details["filename"] = os.path.basename(args.input_file)
        log_operation("ENCODE_TEXT", "FAILED", details)
        return {"status": "error", "success": False, "message": str(e)}

def process_text_decode(args):
    """Process text decoding request"""
    try:
        log_operation("DECODE_TEXT", "STARTED", {"filename": os.path.basename(args.input_file)})

        with open(args.input_file, 'r', encoding='utf-8') as f:
            stego_text = f.read()

        decoded_text = decode_text_data(stego_text)
        if not decoded_text:
            log_operation(
                "DECODE_TEXT",
                "FAILED",
                {
                    "reason": "No hidden message found",
                    "filename": os.path.basename(args.input_file),
                },
            )
            return {"status": "error", "success": False, "message": "No hidden message found in text"}

        password = args.password if hasattr(args, 'password') else None
        decrypted_message = decrypt_message(decoded_text, args.algorithm, password)

        log_operation("DECODE_TEXT", "SUCCESS", {"filename": os.path.basename(args.input_file)})
        return {
            "status": "success",
            "success": True,
            "message": decrypted_message,
            "ciphertext": decoded_text,
        }

    except Exception as e:
        details = {"error": str(e)}
        if hasattr(args, 'input_file') and args.input_file:
            details["filename"] = os.path.basename(args.input_file)
        log_operation("DECODE_TEXT", "FAILED", details)
        return {"status": "error", "success": False, "message": str(e)}

def process_encrypt(args):
    """Process encryption request"""
    try:
        log_operation("ENCRYPT", "STARTED", {"method": args.method})
        password = args.password if hasattr(args, 'password') else None
        ciphertext = encrypt_message(args.message, args.method, password)
        log_operation("ENCRYPT", "SUCCESS", {"method": args.method})
        return {"status": "success", "ciphertext": ciphertext}
    except Exception as e:
        log_operation("ENCRYPT", "FAILED", {"error": str(e)})
        return {"status": "error", "message": str(e)}

def process_decrypt(args):
    """Process decryption request"""
    try:
        log_operation("DECRYPT", "STARTED", {"method": args.method})
        password = args.password if hasattr(args, 'password') else None
        message = decrypt_message(args.ciphertext, args.method, password)
        log_operation("DECRYPT", "SUCCESS", {"method": args.method})
        return {"status": "success", "message": message}
    except Exception as e:
        log_operation("DECRYPT", "FAILED", {"error": str(e)})
        return {"status": "error", "message": str(e)}

def process_hash(args):
    """Process hashing request"""
    try:
        log_operation("HASH", "STARTED", {"algorithm": args.algorithm})
        hash_value = hash_message(args.message, args.algorithm)
        log_operation("HASH", "SUCCESS", {"algorithm": args.algorithm})
        return {"status": "success", "hash": hash_value, "algorithm": args.algorithm}
    except Exception as e:
        log_operation("HASH", "FAILED", {"error": str(e)})
        return {"status": "error", "message": str(e)}

def process_verify_hash(args):
    """Process hash verification request"""
    try:
        log_operation("VERIFY_HASH", "STARTED", {"algorithm": args.algorithm})
        is_valid = verify_hash(args.message, args.hash_value, args.algorithm)
        log_operation("VERIFY_HASH", "SUCCESS" if is_valid else "FAILED", {"algorithm": args.algorithm})
        return {"status": "success", "valid": is_valid, "algorithm": args.algorithm}
    except Exception as e:
        log_operation("VERIFY_HASH", "FAILED", {"error": str(e)})
        return {"status": "error", "message": str(e)}

def process_algorithms(args):
    """Get supported algorithms"""
    return {
        "status": "success",
        "encryption": ["AES", "RSA"],
        "hashing": get_supported_algorithms()
    }

def process_get_logs(args):
    """Process get logs request"""
    try:
        logs = get_logs()
        return {"status": "success", "logs": logs}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def process_get_log_stats(args):
    """Process get log stats request"""
    try:
        stats = get_log_stats()
        return {"status": "success", "stats": stats}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def process_rsa_command(args):
    """Process RSA-related commands"""
    try:
        if args.rsa_command == "generate-keys":
            output_dir = args.output_dir if hasattr(args, 'output_dir') else None
            private_key_path, public_key_path = generate_rsa_keys(output_dir)
            return {
                "status": "success",
                "message": f"RSA keys generated and saved to {private_key_path.parent}",
            }
        elif args.rsa_command == "import-keys":
            import_keys(args.pub_file, args.priv_file)
            return {"status": "success", "message": "RSA keys imported successfully"}
        elif args.rsa_command == "export-keys":
            export_keys(args.output_dir)
            return {
                "status": "success",
                "message": f"RSA keys exported to {args.output_dir}",
            }
        elif args.rsa_command == "encrypt":
            _, public_key = load_keys()
            encrypted = encrypt_with_rsa(public_key, args.message)
            return {"status": "success", "ciphertext": base64.b64encode(encrypted).decode('utf-8')}
        elif args.rsa_command == "decrypt":
            private_key, _ = load_keys()
            decrypted = decrypt_with_rsa(private_key, base64.b64decode(args.ciphertext))
            return {"status": "success", "message": decrypted}
        else:
            return {"status": "error", "message": f"Unknown RSA command: {args.rsa_command}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def process_file_security_command(args):
    """Process file security commands using KeyManager"""
    try:
        action = args.fs_command
        km = get_key_manager()
        
        # Test if KeyManager is available
        try:
            _ = getattr(km, 'get_key_info', None)
        except RuntimeError as re:
            return {"status": "error", "message": str(re)}

        if action == "generate-keypair":
            try:
                public_key_b64, private_key_id, fingerprint = km.generate_keypair()
                print(f"DEBUG - Keypair generated successfully. Key ID: {private_key_id}", file=sys.stderr)
                print(f"DEBUG - Fingerprint: {fingerprint}", file=sys.stderr)
                
                save_key_manager_state(km)

                return {
                    "status": "success",
                    "message": "Keypair generated successfully",
                    "publicKey": public_key_b64,
                    "privateKeyId": private_key_id,
                    "fingerprint": fingerprint
                }
            except Exception as e:
                return {"status": "error", "message": f"Failed to generate keypair: {str(e)}"}
        
        elif action == "load-public-key":
            try:
                with open(args.file_path, 'rb') as f:
                    public_key = f.read()
                fingerprint = km.load_public_key(public_key)
                save_key_manager_state(km)
                return {
                    "status": "success",
                    "message": "Public key loaded successfully",
                    "fingerprint": fingerprint,
                    "publicKey": base64.b64encode(public_key).decode('utf-8'),
                }
            except Exception as e:
                return {"status": "error", "message": f"Failed to load public key: {str(e)}"}

        elif action == "load-private-key":
            try:
                with open(args.file_path, 'rb') as f:
                    key_data = f.read()
                password = args.password if hasattr(args, 'password') else None
                key_id, fingerprint = km.load_private_key(key_data, password)
                print(f"DEBUG - Private key loaded: ID={key_id}, fingerprint={fingerprint}", file=sys.stderr)
                print(f"DEBUG - Keys in memory after load: {len(km.private_keys)}", file=sys.stderr)
                save_key_manager_state(km)
                return {
                    "status": "success",
                    "message": f"Private key loaded successfully. Key ID: {key_id}",
                    "privateKeyId": key_id,
                    "fingerprint": fingerprint,
                    "keysInMemory": len(km.private_keys)
                }
            except Exception as e:
                print(f"DEBUG - Failed to load private key: {str(e)}", file=sys.stderr)
                return {"status": "error", "message": f"Failed to load private key: {str(e)}"}

        elif action == "export-public-key":
            try:
                public_key_data = km.export_public_key()
                output_dir = os.path.dirname(args.file_path)
                if output_dir and not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)
                with open(args.file_path, 'wb') as f:
                    f.write(public_key_data)
                if not os.path.exists(args.file_path) or os.path.getsize(args.file_path) == 0:
                    return {"status": "error", "message": "Failed to write public key file"}
                return {
                    "status": "success",
                    "message": f"Public key exported to {args.file_path}",
                    "file_size": len(public_key_data)
                }
            except Exception as e:
                return {"status": "error", "message": f"Failed to export public key: {str(e)}"}

        elif action == "export-private-key":
            try:
                key_id = args.key_id
                password = args.password if hasattr(args, 'password') and args.password else None
                print(f"DEBUG - Attempting to export private key: {key_id}", file=sys.stderr)
                print(f"DEBUG - Available keys: {list(km.private_keys.keys())}", file=sys.stderr)
                print(f"DEBUG - Keys in memory: {len(km.private_keys)}", file=sys.stderr)
                key_data = km.export_private_key(key_id, password)
                output_dir = os.path.dirname(args.file_path)
                if output_dir and not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)
                with open(args.file_path, 'wb') as f:
                    f.write(key_data)
                if not os.path.exists(args.file_path) or os.path.getsize(args.file_path) == 0:
                    return {"status": "error", "message": "Failed to write private key file"}
                print(f"DEBUG - Private key exported successfully to {args.file_path}", file=sys.stderr)
                return {
                    "status": "success",
                    "message": f"Private key exported to {args.file_path}",
                    "file_size": len(key_data)
                }
            except Exception as e:
                print(f"DEBUG - Export private key failed: {str(e)}", file=sys.stderr)
                return {"status": "error", "message": f"Failed to export private key: {str(e)}"}

        elif action == "split-key":
            try:
                key_id = args.key_id
                print(f"DEBUG - Attempting to split key: {key_id}", file=sys.stderr)
                print(f"DEBUG - Available keys: {list(km.private_keys.keys())}", file=sys.stderr)
                print(f"DEBUG - Keys in memory: {len(km.private_keys)}", file=sys.stderr)
                shares = km.split_key(key_id, args.password, args.threshold, args.shares)
                
                # Use provided output directory or default to backend directory
                output_dir = getattr(args, 'output_dir', None)
                if not output_dir:
                    output_dir = os.path.dirname(os.path.abspath(__file__))
                
                # Ensure output directory exists
                os.makedirs(output_dir, exist_ok=True)
                
                share_files = []
                for i, share in enumerate(shares, 1):
                    share_file = os.path.join(output_dir, f"{args.base_name}_share_{i:02d}.sss")
                    with open(share_file, 'wb') as f:
                        f.write(share)
                    share_files.append(share_file)
                print(f"DEBUG - Key split successfully into {len(shares)} shares in {output_dir}", file=sys.stderr)
                return {
                    "status": "success",
                    "message": f"Key split into {len(shares)} shares successfully",
                    "shareFiles": share_files,
                    "outputDirectory": output_dir
                }
            except Exception as e:
                print(f"DEBUG - Split key failed: {str(e)}", file=sys.stderr)
                return {"status": "error", "message": f"Failed to split key: {str(e)}"}

        elif action == "reconstruct-key":
            try:
                share_files_str = args.share_files
                share_files_list = json.loads(share_files_str)
                shares = []
                for file_path in share_files_list:
                    with open(file_path, 'rb') as f:
                        shares.append(f.read())
                key_id, fingerprint = km.reconstruct_key(shares, args.password)
                save_key_manager_state(km)
                return {
                    "status": "success",
                    "message": "Key reconstructed successfully",
                    "privateKeyId": key_id,
                    "fingerprint": fingerprint
                }
            except Exception as e:
                return {"status": "error", "message": f"Reconstruction failed: {str(e)}"}

        elif action == "encrypt-file":
            try:
                public_key = base64.b64decode(args.key)
                if len(public_key) != 32:
                    return {
                        "status": "error",
                        "message": f"Invalid public key length: {len(public_key)} bytes (expected 32)"
                    }
                original_public_key = km.public_key
                km.public_key = public_key
                try:
                    # Get original filename for metadata
                    original_filename = getattr(args, 'original_filename', None)
                    if not original_filename:
                        original_filename = os.path.basename(args.input_file)
                    
                    fingerprint = km.encrypt_file(args.input_file, args.output_file, original_filename)
                    return {
                        "status": "success",
                        "message": "File encrypted successfully",
                        "fingerprint": fingerprint,
                        "filename": os.path.basename(args.output_file)
                    }
                finally:
                    km.public_key = original_public_key
            except Exception as e:
                return {"status": "error", "message": f"Encryption failed: {str(e)}"}

        elif action == "decrypt-file":
            try:
                key_id = args.key_id
                success = km.decrypt_file(args.input_file, args.output_file, key_id)
                if success:
                    return {
                        "status": "success",
                        "message": "File decrypted successfully",
                        "filename": os.path.basename(args.output_file)
                    }
                else:
                    return {"status": "error", "message": "File decryption failed."}
            except Exception as e:
                return {"status": "error", "message": f"Decryption failed: {str(e)}"}

        elif action == "view-key-info":
            try:
                info = km.get_key_info()
                print(f"DEBUG - view-key-info called", file=sys.stderr)
                print(f"DEBUG - Public key loaded: {info['publicKeyLoaded']}", file=sys.stderr)
                print(f"DEBUG - Private keys in memory: {info['privateKeysInMemory']}", file=sys.stderr)
                print(f"DEBUG - Available key IDs: {info['privateKeyIds']}", file=sys.stderr)
                print(f"DEBUG - KeyManager instance ID: {id(km)}", file=sys.stderr)
                print(f"DEBUG - Private keys dict size: {len(km.private_keys)}", file=sys.stderr)
                
                return {
                    "status": "success",
                    "publicKeyLoaded": info["publicKeyLoaded"],
                    "publicKeyFingerprint": info["publicKeyFingerprint"],
                    "privateKeyLoaded": info["privateKeysInMemory"] > 0,
                    "privateKeyFingerprint": list(info["privateKeyFingerprints"].values())[0] if info["privateKeyFingerprints"] else None,
                    "detailedInfo": info
                }
            except Exception as e:
                print(f"DEBUG - view-key-info error: {str(e)}", file=sys.stderr)
                return {"status": "error", "message": f"Failed to get key info: {str(e)}"}
        elif action == "configure-settings":
            try:
                chunk_size = getattr(args, 'chunk_size', None)
                kdf_strength = getattr(args, 'kdf_strength', None)
                km.configure_settings(chunk_size, kdf_strength)
                return {"status": "success", "message": "Settings updated."}
            except Exception as e:
                return {"status": "error", "message": f"Failed to update settings: {str(e)}"}
        
        elif action == "get-settings":
            try:
                settings_info = {
                    "chunkSize": km.settings.chunk_size,
                    "chunkSizeMB": km.settings.chunk_size // (1024 * 1024),
                    "kdfStrength": km.settings.get_kdf_strength_level().lower(),
                    "scryptN": km.settings.scrypt_n,
                    "scryptR": km.settings.scrypt_r,
                    "scryptP": km.settings.scrypt_p,
                    "algorithm": km.crypto.kem_algo,
                    "encryption": "AES-256-GCM",
                    "keyDerivation": "HKDF-SHA256"
                }
                return {"status": "success", "settings": settings_info}
            except Exception as e:
                return {"status": "error", "message": f"Failed to get settings: {str(e)}"}
        elif action == "get-metadata":
            try:
                from file_security.file_security import X25519FileEncryption
                metadata = X25519FileEncryption.read_file_metadata(args.file_path)
                return {
                    "status": "success",
                    "metadata": metadata,
                    "originalFilename": metadata.get('original_filename', None)
                }
            except Exception as e:
                return {"status": "error", "message": f"Failed to read metadata: {str(e)}"}

        elif action == "clear-state":
            try:
                clear_key_manager_state()
                
                # Also clear current KeyManager instance
                global _key_manager_instance
                if _key_manager_instance is not None:
                    # Wipe private keys
                    for key_id, key in list(km.private_keys.items()):
                        key.wipe()
                    km.private_keys.clear()
                    km.public_key = None
                    km.public_fingerprint = None
                    km.private_fingerprints.clear()
                    # Reset the singleton
                    _key_manager_instance = None
                
                return {"status": "success", "message": "Key state cleared"}
            except Exception as e:
                return {"status": "error", "message": f"Failed to clear state: {str(e)}"}

        else:
            return {"status": "error", "message": f"Unknown file security command: {action}"}

    except Exception as e:
        return {"status": "error", "message": str(e)}

def main():
    parser = argparse.ArgumentParser(description='StegoCrypt Suite CLI')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Image steganography
    img_encode_parser = subparsers.add_parser('encode-image')
    img_encode_parser.add_argument('--message', required=True)
    img_encode_parser.add_argument('--password', required=False)
    img_encode_parser.add_argument('--algorithm', required=True)
    img_encode_parser.add_argument('--input-file', required=True)
    img_encode_parser.add_argument('--output-file', required=True)
    
    img_decode_parser = subparsers.add_parser('decode-image')
    img_decode_parser.add_argument('--password', required=False)
    img_decode_parser.add_argument('--algorithm', required=True)
    img_decode_parser.add_argument('--input-file', required=True)
    
    # Audio steganography
    aud_encode_parser = subparsers.add_parser('encode-audio')
    aud_encode_parser.add_argument('--message', required=True)
    aud_encode_parser.add_argument('--password', required=False)
    aud_encode_parser.add_argument('--algorithm', required=True)
    aud_encode_parser.add_argument('--input-file', required=True)
    aud_encode_parser.add_argument('--output-file', required=True)
    
    aud_decode_parser = subparsers.add_parser('decode-audio')
    aud_decode_parser.add_argument('--password', required=False)
    aud_decode_parser.add_argument('--algorithm', required=True)
    aud_decode_parser.add_argument('--input-file', required=True)
    
    # Video steganography
    vid_encode_parser = subparsers.add_parser('encode-video')
    vid_encode_parser.add_argument('--message', required=True)
    vid_encode_parser.add_argument('--password', required=False)
    vid_encode_parser.add_argument('--algorithm', required=True)
    vid_encode_parser.add_argument('--input-file', required=True)
    vid_encode_parser.add_argument('--output-file', required=True)
    
    vid_decode_parser = subparsers.add_parser('decode-video')
    vid_decode_parser.add_argument('--password', required=False)
    vid_decode_parser.add_argument('--algorithm', required=True)
    vid_decode_parser.add_argument('--input-file', required=True)
    
    # Text steganography
    txt_encode_parser = subparsers.add_parser('encode-text')
    txt_encode_parser.add_argument('--message', required=True)
    txt_encode_parser.add_argument('--password', required=False)
    txt_encode_parser.add_argument('--algorithm', required=True)
    txt_encode_parser.add_argument('--input-file', required=True)
    txt_encode_parser.add_argument('--output-file', required=True)
    
    txt_decode_parser = subparsers.add_parser('decode-text')
    txt_decode_parser.add_argument('--password', required=False)
    txt_decode_parser.add_argument('--algorithm', required=True)
    txt_decode_parser.add_argument('--input-file', required=True)
    
    # Encryption/Decryption
    encrypt_parser = subparsers.add_parser('encrypt')
    encrypt_parser.add_argument('--message', required=True)
    encrypt_parser.add_argument('--password', required=False)
    encrypt_parser.add_argument('--method', required=True)
    
    decrypt_parser = subparsers.add_parser('decrypt')
    decrypt_parser.add_argument('--ciphertext', required=True)
    decrypt_parser.add_argument('--password', required=False)
    decrypt_parser.add_argument('--method', required=True)
    
    # Hashing
    hash_parser = subparsers.add_parser('hash')
    hash_parser.add_argument('--message', required=True)
    hash_parser.add_argument('--algorithm', default='sha256')
    
    verify_hash_parser = subparsers.add_parser('verify-hash')
    verify_hash_parser.add_argument('--message', required=True)
    verify_hash_parser.add_argument('--hash-value', required=True)
    verify_hash_parser.add_argument('--algorithm', default='sha256')
    
    # Algorithms
    algorithms_parser = subparsers.add_parser('algorithms')

    # Logs
    logs_parser = subparsers.add_parser('get-logs')
    log_stats_parser = subparsers.add_parser('get-log-stats')

    # RSA commands
    rsa_parser = subparsers.add_parser('rsa', help='RSA key management')
    rsa_subparsers = rsa_parser.add_subparsers(dest='rsa_command', help='RSA commands')

    rsa_generate_parser = rsa_subparsers.add_parser('generate-keys', help='Generate RSA key pair')
    rsa_generate_parser.add_argument('--output-dir', required=False, help='Directory to save the generated keys')
    
    rsa_import_parser = rsa_subparsers.add_parser('import-keys', help='Import RSA key pair')
    rsa_import_parser.add_argument('--pub-file', required=True, help='Path to public key file')
    rsa_import_parser.add_argument('--priv-file', required=True, help='Path to private key file')

    rsa_export_parser = rsa_subparsers.add_parser('export-keys', help='Export RSA key pair')
    rsa_export_parser.add_argument('--output-dir', required=True, help='Directory to save keys')

    rsa_encrypt_parser = rsa_subparsers.add_parser('encrypt', help='Encrypt a message with RSA')
    rsa_encrypt_parser.add_argument('--message', required=True, help='Message to encrypt')

    rsa_decrypt_parser = rsa_subparsers.add_parser('decrypt', help='Decrypt a message with RSA')
    rsa_decrypt_parser.add_argument('--ciphertext', required=True, help='Ciphertext to decrypt')

    # File Security
    fs_parser = subparsers.add_parser('file-security', help='File encryption and key management')
    fs_subparsers = fs_parser.add_subparsers(dest='fs_command', help='File security commands')

    fs_subparsers.add_parser('generate-keypair', help='Generate X25519 key pair')
    
    fs_load_pub_parser = fs_subparsers.add_parser('load-public-key', help='Load a public key from file')
    fs_load_pub_parser.add_argument('--file-path', required=True)

    fs_load_priv_parser = fs_subparsers.add_parser('load-private-key', help='Load a private key from file')
    fs_load_priv_parser.add_argument('--file-path', required=True)
    fs_load_priv_parser.add_argument('--password', required=False)

    fs_export_pub_parser = fs_subparsers.add_parser('export-public-key', help='Export public key to file')
    fs_export_pub_parser.add_argument('--file-path', required=True)

    fs_export_priv_parser = fs_subparsers.add_parser('export-private-key', help='Export private key to file')
    fs_export_priv_parser.add_argument('--key-id', required=True)
    fs_export_priv_parser.add_argument('--file-path', required=True)
    fs_export_priv_parser.add_argument('--password', required=False)

    fs_split_parser = fs_subparsers.add_parser('split-key', help='Split a private key into shares')
    fs_split_parser.add_argument('--key-id', required=True)
    fs_split_parser.add_argument('--password', required=True)
    fs_split_parser.add_argument('--threshold', required=True, type=int)
    fs_split_parser.add_argument('--shares', required=True, type=int)
    fs_split_parser.add_argument('--base-name', required=True)
    fs_split_parser.add_argument('--output-dir', required=False, help='Directory to save share files')

    fs_reconstruct_parser = fs_subparsers.add_parser('reconstruct-key', help='Reconstruct a private key from shares')
    fs_reconstruct_parser.add_argument('--share-files', required=True, help='JSON encoded list of share file paths')
    fs_reconstruct_parser.add_argument('--password', required=True)

    fs_encrypt_parser = fs_subparsers.add_parser('encrypt-file', help='Encrypt a file')
    fs_encrypt_parser.add_argument('--input-file', required=True)
    fs_encrypt_parser.add_argument('--output-file', required=True)
    fs_encrypt_parser.add_argument('--key', required=True, help='Base64 encoded public key')
    fs_encrypt_parser.add_argument('--original-filename', required=False, help='Original filename to store in metadata')

    fs_decrypt_parser = fs_subparsers.add_parser('decrypt-file', help='Decrypt a file')
    fs_decrypt_parser.add_argument('--input-file', required=True)
    fs_decrypt_parser.add_argument('--output-file', required=True)
    fs_decrypt_parser.add_argument('--key-id', required=True)

    fs_metadata_parser = fs_subparsers.add_parser('get-metadata', help='Get metadata from encrypted file')
    fs_metadata_parser.add_argument('--file-path', required=True)

    fs_subparsers.add_parser('view-key-info', help='View loaded key information')

    fs_config_parser = fs_subparsers.add_parser('configure-settings', help='Configure security settings')
    fs_config_parser.add_argument('--chunk-size', type=int)
    fs_config_parser.add_argument('--kdf-strength', choices=['low', 'medium', 'high', 'maximum'])
    
    fs_subparsers.add_parser('get-settings', help='Get current security settings')
    # Add this new subparser
    fs_clear_parser = fs_subparsers.add_parser('clear-state', help='Clear persisted key state')
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        # Route to appropriate handler
        if args.command == 'encode-image':
            result = process_image_encode(args)
        elif args.command == 'decode-image':
            result = process_image_decode(args)
        elif args.command == 'encode-audio':
            result = process_audio_encode(args)
        elif args.command == 'decode-audio':
            result = process_audio_decode(args)
        elif args.command == 'encode-video':
            result = process_video_encode(args)
        elif args.command == 'decode-video':
            result = process_video_decode(args)
        elif args.command == 'encode-text':
            result = process_text_encode(args)
        elif args.command == 'decode-text':
            result = process_text_decode(args)
        elif args.command == 'encrypt':
            result = process_encrypt(args)
        elif args.command == 'decrypt':
            result = process_decrypt(args)
        elif args.command == 'hash':
            result = process_hash(args)
        elif args.command == 'verify-hash':
            result = process_verify_hash(args)
        elif args.command == 'algorithms':
            result = process_algorithms(args)
        elif args.command == 'get-logs':
            result = process_get_logs(args)
        elif args.command == 'get-log-stats':
            result = process_get_log_stats(args)
        elif args.command == 'rsa':
            result = process_rsa_command(args)
        elif args.command == 'file-security':
            result = process_file_security_command(args)
        else:
            result = {"status": "error", "message": f"Unknown command: {args.command}"}
        
        # Output result as JSON
        print(json.dumps(result))
        
    except Exception as e:
        error_result = {"status": "error", "message": str(e)}
        print(json.dumps(error_result))
        sys.exit(1)

if __name__ == "__main__":
    main()
