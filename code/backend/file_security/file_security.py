# StegoCrypt Secure Suite - X25519 File Encryption System
# A secure file encryption module using X25519 KEM + AES-GCM

import os
import json
import hmac
import hashlib
import struct
import secrets
import sys
import base64
import ctypes
import getpass
from typing import Tuple, Optional, Callable, List, Dict, Any
from datetime import datetime, timezone
from pathlib import Path

# Required dependencies
HAS_CRYPTO = True
_CRYPTO_IMPORT_ERROR = None
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as e:
    # Don't exit at import time; mark crypto as unavailable so callers
    # (such as the CLI) can import this module and handle the missing
    # dependency gracefully. Attempting to instantiate crypto classes
    # will raise a clear RuntimeError via ensure_crypto().
    HAS_CRYPTO = False
    _CRYPTO_IMPORT_ERROR = e


def ensure_crypto():
    """Raise a RuntimeError when cryptography is unavailable.

    Call this from constructors or methods that require the cryptography
    package to provide a clear error instead of allowing a NameError or
    module exit to occur.
    """
    if not HAS_CRYPTO:
        msg = f"Missing dependency: {_CRYPTO_IMPORT_ERROR}. Install with: pip install cryptography"
        raise RuntimeError(msg)

# Constants
MAGIC_BYTES = b'X25F'  # Updated to reflect X25519
CURRENT_VERSION = 3
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4MB
HKDF_INFO = b'x25519-file-encryption:v3'
SALT_SIZE = 16
NONCE_BASE_SIZE = 12
KEY_SIZE = 32
MAC_KEY_SIZE = 32

# Enhanced Scrypt parameters
SCRYPT_LENGTH = 32
SCRYPT_N = 16384  # 2^14
SCRYPT_R = 8
SCRYPT_P = 1

# Required metadata keys
REQUIRED_METADATA_KEYS = {
    'version', 'kem_algo', 'kem_ciphertext', 'hkdf_salt', 'nonce_base',
    'chunk_size', 'aead_algo', 'original_size', 'hmac', 'kdf_algo', 'hkdf_info'
}


class SecuritySettings:
    """Configuration for security parameters"""
    
    def __init__(self):
        self.chunk_size = DEFAULT_CHUNK_SIZE
        self.scrypt_n = SCRYPT_N
        self.scrypt_r = SCRYPT_R
        self.scrypt_p = SCRYPT_P
    
    def get_kdf_strength_level(self) -> str:
        """Get human-readable KDF strength level"""
        if self.scrypt_n >= 32768:
            return "Maximum"
        elif self.scrypt_n >= 16384:
            return "High"
        elif self.scrypt_n >= 8192:
            return "Medium"
        else:
            return "Low"
    
    def set_kdf_strength(self, level: str):
        """Set KDF strength by level"""
        if level.lower() == "low":
            self.scrypt_n = 4096
        elif level.lower() == "medium":
            self.scrypt_n = 8192
        elif level.lower() == "high":
            self.scrypt_n = 16384
        elif level.lower() == "maximum":
            self.scrypt_n = 32768
        else:
            raise ValueError("Invalid strength level")


class SecureBuffer:
    """Secure buffer that automatically wipes memory on cleanup"""
    
    def __init__(self, size: int):
        self._buffer = bytearray(size)
        self._size = size
    
    @classmethod
    def from_bytes(cls, data: bytes):
        """Create secure buffer from existing bytes"""
        buf = cls(len(data))
        buf._buffer[:] = data
        return buf
    
    def __len__(self):
        return self._size
    
    def __getitem__(self, key):
        return self._buffer[key]
    
    def __setitem__(self, key, value):
        self._buffer[key] = value
    
    def to_bytes(self) -> bytes:
        """Convert to bytes (creates a copy)"""
        return bytes(self._buffer)
    
    def wipe(self):
        """Securely wipe the buffer contents"""
        if self._buffer:
            try:
                ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(self._buffer)), 0, len(self._buffer))
            except:
                for i in range(len(self._buffer)):
                    self._buffer[i] = 0
    
    def __del__(self):
        self.wipe()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()


def secure_wipe(buffer):
    """Securely wipe a mutable buffer"""
    if isinstance(buffer, bytearray):
        try:
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buffer)), 0, len(buffer))
        except:
            for i in range(len(buffer)):
                buffer[i] = 0
    elif hasattr(buffer, 'wipe'):
        buffer.wipe()


class X25519KEM:
    """X25519 Key Encapsulation Mechanism"""
    
    def __init__(self):
        self.key_size = 32
        self.ciphertext_size = 32  # Just the ephemeral public key
        
    def generate_keypair(self):
        """Generate X25519 keypair"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return public_bytes, private_bytes
    
    def encap_secret(self, public_key_bytes):
        """Encapsulate secret using X25519"""
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        
        public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
        shared_key = ephemeral_private.exchange(public_key)
        
        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return ephemeral_public_bytes, shared_key
    
    def decap_secret(self, ciphertext, private_key_bytes):
        """Decapsulate secret using X25519"""
        ephemeral_public_bytes = ciphertext
        
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
        
        shared_key = private_key.exchange(ephemeral_public)
        return shared_key

class ShamirSecretSharing:
    """Shamir's Secret Sharing that supports arbitrary-size secrets"""
    
    # Default large prime (can fit most ECC/RSA keys)
    PRIME = 2**521 - 1

    @staticmethod
    def _eval_poly(coeffs: List[int], x: int, prime: int) -> int:
        result = 0
        for coeff in reversed(coeffs):
            result = (result * x + coeff) % prime
        return result

    @staticmethod
    def _lagrange_interpolate(points: List[Tuple[int, int]], prime: int) -> int:
        def mod_inverse(a: int, m: int) -> int:
            return pow(a, m - 2, m)
        
        result = 0
        for i, (xi, yi) in enumerate(points):
            numerator = yi
            denominator = 1
            for j, (xj, _) in enumerate(points):
                if i != j:
                    numerator = (numerator * (-xj)) % prime
                    denominator = (denominator * (xi - xj)) % prime
            result = (result + numerator * mod_inverse(denominator, prime)) % prime
        return result

    @classmethod
    def split_secret(cls, secret: bytes, threshold: int, shares: int) -> List[bytes]:
        """Split secret into shares, handling large secrets automatically"""
        if threshold > shares or threshold < 2:
            raise ValueError("Invalid threshold or share count")
        
        # Break secret into chunks that fit in PRIME
        chunk_size = (cls.PRIME.bit_length() - 1) // 8  # bytes per chunk
        chunks = [secret[i:i+chunk_size] for i in range(0, len(secret), chunk_size)]

        share_lists = [[] for _ in range(shares)]
        
        for chunk in chunks:
            secret_int = int.from_bytes(chunk, 'big')
            coeffs = [secret_int] + [secrets.randbelow(cls.PRIME) for _ in range(threshold - 1)]
            
            for i in range(shares):
                y = cls._eval_poly(coeffs, i + 1, cls.PRIME)
                share_data = {
                    'x': i + 1,
                    'y': y,
                    'threshold': threshold,
                    'chunk_len': len(chunk)
                }
                share_json = json.dumps(share_data).encode('utf-8')
                share_lists[i].append(base64.b64encode(share_json))
        
        # Merge chunk shares per participant
        final_shares = []
        for share_chunks in share_lists:
            final_shares.append(b'|'.join(share_chunks))
        
        return final_shares

    @classmethod
    def reconstruct_secret(cls, shares: List[bytes]) -> bytes:
        """Reconstruct secret from shares"""
        if len(shares) < 2:
            raise ValueError("Need at least 2 shares")
        
        # Split into chunks per share
        chunked_shares = [s.split(b'|') for s in shares]
        num_chunks = len(chunked_shares[0])
        
        secret_bytes = b''
        for i in range(num_chunks):
            points = []
            threshold = None
            chunk_len = None
            for share in chunked_shares:
                share_data = json.loads(base64.b64decode(share[i]).decode('utf-8'))
                if threshold is None:
                    threshold = share_data['threshold']
                    chunk_len = share_data['chunk_len']
                points.append((share_data['x'], share_data['y']))
            
            points = points[:threshold]
            secret_int = cls._lagrange_interpolate(points, cls.PRIME)
            secret_bytes += secret_int.to_bytes(chunk_len, 'big')
        
        return secret_bytes

class X25519FileEncryption:
    """File Encryption using X25519 KEM + AES-GCM"""
    
    def __init__(self, security_settings: Optional[SecuritySettings] = None):
        # Ensure required cryptography package is available for X25519 operations
        ensure_crypto()
        self.kem = X25519KEM()
        self.kem_algo = "X25519-KEM"
        self.settings = security_settings or SecuritySettings()
    
    def generate_keypair(self) -> Tuple[bytes, SecureBuffer, str]:
        """Generate X25519 keypair"""
        public_key, private_key_bytes = self.kem.generate_keypair()
        private_key = SecureBuffer.from_bytes(private_key_bytes)
        secure_wipe(bytearray(private_key_bytes))
        
        fingerprint = hashlib.sha256(public_key).hexdigest()[:16]
        return public_key, private_key, fingerprint
    
    def _derive_keys(self, shared_secret: bytes, salt: bytes) -> Tuple[SecureBuffer, SecureBuffer]:
        """Derive encryption and MAC keys"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE + MAC_KEY_SIZE,
            salt=salt,
            info=HKDF_INFO,
            backend=default_backend()
        )
        
        derived = hkdf.derive(shared_secret)
        enc_key = SecureBuffer.from_bytes(derived[:KEY_SIZE])
        mac_key = SecureBuffer.from_bytes(derived[KEY_SIZE:])
        
        secure_wipe(bytearray(derived))
        return enc_key, mac_key
    
    def encrypt_file(self, input_path: str, output_path: str, public_key: bytes, original_filename: Optional[str] = None,
                    progress_callback: Optional[Callable[[int, int], None]] = None) -> str:
        """Encrypt file"""
        with open(input_path, 'rb') as f:
            data = f.read()
        
        if progress_callback:
            progress_callback(0, len(data))
        
        # Generate secrets
        kem_ciphertext, shared_bytes = self.kem.encap_secret(public_key)
        shared_secret = SecureBuffer.from_bytes(shared_bytes)
        secure_wipe(bytearray(shared_bytes))
        
        salt = secrets.token_bytes(SALT_SIZE)
        nonce_base = secrets.token_bytes(NONCE_BASE_SIZE)
        
        try:
            with shared_secret:
                enc_key, mac_key = self._derive_keys(shared_secret.to_bytes(), salt)
            
            with enc_key, mac_key:
                cipher = AESGCM(enc_key.to_bytes())
                
                # Create metadata
                metadata = {
                    "version": CURRENT_VERSION,
                    "kem_algo": self.kem_algo,
                    "kem_ciphertext": base64.b64encode(kem_ciphertext).decode('ascii'),
                    "hkdf_salt": base64.b64encode(salt).decode('ascii'),
                    "nonce_base": base64.b64encode(nonce_base).decode('ascii'),
                    "chunk_size": self.settings.chunk_size,
                    "aead_algo": "AES-256-GCM",
                    "kdf_algo": "HKDF-SHA256",
                    "hkdf_info": base64.b64encode(HKDF_INFO).decode('ascii'),
                    "original_size": len(data),
                    "original_filename": original_filename or os.path.basename(input_path),
                    "pub_fingerprint": hashlib.sha256(public_key).hexdigest()[:16],
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    "hmac": ""  # Placeholder
                }
                
                # Encrypt data
                nonce = nonce_base + b'\x00\x00\x00\x00'
                ciphertext = cipher.encrypt(nonce, data, None)
                
                # Calculate HMAC
                hmac_ctx = hmac.new(mac_key.to_bytes(), digestmod=hashlib.sha256)
                hmac_ctx.update(ciphertext)
                final_hmac = hmac_ctx.digest()
                metadata["hmac"] = base64.b64encode(final_hmac).decode('ascii')
                
                # Serialize metadata
                metadata_json = json.dumps(metadata, sort_keys=True).encode('utf-8')
                
                # Write encrypted file
                with open(output_path, 'wb') as f:
                    f.write(MAGIC_BYTES)
                    f.write(struct.pack('>I', len(metadata_json)))
                    f.write(metadata_json)
                    f.write(ciphertext)
                
                if progress_callback:
                    progress_callback(len(data), len(data))
                
                return hashlib.sha256(public_key).hexdigest()[:16]
        
        finally:
            secure_wipe(bytearray(salt))
            secure_wipe(bytearray(nonce_base))
    
    def decrypt_file(self, input_path: str, output_path: str, private_key: SecureBuffer,
                    progress_callback: Optional[Callable[[int, int], None]] = None) -> bool:
        """Decrypt file"""
        with open(input_path, 'rb') as f:
            # Read magic bytes
            magic = f.read(4)
            if magic != MAGIC_BYTES:
                raise ValueError("Invalid file format")
            
            # Read metadata
            metadata_len = struct.unpack('>I', f.read(4))[0]
            metadata_json = f.read(metadata_len)
            metadata = json.loads(metadata_json.decode('utf-8'))
            
            # Extract parameters
            kem_ciphertext = base64.b64decode(metadata["kem_ciphertext"])
            salt = base64.b64decode(metadata["hkdf_salt"])
            nonce_base = base64.b64decode(metadata["nonce_base"])
            expected_hmac = base64.b64decode(metadata["hmac"])
            
            # Read ciphertext
            ciphertext = f.read()
        
        if progress_callback:
            progress_callback(0, len(ciphertext))
        
        # Decapsulate shared secret
        with private_key:
            shared_bytes = self.kem.decap_secret(kem_ciphertext, private_key.to_bytes())
            shared_secret = SecureBuffer.from_bytes(shared_bytes)
            secure_wipe(bytearray(shared_bytes))
        
        with shared_secret:
            enc_key, mac_key = self._derive_keys(shared_secret.to_bytes(), salt)
        
        with enc_key, mac_key:
            # Verify HMAC
            hmac_ctx = hmac.new(mac_key.to_bytes(), digestmod=hashlib.sha256)
            hmac_ctx.update(ciphertext)
            computed_hmac = hmac_ctx.digest()
            
            if not hmac.compare_digest(computed_hmac, expected_hmac):
                raise ValueError("HMAC verification failed - data may be corrupted")
            
            # Decrypt
            cipher = AESGCM(enc_key.to_bytes())
            nonce = nonce_base + b'\x00\x00\x00\x00'
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            if progress_callback:
                progress_callback(len(ciphertext), len(ciphertext))
            
            return True
    
    def protect_private_key(self, private_key: SecureBuffer, password: str) -> bytes:
        """Protect private key with password using Scrypt"""
        salt = secrets.token_bytes(16)
        
        try:
            kdf = Scrypt(
                length=32,
                salt=salt,
                n=self.settings.scrypt_n,
                r=self.settings.scrypt_r,
                p=self.settings.scrypt_p,
                backend=default_backend()
            )
            derived_key = kdf.derive(password.encode('utf-8'))
            
            with SecureBuffer.from_bytes(derived_key) as key_buf:
                nonce = secrets.token_bytes(12)
                cipher = AESGCM(key_buf.to_bytes())
                ciphertext = cipher.encrypt(nonce, private_key.to_bytes(), None)
                
                key_blob = {
                    "version": CURRENT_VERSION,
                    "kdf": "scrypt",
                    "kdf_params": {
                        "n": self.settings.scrypt_n,
                        "r": self.settings.scrypt_r,
                        "p": self.settings.scrypt_p,
                        "length": 32
                    },
                    "salt": base64.b64encode(salt).decode('ascii'),
                    "nonce": base64.b64encode(nonce).decode('ascii'),
                    "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
                    "kem_algo": self.kem_algo
                }
                
                return json.dumps(key_blob, sort_keys=True).encode('utf-8')
        
        finally:
            if 'derived_key' in locals():
                secure_wipe(bytearray(derived_key))
    
    def unprotect_private_key(self, key_blob: bytes, password: str) -> SecureBuffer:
        """Unprotect private key with password"""
        try:
            blob_data = json.loads(key_blob.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Invalid key blob format")
        
        if blob_data.get("kdf") != "scrypt":
            raise ValueError("Unsupported KDF")
        
        params = blob_data["kdf_params"]
        salt = base64.b64decode(blob_data["salt"])
        nonce = base64.b64decode(blob_data["nonce"])
        ciphertext = base64.b64decode(blob_data["ciphertext"])
        
        try:
            kdf = Scrypt(
                length=params["length"],
                salt=salt,
                n=params["n"],
                r=params["r"],
                p=params["p"],
                backend=default_backend()
            )
            derived_key = kdf.derive(password.encode('utf-8'))
            
            with SecureBuffer.from_bytes(derived_key) as key_buf:
                cipher = AESGCM(key_buf.to_bytes())
                private_key_bytes = cipher.decrypt(nonce, ciphertext, None)
                return SecureBuffer.from_bytes(private_key_bytes)
        
        except Exception as e:
            if "verification failed" in str(e).lower():
                raise ValueError("Invalid password")
            raise ValueError(f"Key unprotection failed: {e}")
        
        finally:
            if 'derived_key' in locals():
                secure_wipe(bytearray(derived_key))
    
    def split_key_with_sss(self, private_key: SecureBuffer, password: str, 
                        threshold: int, shares: int) -> List[bytes]:
        """Split private key using Shamir's Secret Sharing"""
        encrypted_key = self.protect_private_key(private_key, password)
        return ShamirSecretSharing.split_secret(encrypted_key, threshold, shares)
    
    def reconstruct_key_from_sss(self, shares: List[bytes], password: str) -> SecureBuffer:
        """Reconstruct private key from SSS shares"""
        encrypted_key = ShamirSecretSharing.reconstruct_secret(shares)
        return self.unprotect_private_key(encrypted_key, password)
    
    @staticmethod
    def read_file_metadata(file_path: str) -> Dict[str, Any]:
        """Read metadata from encrypted file"""
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            if magic != MAGIC_BYTES:
                raise ValueError("Invalid file format")
            
            metadata_len = struct.unpack('>I', f.read(4))[0]
            metadata_json = f.read(metadata_len)
            return json.loads(metadata_json.decode('utf-8'))

class KeyManager:
    """Manages multiple keys and provides unified interface for CLI"""
    
    def __init__(self):
        ensure_crypto()
        self.settings = SecuritySettings()
        self.crypto = X25519FileEncryption(self.settings)
        self.public_key = None
        self.private_keys = {}  # Dict[key_id: SecureBuffer]
        self.public_fingerprint = None
        self.private_fingerprints = {}  # Dict[key_id: fingerprint]
    
    def generate_keypair(self) -> Tuple[str, str, str]:
        """Generate keypair and return (public_key_b64, private_key_id, fingerprint)"""
        public_key, private_key, fingerprint = self.crypto.generate_keypair()
        
        # Store keys
        self.public_key = public_key
        self.public_fingerprint = fingerprint
        
        # Generate unique ID for private key
        key_id = hashlib.sha256(public_key + secrets.token_bytes(16)).hexdigest()[:16]
        self.private_keys[key_id] = private_key
        self.private_fingerprints[key_id] = fingerprint
        
        public_key_b64 = base64.b64encode(public_key).decode('utf-8')
        return public_key_b64, key_id, fingerprint
    
    def load_public_key(self, public_key: bytes) -> str:
        """Load public key and return fingerprint"""
        if len(public_key) != 32:
            raise ValueError(f"Invalid public key length: {len(public_key)} bytes (expected 32)")
        
        self.public_key = public_key
        self.public_fingerprint = hashlib.sha256(public_key).hexdigest()[:16]
        return self.public_fingerprint
    
    def load_private_key(self, key_data: bytes, password: Optional[str] = None) -> Tuple[str, str]:
        """Load private key and return (key_id, fingerprint)"""
        try:
            # Try to parse as JSON (protected format)
            key_blob = json.loads(key_data.decode('utf-8'))
            if password is None:
                raise ValueError("Password required for protected private key")
            private_key = self.crypto.unprotect_private_key(key_data, password)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Raw private key
            if len(key_data) != 32:
                raise ValueError(f"Invalid private key length: {len(key_data)} bytes (expected 32)")
            private_key = SecureBuffer.from_bytes(key_data)
        
        # Derive public key to get fingerprint
        temp_private = x25519.X25519PrivateKey.from_private_bytes(private_key.to_bytes())
        temp_public = temp_private.public_key()
        temp_public_bytes = temp_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        fingerprint = hashlib.sha256(temp_public_bytes).hexdigest()[:16]
        
        # Generate key ID
        key_id = hashlib.sha256(temp_public_bytes + secrets.token_bytes(16)).hexdigest()[:16]
        
        # Store the key
        self.private_keys[key_id] = private_key
        self.private_fingerprints[key_id] = fingerprint
        
        return key_id, fingerprint
    
    def export_public_key(self) -> bytes:
        """Export current public key"""
        if self.public_key is None:
            raise ValueError("No public key loaded")
        return self.public_key
    
    def export_private_key(self, key_id: str, password: Optional[str] = None) -> bytes:
        """Export private key with optional password protection"""
        if key_id not in self.private_keys:
            raise ValueError(f"Private key not found: {key_id}")
        
        private_key = self.private_keys[key_id]
        
        if password:
            return self.crypto.protect_private_key(private_key, password)
        else:
            return private_key.to_bytes()
    
    def split_key(self, key_id: str, password: str, threshold: int, shares: int) -> List[bytes]:
        """Split private key into shares"""
        if key_id not in self.private_keys:
            raise ValueError(f"Private key not found: {key_id}")
        
        private_key = self.private_keys[key_id]
        return self.crypto.split_key_with_sss(private_key, password, threshold, shares)
    
    def reconstruct_key(self, shares: List[bytes], password: str) -> Tuple[str, str]:
        """Reconstruct private key from shares and return (key_id, fingerprint)"""
        private_key = self.crypto.reconstruct_key_from_sss(shares, password)
        
        # Derive public key for fingerprint
        temp_private = x25519.X25519PrivateKey.from_private_bytes(private_key.to_bytes())
        temp_public = temp_private.public_key()
        temp_public_bytes = temp_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        fingerprint = hashlib.sha256(temp_public_bytes).hexdigest()[:16]
        
        # Generate key ID and store
        key_id = hashlib.sha256(temp_public_bytes + secrets.token_bytes(16)).hexdigest()[:16]
        self.private_keys[key_id] = private_key
        self.private_fingerprints[key_id] = fingerprint
        
        return key_id, fingerprint
    
    def encrypt_file(self, input_path: str, output_path: str, original_filename: Optional[str] = None) -> str:
        """Encrypt file using current public key"""
        if self.public_key is None:
            raise ValueError("No public key loaded")
        
        if original_filename is None:
            original_filename = os.path.basename(input_path)
        
        return self.crypto.encrypt_file(input_path, output_path, self.public_key, original_filename)
    
    def decrypt_file(self, input_path: str, output_path: str, key_id: str) -> bool:
        """Decrypt file using specified private key"""
        if key_id not in self.private_keys:
            raise ValueError(f"Private key not found: {key_id}. Available keys: {list(self.private_keys.keys())}")
        
        private_key = self.private_keys[key_id]
        return self.crypto.decrypt_file(input_path, output_path, private_key)
    
    def get_key_info(self) -> Dict[str, Any]:
        """Get information about loaded keys"""
        return {
            "publicKeyLoaded": self.public_key is not None,
            "publicKeyFingerprint": self.public_fingerprint,
            "privateKeysInMemory": len(self.private_keys),
            "privateKeyIds": list(self.private_keys.keys()),
            "privateKeyFingerprints": self.private_fingerprints,
            "algorithm": "X25519-KEM",
            "encryption": "AES-256-GCM"
        }
    
    def configure_settings(self, chunk_size: Optional[int] = None, kdf_strength: Optional[str] = None):
        """Configure security settings"""
        if chunk_size is not None:
            self.settings.chunk_size = chunk_size
        if kdf_strength is not None:
            self.settings.set_kdf_strength(kdf_strength)
        
        # Recreate crypto instance with new settings
        self.crypto = X25519FileEncryption(self.settings)

class StegoCryptSecureSuite:
    """Main CLI interface for StegoCrypt Secure Suite"""
    
    def __init__(self):
        self.settings = SecuritySettings()
        self.crypto = X25519FileEncryption(self.settings)
        self.public_key = None
        self.private_key = None
        self.public_fingerprint = None
        self.private_fingerprint = None
    
    def display_banner(self):
        """Display application banner"""
        print("========= StegoCrypt Secure Suite =========")
        print()
    
    def display_menu(self):
        """Display main menu options"""
        print("🔑 Key Management")
        print("1. Create a new keypair")
        print("2. Load public key (for encryption)")
        print("3. Load private key (for decryption)")
        print("4. Export public key")
        print("5. Export/backup private key (with password protection)")
        print("6. Split private key into recovery shares")
        print("7. Reconstruct private key from recovery shares")
        print()
        print("🗄️ File Operations")
        print("8. Encrypt a file (requires public key)")
        print("9. Decrypt a file (requires private key)")
        print()
        print("⚙️ Advanced Options")
        print("10. View key information")
        print("11. Configure security settings (chunk size, KDF strength)")
        print()
        print("❌ Exit")
        print()
    
    def get_menu_choice(self) -> int:
        """Get user menu choice"""
        try:
            choice = input("Enter your choice (1-11, or 0 to exit): ").strip()
            if choice == '0' or choice.lower() in ['exit', 'quit']:
                return 0
            return int(choice)
        except ValueError:
            return -1
    
    def progress_display(self, current: int, total: int):
        """Progress callback for operations"""
        if total > 0:
            percent = (current * 100) // total
            bar_length = 50
            filled_length = (current * bar_length) // total
            bar = '█' * filled_length + '░' * (bar_length - filled_length)
            print(f"\rProgress: [{bar}] {percent}%", end='', flush=True)
        if current >= total:
            print()
    
    def create_new_key(self):
        """Generate new X25519 keypair"""
        print("\n🔑 Creating new X25519 keypair...")
        try:
            public_key, private_key, fingerprint = self.crypto.generate_keypair()
            
            # Store both keys
            self.public_key = public_key
            self.private_key = private_key
            self.public_fingerprint = fingerprint
            self.private_fingerprint = fingerprint  # Same for keypair
            
            print(f"✅ Success! Keypair generated")
            print(f"🔍 Fingerprint: {fingerprint}")
            print(f"📏 Key size: {len(public_key)} bytes (public), {len(private_key)} bytes (private)")
            print("ℹ️  Both public and private keys are now loaded")
            
        except Exception as e:
            print(f"❌ Error generating keypair: {e}")

    def load_public_key(self):
        """Load public key only (for encryption)"""
        print("\n🔑 Loading public key for encryption...")
        try:
            pub_file = input("📂 Public key file path: ").strip()
            
            if not os.path.exists(pub_file):
                print(f"❌ Public key file not found: {pub_file}")
                return
            
            with open(pub_file, 'rb') as f:
                key_data = f.read()
            
            # Check if this is raw key data or protected format
            try:
                # Try to parse as JSON (protected format)
                json.loads(key_data.decode('utf-8'))
                print("❌ This appears to be a protected private key, not a public key")
                return
            except (json.JSONDecodeError, UnicodeDecodeError):
                # This should be raw public key data
                if len(key_data) != 32:
                    print(f"❌ Invalid public key length: {len(key_data)} bytes (expected 32)")
                    return
                
                self.public_key = key_data
                self.public_fingerprint = hashlib.sha256(self.public_key).hexdigest()[:16]
                print(f"✅ Public key loaded successfully!")
                print(f"🔍 Fingerprint: {self.public_fingerprint}")
                print("ℹ️  You can now encrypt files with this key")
            
        except Exception as e:
            print(f"❌ Error loading public key: {e}")

    def load_private_key(self):
        """Load private key only (for decryption)"""
        print("\n🔑 Loading private key for decryption...")
        try:
            priv_file = input("📂 Private key file path: ").strip()
            
            if not os.path.exists(priv_file):
                print(f"❌ Private key file not found: {priv_file}")
                return
            
            with open(priv_file, 'rb') as f:
                private_key_data = f.read()
            
            # Check if protected (JSON format) or raw bytes
            try:
                json.loads(private_key_data.decode('utf-8'))
                # This is a protected key
                password = getpass.getpass("🔐 Private key password: ")
                self.private_key = self.crypto.unprotect_private_key(private_key_data, password)
                print("🔓 Private key unprotected successfully")
            except (json.JSONDecodeError, UnicodeDecodeError):
                # This should be raw private key data
                if len(private_key_data) != 32:
                    print(f"❌ Invalid private key length: {len(private_key_data)} bytes (expected 32)")
                    return
                self.private_key = SecureBuffer.from_bytes(private_key_data)
                print("📖 Loaded unprotected private key")
            
            # Calculate the corresponding public key fingerprint
            try:
                # Create temporary X25519 private key object to derive public key
                temp_private = x25519.X25519PrivateKey.from_private_bytes(self.private_key.to_bytes())
                temp_public = temp_private.public_key()
                temp_public_bytes = temp_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                self.private_fingerprint = hashlib.sha256(temp_public_bytes).hexdigest()[:16]
                print(f"🔍 Corresponding public key fingerprint: {self.private_fingerprint}")
                
            except Exception as e:
                print(f"⚠️ Warning: Could not calculate key fingerprint: {e}")
                self.private_fingerprint = None
            
            print(f"✅ Private key loaded successfully!")
            print("ℹ️  You can now decrypt files encrypted with the corresponding public key")
            
        except Exception as e:
            print(f"❌ Error loading private key: {e}")
            # Clean up on error
            if hasattr(self, 'private_key') and self.private_key:
                self.private_key.wipe()
                self.private_key = None
            self.private_fingerprint = None

    def export_public_key(self):
        """Export public key only"""
        if not self.public_key:
            print("❌ No public key available. Create a keypair or load a public key first.")
            return
        
        print("\n💾 Export Public Key")
        try:
            pub_file = input("📂 Public key save path(.pub): ").strip()
            
            with open(pub_file, 'wb') as f:
                f.write(self.public_key)
            
            print(f"✅ Public key exported to: {pub_file}")
            print(f"🔍 Fingerprint: {self.public_fingerprint}")
            print("ℹ️  This file can be safely shared for others to encrypt files for you")
            
        except Exception as e:
            print(f"❌ Error exporting public key: {e}")
    
    def export_private_key(self):
        """Export/backup private key with optional password protection"""
        if not self.private_key:
            print("❌ No private key available. Create a keypair or load a private key first.")
            return
        
        print("\n💾 Export/Backup Private Key")
        try:
            priv_file = input("📂 Private key save path(.priv): ").strip()
            protect = input("🔐 Protect private key with password? (y/n): ").lower() == 'y'
            
            if protect:
                password = getpass.getpass("🔐 Enter password: ")
                confirm = getpass.getpass("🔐 Confirm password: ")
                if password != confirm:
                    print("❌ Passwords don't match!")
                    return
                
                protected = self.crypto.protect_private_key(self.private_key, password)
                with open(priv_file, 'wb') as f:
                    f.write(protected)
                print(f"🔒 Private key saved (password protected) to: {priv_file}")
            else:
                with open(priv_file, 'wb') as f:
                    f.write(self.private_key.to_bytes())
                print(f"🔓 Private key saved (unprotected) to: {priv_file}")
            
            print("⚠️  Keep this file secure - it allows decryption of your files!")
            
        except Exception as e:
            print(f"❌ Error saving private key: {e}")
    
    def split_key_into_shares(self):
        """Split private key using Shamir's Secret Sharing"""
        if not self.private_key:
            print("❌ No private key available. Create or load a key first.")
            return
        
        print("\n🎯 Split Key into Recovery Shares")
        try:
            threshold = int(input("🔢 Threshold (minimum shares needed to reconstruct): "))
            total_shares = int(input("🔢 Total number of shares to create: "))
            
            if threshold > total_shares or threshold < 2:
                print("❌ Invalid threshold or share count!")
                return
            
            password = getpass.getpass("🔐 Password for key protection: ")
            base_name = input("📝 Base name for share files: ").strip()
            
            print("🔄 Splitting key into shares...")
            shares = self.crypto.split_key_with_sss(
                self.private_key, password, threshold, total_shares
            )
            
            for i, share in enumerate(shares, 1):
                share_file = f"{base_name}_share_{i:02d}.sss"
                with open(share_file, 'wb') as f:
                    f.write(share)
                print(f"💾 Share {i} saved to: {share_file}")
            
            print(f"✅ Key successfully split into {total_shares} shares (threshold: {threshold})")
            
        except Exception as e:
            print(f"❌ Error splitting key: {e}")
    
    def reconstruct_key_from_shares(self):
        """Reconstruct private key from SSS shares"""
        print("\n🔄 Reconstruct Key from Recovery Shares")
        try:
            num_shares = int(input("🔢 Number of share files to use: "))
            
            shares = []
            for i in range(num_shares):
                share_file = input(f"📂 Share file {i+1} path: ").strip()
                if not os.path.exists(share_file):
                    print(f"❌ Share file not found: {share_file}")
                    return
                
                with open(share_file, 'rb') as f:
                    shares.append(f.read())
                print(f"📖 Loaded share {i+1}")
            
            password = getpass.getpass("🔐 Enter password: ")
            
            print("🔄 Reconstructing key from shares...")
            reconstructed_key = self.crypto.reconstruct_key_from_sss(shares, password)
            
            use_key = input("🔑 Use as current private key? (y/n): ").lower() == 'y'
            if use_key:
                if self.private_key:
                    self.private_key.wipe()
                self.private_key = reconstructed_key
                print("✅ Private key reconstructed and loaded!")
                
                # Try to derive fingerprint if we have public key, otherwise generate it
                if self.public_key:
                    self.private_fingerprint = hashlib.sha256(self.public_key).hexdigest()[:16]
                    print(f"🔍 Fingerprint: {self.private_fingerprint}")
            else:
                output_file = input("📂 Save reconstructed key to file(.priv): ").strip()
                with open(output_file, 'wb') as f:
                    f.write(reconstructed_key.to_bytes())
                reconstructed_key.wipe()
                print(f"💾 Reconstructed key saved to: {output_file}")
            
        except Exception as e:
            print(f"❌ Error reconstructing key: {e}")
    
    def encrypt_file(self):
        """Encrypt a file"""
        if not self.public_key:
            print("❌ No public key available. Create or load a key first.")
            return
        
        print("\n🔒 Encrypt File")
        try:
            input_file = input("📂 Input file path: ").strip()
            if not os.path.exists(input_file):
                print(f"❌ File not found: {input_file}")
                return
            
            # Get file size for progress display
            file_size = os.path.getsize(input_file)
            print(f"📏 File size: {file_size:,} bytes")
            
            output_file = input("📂 Output file path (.x25): ").strip()
            if not output_file.endswith('.x25'):
                output_file += '.x25'
            
            print("🔄 Encrypting file...")
            fingerprint = self.crypto.encrypt_file(
                input_file, output_file, self.public_key, self.progress_display
            )
            print(f"✅ File encrypted successfully!")
            print(f"📁 Output: {output_file}")
            print(f"🔍 Key fingerprint: {fingerprint}")
            
            # Show encrypted file size
            encrypted_size = os.path.getsize(output_file)
            overhead = encrypted_size - file_size
            print(f"📊 Encrypted size: {encrypted_size:,} bytes (+{overhead} bytes overhead)")
            
        except Exception as e:
            print(f"❌ Encryption error: {e}")
    
    def decrypt_file(self):
        """Decrypt a file"""
        if not self.private_key:
            print("❌ No private key available. Load a private key first (option 3).")
            return
        
        print("\n🔓 Decrypt File")
        try:
            input_file = input("📂 Encrypted file path: ").strip()
            if not os.path.exists(input_file):
                print(f"❌ File not found: {input_file}")
                return
            
            # Try to read and display metadata first
            metadata = None
            try:
                metadata = self.crypto.read_file_metadata(input_file)
                print(f"📋 File metadata:")
                print(f"   🔍 Key fingerprint: {metadata.get('pub_fingerprint', 'Unknown')}")
                print(f"   📏 Original size: {metadata.get('original_size', 'Unknown'):,} bytes")
                print(f"   🕒 Encrypted: {metadata.get('timestamp_utc', 'Unknown')}")
                print(f"   🔐 Algorithm: {metadata.get('kem_algo', 'Unknown')}")
                
            except Exception as e:
                print(f"⚠️  Could not read file metadata: {e}")
                print("Proceeding with decryption attempt...")
            
            # Check key fingerprint compatibility if both are available
            if (metadata and 
                hasattr(self, 'private_fingerprint') and 
                self.private_fingerprint and 
                metadata.get('pub_fingerprint')):
                
                file_fingerprint = metadata.get('pub_fingerprint')
                if self.private_fingerprint != file_fingerprint:
                    print("\n⚠️  Warning: Key fingerprint mismatch detected!")
                    print(f"   📁 File was encrypted with public key: {file_fingerprint}")
                    print(f"   🔑 Your private key corresponds to:   {self.private_fingerprint}")
                    print("\n💡 This means:")
                    print("   • Your private key cannot decrypt this file")
                    print("   • You need the private key that matches fingerprint: {file_fingerprint}")
                    print("   • Decryption will fail with HMAC verification error")
                    
                    proceed = input("\nAttempt decryption anyway? (y/n): ").lower()
                    if proceed != 'y':
                        print("❌ Decryption cancelled")
                        return
                    print()
            
            output_file = input("📂 Output file path: ").strip()
            if not output_file:
                print("❌ Output file path cannot be empty")
                return
            
            # Warn if output file exists
            if os.path.exists(output_file):
                overwrite = input(f"⚠️  File '{output_file}' exists. Overwrite? (y/n): ").lower()
                if overwrite != 'y':
                    print("❌ Decryption cancelled")
                    return
            
            print("🔄 Decrypting file...")
            success = self.crypto.decrypt_file(
                input_file, output_file, self.private_key, self.progress_display
            )
            
            if success:
                print(f"✅ File decrypted successfully!")
                print(f"📁 Output: {output_file}")
                
                # Show decrypted file size and verify it matches expected size
                decrypted_size = os.path.getsize(output_file)
                expected_size = metadata.get('original_size') if metadata else None
                
                print(f"📊 Decrypted size: {decrypted_size:,} bytes")
                
                if expected_size and decrypted_size == expected_size:
                    print("✅ File size verification: PASSED")
                elif expected_size:
                    print(f"⚠️  Expected {expected_size:,} bytes, got {decrypted_size:,} bytes")
            
        except Exception as e:
            error_msg = str(e)
            print(f"❌ Decryption error: {error_msg}")
            
            # Provide specific guidance based on error type
            if "HMAC verification failed" in error_msg:
                print("\n💡 HMAC verification failed - this usually means:")
                print("   • Wrong private key for this encrypted file")
                print("   • File has been corrupted or tampered with")
                print("   • Key fingerprint mismatch (shown above)")
                print("\n🔧 To fix this:")
                print("   • Verify you have the correct private key")
                print("   • Check the key fingerprint matches the file")
                print("   • Try a different private key file")
                
            elif "Invalid file format" in error_msg:
                print("\n💡 This doesn't appear to be a valid encrypted file")
                print("   • Check the file path and extension (.x25)")
                print("   • Ensure the file wasn't corrupted during transfer")
                
            elif "verification failed" in error_msg.lower():
                print("\n💡 This might be a password or key format issue")
                print("   • Double-check your private key password")
                print("   • Verify the private key file format")
            
            # Clean up partial output file on error
            try:
                if 'output_file' in locals() and os.path.exists(output_file):
                    os.unlink(output_file)
                    print(f"🗑️  Cleaned up partial file: {output_file}")
            except:
                pass

    def view_key_fingerprint(self):
        """Display current key information and fingerprint"""
        print("\n🔍 Current Key Information")
        print("-" * 50)
        
        if self.public_key:
            print(f"✅ Public Key: Available ({len(self.public_key)} bytes)")
            print(f"🔍 Public Key Fingerprint: {self.public_fingerprint}")
            
            full_hash = hashlib.sha256(self.public_key).hexdigest()
            print(f"🔐 Full SHA256: {full_hash}")
            print("📤 Status: Can encrypt files")
        else:
            print("❌ Public Key: Not available")
            print("ℹ️  Load a public key to encrypt files")
        
        print()
        
        if self.private_key:
            print(f"✅ Private Key: Available ({len(self.private_key)} bytes)")
            print(f"🔍 Private Key Fingerprint: {self.private_fingerprint}")
            print("📥 Status: Can decrypt files")
        else:
            print("❌ Private Key: Not available")
            print("ℹ️  Load a private key to decrypt files")
        
        print()
        print(f"🔒 Algorithm: {self.crypto.kem_algo}")
        print(f"🔐 Encryption: AES-256-GCM")
        print(f"🔑 Key Derivation: HKDF-SHA256")
        print(f"🛡️  KDF Strength: {self.settings.get_kdf_strength_level()}")
        print(f"📦 Chunk Size: {self.settings.chunk_size:,} bytes")
    
    def configure_security_settings(self):
        """Configure security settings"""
        print("\n⚙️ Security Settings Configuration")
        print("-" * 50)
        print(f"Current settings:")
        print(f"📦 Chunk Size: {self.settings.chunk_size:,} bytes")
        print(f"🛡️  KDF Strength: {self.settings.get_kdf_strength_level()}")
        print(f"🔢 Scrypt N: {self.settings.scrypt_n}")
        print()
        
        print("What would you like to configure?")
        print("1. Chunk size (affects memory usage during encryption)")
        print("2. KDF strength (affects password derivation security)")
        print("3. Reset to defaults")
        print("4. Back to main menu")
        
        try:
            choice = int(input("Enter choice (1-4): "))
            
            if choice == 1:
                self.configure_chunk_size()
            elif choice == 2:
                self.configure_kdf_strength()
            elif choice == 3:
                self.reset_security_defaults()
            elif choice == 4:
                return
            else:
                print("❌ Invalid choice")
                
        except ValueError:
            print("❌ Invalid input")
    
    def configure_chunk_size(self):
        """Configure chunk size setting"""
        print("\n📦 Chunk Size Configuration")
        print("Current chunk size:", f"{self.settings.chunk_size:,} bytes")
        print()
        print("Available options:")
        print("1. 1 MB (1,048,576 bytes) - Lower memory usage")
        print("2. 4 MB (4,194,304 bytes) - Default, balanced")
        print("3. 8 MB (8,388,608 bytes) - Higher performance")
        print("4. 16 MB (16,777,216 bytes) - Maximum performance")
        print("5. Custom size")
        
        try:
            choice = int(input("Select chunk size (1-5): "))
            
            if choice == 1:
                self.settings.chunk_size = 1 * 1024 * 1024
            elif choice == 2:
                self.settings.chunk_size = 4 * 1024 * 1024
            elif choice == 3:
                self.settings.chunk_size = 8 * 1024 * 1024
            elif choice == 4:
                self.settings.chunk_size = 16 * 1024 * 1024
            elif choice == 5:
                size_mb = float(input("Enter chunk size in MB: "))
                if size_mb <= 0 or size_mb > 256:
                    print("❌ Invalid size (must be between 0.1 and 256 MB)")
                    return
                self.settings.chunk_size = int(size_mb * 1024 * 1024)
            else:
                print("❌ Invalid choice")
                return
            
            print(f"✅ Chunk size set to: {self.settings.chunk_size:,} bytes")
            
        except ValueError:
            print("❌ Invalid input")
    
    def configure_kdf_strength(self):
        """Configure KDF strength setting"""
        print("\n🛡️ KDF Strength Configuration")
        print(f"Current strength: {self.settings.get_kdf_strength_level()}")
        print(f"Current Scrypt N: {self.settings.scrypt_n}")
        print()
        print("Available strength levels:")
        print("1. Low (N=4096) - Faster, less secure")
        print("2. Medium (N=8192) - Balanced")
        print("3. High (N=16384) - Default, recommended")
        print("4. Maximum (N=32768) - Slower, most secure")
        
        try:
            choice = int(input("Select strength level (1-4): "))
            
            levels = ["low", "medium", "high", "maximum"]
            if 1 <= choice <= 4:
                level = levels[choice - 1]
                old_strength = self.settings.get_kdf_strength_level()
                self.settings.set_kdf_strength(level)
                print(f"✅ KDF strength changed from {old_strength} to {self.settings.get_kdf_strength_level()}")
                print(f"🔢 New Scrypt N: {self.settings.scrypt_n}")
                
                if choice == 4:
                    print("⚠️  Note: Maximum strength will significantly increase key derivation time")
            else:
                print("❌ Invalid choice")
                
        except ValueError:
            print("❌ Invalid input")
    
    def reset_security_defaults(self):
        """Reset security settings to defaults"""
        print("\n🔄 Reset to Default Settings")
        confirm = input("Are you sure you want to reset all settings to defaults? (y/n): ").lower()
        
        if confirm == 'y':
            self.settings = SecuritySettings()
            self.crypto = X25519FileEncryption(self.settings)
            print("✅ Security settings reset to defaults")
            print(f"📦 Chunk Size: {self.settings.chunk_size:,} bytes")
            print(f"🛡️  KDF Strength: {self.settings.get_kdf_strength_level()}")
        else:
            print("❌ Reset cancelled")
    
    def run(self):
        """Main menu loop"""
        self.display_banner()
        
        while True:
            try:
                self.display_menu()
                choice = self.get_menu_choice()
                
                if choice == 0:
                    print("👋 Thank you for using StegoCrypt Secure Suite!")
                    break
                elif choice == 1:
                    self.create_new_key()
                elif choice == 2:
                    self.load_public_key()
                elif choice == 3:
                    self.load_private_key()
                elif choice == 4:
                    self.export_public_key()
                elif choice == 5:
                    self.export_private_key()
                elif choice == 6:
                    self.split_key_into_shares()
                elif choice == 7:
                    self.reconstruct_key_from_shares()
                elif choice == 8:
                    self.encrypt_file()
                elif choice == 9:
                    self.decrypt_file()
                elif choice == 10:
                    self.view_key_fingerprint()
                elif choice == 11:
                    self.configure_security_settings()
                else:
                    print("❌ Invalid choice. Please try again.")
                
                input("\n⏸️  Press Enter to continue...")
                print("\n" + "="*50 + "\n")
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Unexpected error: {e}")
                input("\n⏸️  Press Enter to continue...")

if __name__ == "__main__":
    try:
        suite = StegoCryptSecureSuite()
        suite.run()
    except KeyboardInterrupt:
        print("\n\n👋 Program interrupted. Goodbye!")
    except Exception as e:
        print(f"\n❌ Program error: {e}")
        import traceback
        traceback.print_exc()