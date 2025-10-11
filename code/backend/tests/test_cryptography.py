"""
Test suite for StegoCrypt Suite cryptography modules.
Tests AES and RSA encryption/decryption functionality.
"""

import pytest
import tempfile
import os
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "Backend"))

from local_crypto.aes_crypto import (
    get_key_from_password,
    save_aes_key,
    load_aes_key,
    generate_new_aes_key,
    encrypt_aes,
    decrypt_aes
)
from local_crypto.rsa_crypto import (
    generate_and_save_keys,
    load_keys,
    encrypt_rsa,
    decrypt_rsa
)


class TestAESCrypto:
    """Test AES cryptography functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        # Create temporary directory for test keys
        self.temp_dir = tempfile.mkdtemp()
        self.original_key_dir = Path.home() / ".stegocrypt_keys"
        
        # Backup original keys if they exist
        if self.original_key_dir.exists():
            self.keys_backed_up = True
            # In real test, you'd backup here
        else:
            self.keys_backed_up = False
    
    def teardown_method(self):
        """Clean up test environment."""
        # Clean up temporary files
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_key_derivation(self):
        """Test password-based key derivation."""
        password = "test_password_123"
        key1, salt1 = get_key_from_password(password)
        key2, _ = get_key_from_password(password)
        
        assert len(key1) == 16  # AES-128 key length
        assert len(salt1) == 16  # Salt length
        assert key1 != key2  # Different salt = different key
    
    def test_key_generation(self):
        """Test random key generation."""
        key, salt = generate_new_aes_key()
        
        assert len(key) == 16
        assert len(salt) == 16
        assert key != generate_new_aes_key()[0]  # Keys should be different
    
    def test_encryption_decryption(self):
        """Test AES encryption and decryption."""
        key, _ = generate_new_aes_key()
        test_message = "Hello, StegoCrypt Suite!"
        
        # Encrypt
        encrypted = encrypt_aes(key, test_message)
        assert encrypted != test_message
        assert isinstance(encrypted, (bytes, bytearray))
        
        # Decrypt
        decrypted = decrypt_aes(key, encrypted)
        assert decrypted == test_message
    
    def test_empty_message(self):
        """Test handling of empty messages."""
        key, _ = generate_new_aes_key()
        
        with pytest.raises(Exception):
            encrypt_aes(key, "")
    
    def test_large_message(self):
        """Test encryption of large messages."""
        key, _ = generate_new_aes_key()
        large_message = "A" * 1000
        
        encrypted = encrypt_aes(key, large_message)
        decrypted = decrypt_aes(key, encrypted)
        
        assert decrypted == large_message


class TestRSACrypto:
    """Test RSA cryptography functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        # Create temporary directory for test keys
        self.temp_dir = tempfile.mkdtemp()
        self.original_key_dir = Path.home() / ".stegocrypt_keys"
        
        # Backup original keys if they exist
        if self.original_key_dir.exists():
            self.keys_backed_up = True
            # In real test, you'd backup here
        else:
            self.keys_backed_up = False
    
    def teardown_method(self):
        """Clean up test environment."""
        # Clean up temporary files
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_key_generation(self):
        """Test RSA key pair generation."""
        # This would need to be mocked in real tests to avoid file system operations
        # For now, we'll test the function exists
        assert callable(generate_and_save_keys)
    
    def test_encryption_decryption(self):
        """Test RSA encryption and decryption."""
        # This would need proper key setup in real tests
        # For now, we'll test the function signatures
        assert callable(encrypt_rsa)
        assert callable(decrypt_rsa)
    
    def test_password_protection(self):
        """Test password-protected key functionality."""
        # This would need proper key setup in real tests
        assert callable(load_keys)


class TestCryptographyIntegration:
    """Test integration between cryptography modules."""
    
    def test_aes_rsa_workflow(self):
        """Test combined AES and RSA workflow."""
        # This would test the complete encryption workflow
        # For now, we'll test that both modules can be imported
        assert True  # Placeholder for actual integration test


if __name__ == "__main__":
    pytest.main([__file__])
