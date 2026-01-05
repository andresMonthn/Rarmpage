import unittest
import os
import sys

# Ajuste de path para importaciones
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from cipher.aes256_rar_adapter import AES256RARAdapter

class TestCipherEngine(unittest.TestCase):

    def setUp(self):
        self.adapter = AES256RARAdapter()

    def test_structure_validation(self):
        """Prueba la validación estructural básica (alineación de bloque)."""
        valid_block = b'\x00' * 16
        invalid_block = b'\x00' * 15
        
        self.assertTrue(self.adapter.validate_structure(valid_block))
        self.assertFalse(self.adapter.validate_structure(invalid_block))
        self.assertFalse(self.adapter.validate_structure(b""))

    def test_aes_availability(self):
        """Verifica si tenemos capacidad de descifrado (depende de 'cryptography')."""
        if self.adapter.is_available():
            # Test Vector Básico (AES-256-CBC)
            # Key: 32 bytes zeros
            key = b'\x00' * 32
            # IV: 16 bytes zeros
            iv = b'\x00' * 16
            # Plaintext: 16 bytes 'A'
            plaintext = b'A' * 16
            
            # Encrypt simulation (if we could) or just try decrypt known vector
            # Known vector for Key=0, IV=0, Plain='AAAAAAAAAAAAAAAA'
            # Using external tool result for verification logic would be ideal, 
            # but for now we check that decrypting DOES NOT crash and returns bytes.
            
            # Let's verify it accepts valid inputs
            # Mock ciphertext (16 bytes)
            ciphertext = b'\xdc\x95\xc0\x78\xa2\x40\x89\x89\xad\x48\xa2\x14\x92\x84\x20\x87' # Random garbage
            
            try:
                decrypted = self.adapter.decrypt_block(ciphertext, key, iv)
                self.assertEqual(len(decrypted), 16)
            except Exception as e:
                self.fail(f"Decrypt block raised unexpected exception: {e}")
        else:
            print("WARNING: 'cryptography' library not found. Skipping functional AES tests.")

if __name__ == '__main__':
    unittest.main()
