import unittest
import sys
import os

# Ajuste de path para importaciones
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from crypto_engine.crypto_context import CryptoContext
from kdf_engine.pbkdf2_adapter import PBKDF2Adapter

class TestKdfEngine(unittest.TestCase):

    def test_crypto_context_storage(self):
        """Verifica que CryptoContext almacene datos correctamente sin procesar."""
        # Update: CryptoContext signature changed (params instead of kdf_params)
        ctx = CryptoContext(algorithm="AES-256", params={"iter": 1000}, flags={"enc": True})
        self.assertEqual(ctx.algorithm, "AES-256")
        self.assertEqual(ctx.params["iter"], 1000)
        
    def test_pbkdf2_adapter_rfc_vector(self):
        """
        Prueba básica de conformidad usando un vector de prueba simple (RFC 6070 subset).
        """
        adapter = PBKDF2Adapter()
        
        # Test Case 1 from RFC 6070
        password = b"password"
        salt = b"salt"
        iterations = 1
        params = {"salt": salt, "iterations": iterations, "dklen": 20}
        
        # Expected Output: 120fb6cffcf8b32c43e7225256c4f837a86548c9
        expected = bytes.fromhex("120fb6cffcf8b32c43e7225256c4f837a86548c9")
        
        result = adapter.derive_key(password, params)
        self.assertEqual(result, expected)

    def test_pbkdf2_adapter_validation(self):
        """Verifica las protecciones de input."""
        adapter = PBKDF2Adapter()
        
        with self.assertRaises(TypeError):
            adapter.derive_key("string_password", {"salt": b"s", "iterations": 1})
            
        with self.assertRaises(ValueError):
            adapter.derive_key(b"pass", {"salt": None, "iterations": 1})

if __name__ == '__main__':
    unittest.main()
