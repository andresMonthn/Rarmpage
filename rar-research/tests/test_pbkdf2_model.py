import unittest
import sys
import os

# Asegurar que podemos importar src
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from kdf.pbkdf2_model import PBKDF2Model

class TestPBKDF2Model(unittest.TestCase):
    def test_model_structure(self):
        """Verifica que el modelo sea descriptivo y no requiera dependencias externas."""
        model = PBKDF2Model(hash_algorithm='sha256', output_length=32)
        desc = model.describe()
        
        self.assertEqual(desc['PRF'], 'HMAC-SHA256')
        self.assertIn('DK = PBKDF2', desc['Formula'])
        
    def test_explain_steps(self):
        """Verifica los cálculos teóricos de costo."""
        model = PBKDF2Model(hash_algorithm='sha256', output_length=32)
        steps = model.explain_steps(password_len=8, salt_len=16, iterations=1000)
        
        # Para 32 bytes output y SHA256 (32 bytes), es 1 bloque.
        # Costo total = 1 * 1000 = 1000 HMAC calls
        self.assertTrue(any("1000 operaciones HMAC" in s for s in steps))
        
    def test_no_hashlib_dependency(self):
        """Asegura que no estamos importando hashlib en el módulo (inspección básica)."""
        import kdf.pbkdf2_model
        with open(kdf.pbkdf2_model.__file__, 'r') as f:
            content = f.read()
            self.assertNotIn("import hashlib", content)
            self.assertNotIn("from hashlib", content)

if __name__ == '__main__':
    unittest.main()
