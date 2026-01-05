import unittest
import sys
import os

# Ajuste de path para importaciones
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from validation.structure_validator import StructureValidator
from validation.result_classifier import ValidationState, ResultClassifier

class TestValidationSystem(unittest.TestCase):

    def setUp(self):
        self.validator = StructureValidator()

    def test_classifier_states(self):
        """Verifica que el clasificador describa los estados correctamente."""
        self.assertIn("Éxito", ResultClassifier.describe(ValidationState.VALID_STRUCTURE))
        self.assertIn("Fallo", ResultClassifier.describe(ValidationState.INVALID_KEY))

    def test_validator_known_signatures(self):
        """Verifica que detecte firmas conocidas (ej. PNG header)."""
        # Header PNG real
        png_data = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' + b'\x00' * 10
        state = self.validator.validate_decrypted_block(png_data)
        self.assertEqual(state, ValidationState.VALID_STRUCTURE)

    def test_validator_random_noise(self):
        """Verifica que el ruido aleatorio sea marcado como clave inválida."""
        # Generar ruido aleatorio (simulando descifrado AES con clave errónea)
        import random
        random_bytes = bytes([random.randint(0, 255) for _ in range(100)])
        # Asegurar que no empiece accidentalmente con una firma (improbable pero posible)
        if random_bytes.startswith(b'\x89\x50'): 
             random_bytes = b'\xFF' + random_bytes[1:]
             
        state = self.validator.validate_decrypted_block(random_bytes)
        self.assertEqual(state, ValidationState.INVALID_KEY)

    def test_validator_rar_heuristics(self):
        """Verifica la heurística de ceros para estructuras internas."""
        # Bloque con muchos ceros (típico de padding o estructuras sparse)
        sparse_block = b'\x00' * 50 + b'\x01\x02'
        state = self.validator.validate_decrypted_block(sparse_block)
        # Según nuestra heurística simple (>30% ceros), esto debería pasar como estructura potencial
        self.assertEqual(state, ValidationState.VALID_STRUCTURE)

if __name__ == '__main__':
    unittest.main()
