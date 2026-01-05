import unittest
import sys
import os
import json

# Asegurar path
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from reporting import metrics
from reporting.exporter import Exporter

class TestReporting(unittest.TestCase):
    
    def setUp(self):
        self.sample_data = {
            metrics.CIPHER_ALGO: "AES-256",
            metrics.KDF_ALGO: "PBKDF2-HMAC-SHA256",
            metrics.KDF_ITERATIONS: 32800,
            metrics.SALT_HEX: "00112233"
        }
        self.exporter = Exporter()

    def test_metrics_constants(self):
        """Verifica que las constantes existan y tengan valor."""
        self.assertEqual(metrics.KDF_ITERATIONS, "kdf_iterations")
        self.assertIn(metrics.CIPHER_ALGO, metrics.REQUIRED_METRICS)

    def test_validate_consistency_success(self):
        """Valida un diccionario correcto."""
        self.assertTrue(metrics.validate_consistency(self.sample_data))

    def test_validate_consistency_fail(self):
        """Valida que falle si faltan claves obligatorias."""
        bad_data = {metrics.CIPHER_ALGO: "AES"} # Falta iterations, salt, etc.
        self.assertFalse(metrics.validate_consistency(bad_data))

    def test_export_json(self):
        """Verifica la exportación a JSON."""
        json_str = self.exporter.to_json(self.sample_data)
        loaded = json.loads(json_str)
        self.assertEqual(loaded[metrics.CIPHER_ALGO], "AES-256")
        self.assertEqual(loaded[metrics.KDF_ITERATIONS], 32800)

    def test_export_csv(self):
        """Verifica la exportación a CSV."""
        # Probamos con una lista de datos
        data_list = [self.sample_data, self.sample_data.copy()]
        csv_str = self.exporter.to_csv(data_list)
        
        lines = csv_str.strip().split('\n')
        # Header + 2 data lines = 3 lines
        self.assertEqual(len(lines), 3)
        self.assertIn("kdf_iterations", lines[0]) # Header
        self.assertIn("AES-256", lines[1]) # Data

    def test_export_csv_single_dict(self):
        """Verifica que to_csv maneje un solo diccionario envolviéndolo en lista."""
        csv_str = self.exporter.to_csv(self.sample_data)
        lines = csv_str.strip().split('\n')
        self.assertEqual(len(lines), 2) # Header + 1 data line

if __name__ == '__main__':
    unittest.main()
