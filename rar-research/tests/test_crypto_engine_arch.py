import unittest
import time
import sys
import os

# Ajuste de path para importaciones
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from crypto_engine.crypto_context import CryptoContext
from crypto_engine.execution_limits import ExecutionLimits, LimitExceededError

class TestCryptoEngineArchitecture(unittest.TestCase):

    def test_crypto_context_responsibilities(self):
        """
        Valida que CryptoContext mantenga estado, referencias y no persista secretos.
        """
        # 1. Estado y Params
        ctx = CryptoContext(algorithm="AES-256", params={"iv": "1234"}, flags={"debug": True})
        self.assertEqual(ctx.algorithm, "AES-256")
        self.assertTrue(ctx.flags["debug"])
        
        # 2. Referencias a Adaptadores
        ctx.register_adapter("kdf", "DummyAdapterInstance")
        self.assertEqual(ctx.get_adapter("kdf"), "DummyAdapterInstance")
        
        # 3. Serialización Segura (to_dict)
        # Simulamos un param sensible
        ctx.params["password"] = "secret123" 
        safe_dict = ctx.to_dict()
        self.assertNotIn("password", safe_dict["params"]) # Debe ser filtrado
        self.assertIn("iv", safe_dict["params"])

    def test_execution_limits_safe_mode(self):
        """Valida los límites en modo seguro (por defecto)."""
        limits = ExecutionLimits(mode="SAFE")
        limits.start_timer()
        
        # Iteraciones dentro del límite
        try:
            limits.check_limits(current_iterations=100)
        except LimitExceededError:
            self.fail("check_limits raised LimitExceededError unexpectedly in SAFE mode")

        # Iteraciones fuera del límite (DEFAULT_MAX_ITERATIONS = 100,000)
        with self.assertRaises(LimitExceededError):
            limits.check_limits(current_iterations=100_001)

    def test_execution_limits_timeout(self):
        """Valida el mecanismo de timeout."""
        limits = ExecutionLimits(mode="SAFE")
        # Forzamos un timeout muy corto para el test
        limits.timeout = 0.01 
        limits.start_timer()
        
        time.sleep(0.02)
        
        with self.assertRaises(TimeoutError):
            limits.check_limits(current_iterations=0)

    def test_execution_limits_research_mode(self):
        """Valida que el modo RESEARCH permita umbrales más altos."""
        limits = ExecutionLimits(mode="RESEARCH")
        self.assertEqual(limits.max_iterations, ExecutionLimits.RESEARCH_MAX_ITERATIONS)
        self.assertGreater(limits.timeout, 5.0)

if __name__ == '__main__':
    unittest.main()
