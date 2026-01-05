import unittest
import time
from unittest.mock import MagicMock

# Ajuste de path para importaciones
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from orchestrator.execution_manager import ExecutionManager

class TestExecutionManager(unittest.TestCase):
    def setUp(self):
        self.mock_profile = MagicMock()
        self.manager = ExecutionManager(self.mock_profile)

    def test_limits_attempts(self):
        """Verifica que el manager se detenga al alcanzar el límite de intentos."""
        self.manager.set_limits(max_attempts=5)
        
        # Estrategia infinita que siempre falla
        def infinite_strategy():
            while True:
                yield False

        result = self.manager.start(infinite_strategy())
        
        self.assertFalse(result)
        self.assertEqual(self.manager.attempts, 5)

    def test_limits_time(self):
        """Verifica que el manager se detenga al alcanzar el límite de tiempo."""
        self.manager.set_limits(max_time_seconds=0.1) # 100ms
        
        def slow_strategy():
            while True:
                time.sleep(0.05) # 50ms
                yield False

        start = time.time()
        result = self.manager.start(slow_strategy())
        elapsed = time.time() - start
        
        self.assertFalse(result)
        # Debería haber corrido al menos 1 o 2 veces, pero detenerse cerca de 0.1s
        self.assertLess(elapsed, 0.3) # Margen de error
        self.assertGreater(self.manager.attempts, 0)

    def test_success(self):
        """Verifica que retorne True si la estrategia encuentra solución."""
        self.manager.set_limits(max_attempts=10)
        
        def success_strategy():
            yield False
            yield False
            yield True # Éxito en el 3er intento
            
        result = self.manager.start(success_strategy())
        
        self.assertTrue(result)
        self.assertEqual(self.manager.attempts, 3)

if __name__ == '__main__':
    unittest.main()
