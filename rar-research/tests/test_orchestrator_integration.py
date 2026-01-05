import unittest
import sys
import os

# Ajuste de path para importaciones
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from orchestrator.execution_manager import ExecutionManager
from orchestrator.controlled_validation_strategy import ControlledValidationStrategy

class TestOrchestrationIntegration(unittest.TestCase):
    
    def test_validation_flow_success(self):
        """
        Prueba el flujo completo:
        Manager -> Strategy -> Success
        """
        # 1. Configurar Estrategia
        strategy = ControlledValidationStrategy()
        candidates = ["wrong1", "wrong2", "secret", "wrong3"]
        strategy.prepare(target_profile=None, candidate_list=candidates, correct_password="secret")
        
        # 2. Configurar Manager
        manager = ExecutionManager(profile=None)
        manager.set_limits(max_attempts=10) # Límite holgado
        
        # 3. Ejecutar
        # El manager consume el iterador strategy.execute()
        result = manager.start(strategy.execute())
        
        # 4. Verificar
        self.assertTrue(result, "El manager debería reportar éxito.")
        self.assertEqual(manager.attempts, 3, "Debería detenerse en el 3er intento ('secret').")

    def test_validation_flow_failure(self):
        """
        Prueba flujo de fallo:
        Manager -> Strategy -> Exhausted -> Failure
        """
        strategy = ControlledValidationStrategy()
        candidates = ["wrong1", "wrong2"]
        strategy.prepare(target_profile=None, candidate_list=candidates, correct_password="secret")
        
        manager = ExecutionManager(profile=None)
        
        result = manager.start(strategy.execute())
        
        self.assertFalse(result, "El manager debería reportar fallo.")
        self.assertEqual(manager.attempts, 2, "Debería probar todos los candidatos.")

    def test_validation_flow_limit(self):
        """
        Prueba interrupción por límite del manager:
        Manager (Limit=1) -> Strategy (2 candidates) -> Failure (Stopped)
        """
        strategy = ControlledValidationStrategy()
        candidates = ["wrong1", "secret"]
        strategy.prepare(target_profile=None, candidate_list=candidates, correct_password="secret")
        
        manager = ExecutionManager(profile=None)
        manager.set_limits(max_attempts=1) # Solo permitimos 1 intento
        
        result = manager.start(strategy.execute())
        
        self.assertFalse(result, "Debería fallar por límite de intentos.")
        self.assertEqual(manager.attempts, 1, "Solo debió ejecutar 1 intento.")

if __name__ == '__main__':
    unittest.main()
