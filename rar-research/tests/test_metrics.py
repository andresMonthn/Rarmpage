import unittest
import time
import os
import sys

# Ajuste de path
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from metrics.execution_metrics import ExecutionMetrics

class TestExecutionMetrics(unittest.TestCase):

    def test_measurement_basics(self):
        """Verifica que mida tiempo y memoria mayor a cero."""
        metrics = ExecutionMetrics()
        metrics.start()
        
        # Simular carga de trabajo
        _ = [i for i in range(100000)] # Consume RAM y CPU
        time.sleep(0.01) # Consume Tiempo
        
        result = metrics.stop()
        
        self.assertGreater(result["duration_seconds"], 0.0)
        self.assertGreater(result["peak_memory_bytes"], 0)
        self.assertIn("cost_factor", result)

    def test_cost_factor_consistency(self):
        """Verifica que el factor de costo sea consistente (mayor trabajo = mayor costo)."""
        # Trabajo pequeño
        metrics_small = ExecutionMetrics()
        metrics_small.start()
        time.sleep(0.001)
        res_small = metrics_small.stop()
        
        # Trabajo grande
        metrics_large = ExecutionMetrics()
        metrics_large.start()
        time.sleep(0.05)
        res_large = metrics_large.stop()
        
        self.assertGreater(res_large["cost_factor"], res_small["cost_factor"])

    def test_helper_wrapper(self):
        """Verifica el helper estático."""
        def dummy_work():
            time.sleep(0.01)
            
        result = ExecutionMetrics.measure_function(dummy_work)
        self.assertGreater(result["duration_seconds"], 0.009)

if __name__ == '__main__':
    unittest.main()
