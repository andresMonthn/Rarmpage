import time
import tracemalloc
from typing import Dict, Any

class ExecutionMetrics:
    """
    Responsabilidad:
    Medir comportamiento del sistema durante operaciones criptográficas.
    
    Mide:
    - Tiempo de ejecución (Wall clock).
    - Memoria consumida (Peak allocation).
    - Costo relativo (Tiempo/Operación).
    
    NO:
    - No cuenta intentos (no es un tracker de cracking).
    - No optimiza ataques.
    """

    def __init__(self):
        self._start_time = 0.0
        self._end_time = 0.0
        self._peak_memory = 0
        self._running = False

    def start(self):
        """Inicia la medición de recursos."""
        if self._running:
            return
        
        self._running = True
        tracemalloc.start()
        self._start_time = time.perf_counter()

    def stop(self) -> Dict[str, Any]:
        """
        Detiene la medición y retorna métricas.
        
        Returns:
            Dict con 'duration_seconds', 'peak_memory_bytes', 'cost_factor'.
        """
        if not self._running:
            return {}

        self._end_time = time.perf_counter()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self._running = False
        
        self._peak_memory = peak
        duration = self._end_time - self._start_time

        return {
            "duration_seconds": duration,
            "peak_memory_bytes": self._peak_memory,
            "cost_factor": self._calculate_cost_factor(duration, self._peak_memory)
        }

    def _calculate_cost_factor(self, duration: float, memory: int) -> float:
        """
        Calcula un índice de costo relativo sintético.
        Útil para comparar diferentes configuraciones de KDF.
        Fórmula arbitraria para investigación: (Tiempo * 1000) + (Memoria / 1MB)
        """
        mem_mb = memory / (1024 * 1024)
        return (duration * 1000) + mem_mb

    @staticmethod
    def measure_function(func, *args, **kwargs) -> Dict[str, Any]:
        """Helper para medir una función individual."""
        metrics = ExecutionMetrics()
        metrics.start()
        try:
            func(*args, **kwargs)
        finally:
            # Detener medición siempre, pero permitir que las excepciones se propaguen
            result = metrics.stop()
        return result
