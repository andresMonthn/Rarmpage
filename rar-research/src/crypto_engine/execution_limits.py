import time

class ExecutionLimits:
    """
    Responsabilidad:
    Garantizar que el sistema no se descontrole (Arquitectura Defensiva).
    
    Define:
    - Máximo de iteraciones
    - Timeout global
    - Modos de operación (Seguro vs Investigación)
    """

    # Constantes por defecto (Modo Seguro)
    DEFAULT_MAX_ITERATIONS = 100_000 # Límite razonable para pruebas rápidas
    DEFAULT_TIMEOUT_SECONDS = 5.0    # Timeout estricto para evitar bloqueos
    
    # Modo Investigación (Permite cargas más pesadas)
    RESEARCH_MAX_ITERATIONS = 10_000_000
    RESEARCH_TIMEOUT_SECONDS = 60.0

    def __init__(self, mode: str = "SAFE"):
        self.mode = mode.upper()
        self._start_time = None
        
        if self.mode == "RESEARCH":
            self.max_iterations = self.RESEARCH_MAX_ITERATIONS
            self.timeout = self.RESEARCH_TIMEOUT_SECONDS
        else:
            self.max_iterations = self.DEFAULT_MAX_ITERATIONS
            self.timeout = self.DEFAULT_TIMEOUT_SECONDS

    def start_timer(self):
        """Inicia el temporizador de ejecución."""
        self._start_time = time.time()

    def check_limits(self, current_iterations: int = 0):
        """
        Verifica si se han excedido los límites definidos.
        Lanza excepciones si se violan las reglas.
        """
        # 1. Chequeo de Iteraciones
        if current_iterations > self.max_iterations:
            raise LimitExceededError(f"Iteration limit exceeded: {current_iterations} > {self.max_iterations}")

        # 2. Chequeo de Tiempo (Timeout)
        if self._start_time:
            elapsed = time.time() - self._start_time
            if elapsed > self.timeout:
                raise TimeoutError(f"Execution timed out: {elapsed:.2f}s > {self.timeout}s")

    def get_limits_summary(self):
        return {
            "mode": self.mode,
            "max_iterations": self.max_iterations,
            "timeout_seconds": self.timeout
        }

class LimitExceededError(Exception):
    """Excepción lanzada cuando se supera un límite de cantidad."""
    pass
