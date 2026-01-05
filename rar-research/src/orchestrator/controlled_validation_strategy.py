from .strategy_base import StrategyBase
import time

class ControlledValidationStrategy(StrategyBase):
    """
    Responsabilidad:
    Estrategia de validación controlada para pruebas de pipeline.
    
    Uso:
    - Contraseñas conocidas previamente.
    - Validación de flujo sin ataque real (simulación).
    
    📌 Esto es clave: validar implementación ≠ atacar archivo.
    """

    def __init__(self):
        super().__init__(
            name="Controlled Validation", 
            description="Valida el pipeline usando una lista predefinida de candidatos."
        )
        self.candidates = []
        self.target_hash_simulator = None # Simulación de validación

    def prepare(self, target_profile, candidate_list=None, correct_password=None):
        """
        Configura la lista de validación.
        
        Args:
            target_profile: Perfil criptográfico (no usado activamente en simulación simple).
            candidate_list (list): Lista de contraseñas a probar.
            correct_password (str): Contraseña 'correcta' simulada para validar el éxito.
        """
        if candidate_list is None:
            candidate_list = []
            
        self.candidates = candidate_list
        self.correct_password = correct_password
        self.is_prepared = True
        self.attempts_made = 0

    def generate_attempts(self):
        """Emite candidatos de la lista predefinida."""
        for candidate in self.candidates:
            self.attempts_made += 1
            # Simulamos un pequeño retraso de procesamiento si fuera necesario
            # time.sleep(0.001) 
            yield {'candidate': candidate}

    def validate_attempt(self, attempt_info):
        """
        Simula la validación comparando con la contraseña correcta conocida.
        En un caso real, esto llamaría a las primitivas criptográficas (AES/Hash).
        """
        candidate = attempt_info.get('candidate')
        
        if self.correct_password and candidate == self.correct_password:
            return True
        return False

    def report(self):
        return {
            "strategy": self.name,
            "attempts": self.attempts_made,
            "total_candidates": len(self.candidates),
            "found": False # Se actualizaría externamente si se detiene por éxito
        }
