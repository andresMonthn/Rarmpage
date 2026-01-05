from abc import ABC, abstractmethod

class StrategyBase(ABC):
    """
    Responsabilidad:
    Definir el contrato de una estrategia operativa.
    
    Define:
    - Inputs permitidos (configuración, wordlists, etc.)
    - Outputs esperados (éxito/fallo, metadatos del intento)
    - Estructura de ciclo de vida (prepare -> execute -> report)
    
    NO implementa lógica de ataque o validación específica.
    """

    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.is_prepared = False

    @abstractmethod
    def prepare(self, target_profile, **kwargs):
        """
        Prepara la estrategia antes de la ejecución.
        Args:
            target_profile: CryptoProfile del archivo objetivo.
            **kwargs: Parámetros adicionales (ej. ruta a wordlist).
        """
        pass

    @abstractmethod
    def generate_attempts(self):
        """
        Generador que emite intentos individuales.
        Yields:
            dict: Información del intento (ej. {'candidate': 'password123'}).
        """
        pass

    @abstractmethod
    def validate_attempt(self, attempt_info):
        """
        Valida si un intento específico tuvo éxito.
        Args:
            attempt_info (dict): Datos del intento actual.
        Returns:
            bool: True si el intento fue exitoso, False si no.
        """
        pass

    def execute(self):
        """
        Método principal que orquesta el generador y la validación.
        Este es el iterador que consumirá el ExecutionManager.
        
        Yields:
            bool: True si se encontró la solución en este paso, False si no.
        """
        if not self.is_prepared:
            raise RuntimeError(f"Strategy {self.name} not prepared. Call prepare() first.")

        for attempt in self.generate_attempts():
            success = self.validate_attempt(attempt)
            yield success
            if success:
                break

    @abstractmethod
    def report(self):
        """Retorna un resumen de la ejecución de la estrategia."""
        pass
