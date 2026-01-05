from enum import Enum, auto

class ValidationState(Enum):
    """
    Estados posibles tras la validación de un intento de descifrado.
    """
    VALID_STRUCTURE = "VALID_STRUCTURE" # Estructura correcta (éxito)
    INVALID_KEY = "INVALID_KEY"         # Basura aleatoria (clave incorrecta)
    CORRUPT_OUTPUT = "CORRUPT_OUTPUT"   # Estructura parcial o dañada

class ResultClassifier:
    """
    Responsabilidad:
    Clasificar resultados exponiendo los estados.
    """
    
    @staticmethod
    def describe(state: ValidationState) -> str:
        """Retorna una descripción humana del estado."""
        if state == ValidationState.VALID_STRUCTURE:
            return "Éxito: La estructura desencriptada es válida."
        elif state == ValidationState.INVALID_KEY:
            return "Fallo: El resultado no tiene estructura reconocible (probablemente clave errónea)."
        elif state == ValidationState.CORRUPT_OUTPUT:
            return "Error: Se detectaron rastros de estructura pero están corruptos."
        return "Estado desconocido."
