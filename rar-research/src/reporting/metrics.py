"""
Módulo de definición de métricas estándar del proyecto.
Responsabilidad:
- Definir nombres de métricas como constantes.
- Validar consistencia de los diccionarios de datos.
"""

# Identificación de Algoritmos
CIPHER_ALGO = "cipher_algorithm"
KDF_ALGO = "kdf_algorithm"

# Parámetros KDF
KDF_ITERATIONS = "kdf_iterations"
SALT_HEX = "salt_hex"
KDF_OUTPUT_LEN = "kdf_output_length"

# Métricas de Costo y Rendimiento
ESTIMATED_COST_UNIT = "estimated_cost_unit" # e.g. "HMAC calls"
TOTAL_HMAC_CALLS = "total_hmac_calls"
BENCHMARK_SPEED_HS = "benchmark_speed_hs"   # Hashes per second

# Lista de métricas obligatorias para un reporte completo
REQUIRED_METRICS = [
    CIPHER_ALGO,
    KDF_ALGO,
    KDF_ITERATIONS,
    SALT_HEX
]

def validate_consistency(data: dict) -> bool:
    """
    Valida que el diccionario de datos contenga las claves obligatorias.
    
    Args:
        data (dict): Diccionario con métricas.
        
    Returns:
        bool: True si es consistente, False si faltan claves.
        
    Raises:
        ValueError: Si data no es un diccionario.
    """
    if not isinstance(data, dict):
        raise ValueError("Data must be a dictionary")
        
    missing = [key for key in REQUIRED_METRICS if key not in data]
    
    if missing:
        # En una implementación estricta podríamos lanzar error,
        # pero aquí retornamos False para manejo suave.
        return False
        
    return True
