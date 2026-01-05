import binascii
from .result_classifier import ValidationState

class StructureValidator:
    """
    Responsabilidad:
    Validar si un resultado es estructuralmente correcto.
    
    Criterios:
    - Headers válidos (Magic bytes conocidos)
    - Integridad estructural (CRC si es posible, longitud)
    - Decisión binaria: "¿Se abrió?" (Es parseable)
    """

    def __init__(self):
        # Firmas comunes de archivos para detección heurística en payloads
        self.known_signatures = {
            b'\x52\x61\x72\x21': "RAR",   # Rar!
            b'\x50\x4B\x03\x04': "ZIP",   # PK..
            b'\x25\x50\x44\x46': "PDF",   # %PDF
            b'\x89\x50\x4E\x47': "PNG",   # .PNG
            b'\xFF\xD8\xFF': "JPG",       # JPG marker
            # Añadir más según necesidad del research scope
        }

    def validate_decrypted_block(self, data: bytes) -> ValidationState:
        """
        Analiza un bloque de datos descifrados para determinar su validez.
        
        Args:
            data (bytes): Los datos resultantes del descifrado.
            
        Returns:
            ValidationState: El estado clasificado.
        """
        if not data:
            return ValidationState.INVALID_KEY

        # 1. Análisis de Entropía / Aleatoriedad
        # Datos mal descifrados suelen tener alta entropía y distribución uniforme (ruido).
        # Datos estructurados suelen tener patrones, ceros, textos, etc.
        # (Implementación simplificada: buscar firmas)

        # 2. Búsqueda de Magia (Headers)
        # Si encontramos una firma conocida al inicio, es un fuerte indicador de éxito.
        for signature, _ in self.known_signatures.items():
            if data.startswith(signature):
                # Podríamos añadir validación de CRC aquí si el formato lo permite
                return ValidationState.VALID_STRUCTURE

        # 3. Heurísticas de Estructura RAR interna (Service headers)
        # RAR5 usa estructuras VINT y tipos de header específicos.
        # Si detectamos un patrón VINT válido seguido de un tipo de header conocido,
        # podría ser una estructura válida interna.
        if self._looks_like_rar_structure(data):
             return ValidationState.VALID_STRUCTURE

        # 4. Caso por defecto: Ruido
        # Si no parece nada conocido, asumimos clave incorrecta.
        # (Para distinguir CORRUPT_OUTPUT se requeriría un análisis más profundo:
        #  ej. CRC falla pero header ok)
        
        return ValidationState.INVALID_KEY

    def _looks_like_rar_structure(self, data: bytes) -> bool:
        """
        Intenta detectar si los bytes parecen una estructura interna de RAR (Service Header).
        Esto es heurístico y básico.
        """
        if len(data) < 3:
            return False
            
        # Ejemplo muy simplificado:
        # RAR5 headers a menudo empiezan con CRC (4 bytes) + Size (VINT) + Type (VINT)
        # Validar esto rigurosamente requiere el parser completo.
        # Aquí asumimos que si vemos muchos nulos o patrones repetitivos NO es ruido puro.
        
        # Si el 30% de los bytes son 0x00, es probable que sea estructura y no ruido AES random.
        zeros = data.count(b'\x00')
        if len(data) > 0 and (zeros / len(data)) > 0.3:
            return True
            
        return False
