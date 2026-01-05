import hashlib
from .kdf_interface import KDFEngine

class PBKDF2Adapter(KDFEngine):
    """
    Responsabilidad:
    Adaptador técnico a PBKDF2 solo para entornos de prueba.
    
    Reglas:
    - Inputs controlados
    - Sin loops abiertos
    - Sin paralelización agresiva
    
    📌 Uso exclusivo para validación y medición, no ataque masivo.
    """

    def derive_key(self, secret: bytes, params: dict = None) -> bytes:
        """
        Implementación concreta de PBKDF2-HMAC-SHA256 usando hashlib.
        
        Args:
            secret (bytes): Contraseña.
            params (dict): Debe contener 'salt' y 'iterations'.
            
        Returns:
            bytes: Clave derivada.
        """
        if not isinstance(secret, bytes):
            raise TypeError("Secret must be bytes")
            
        # Params ahora es opcional en la interfaz base pero necesario aqui
        # Ajustamos para cumplir firma base: derive_key(self, secret: bytes) -> bytes
        # PERO PBKDF2 necesita params. 
        # SOLUCIÓN: Asumimos que esta clase se instancia o configura con contexto,
        # O aceptamos params como argumento extra (python permite kwargs en implementacion)
        # Por ahora mantengo compatibilidad con código existente que pasa params
        
        if params is None:
             raise ValueError("PBKDF2 requires params (salt, iterations)")

        salt = params.get('salt')
        iterations = params.get('iterations')
        dklen = params.get('dklen', 32) # Default 32 bytes for AES-256
        
        if not salt or not isinstance(salt, bytes):
            raise ValueError("Valid salt (bytes) is required")
        
        if not iterations or iterations < 1:
            raise ValueError("Positive iteration count is required")

        # Ejecución controlada usando la librería estándar
        return hashlib.pbkdf2_hmac(
            hash_name='sha256',
            password=secret,
            salt=salt,
            iterations=iterations,
            dklen=dklen
        )

    def cost_profile(self):
        """
        Retorna el perfil de costo estándar para PBKDF2-SHA256.
        """
        return {
            "algorithm": "PBKDF2-HMAC-SHA256",
            "cpu_intensive": True,
            "memory_intensive": False,
            "parallelizable": False,
            "note": "Suitable for validation, not attack"
        }
