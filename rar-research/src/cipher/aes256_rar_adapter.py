from .cipher_interface import CipherAdapter

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False
    try:
        from .tiny_aes import AES256Cipher
        _HAS_TINY_AES = True
    except ImportError:
        _HAS_TINY_AES = False

class AES256RARAdapter(CipherAdapter):
    """
    Responsabilidad:
    Adaptar AES-256 al formato RAR, no a fuerza bruta.
    
    Uso legítimo:
    - Validación de bloque
    - Verificación estructural
    - Tests con datos conocidos
    
    📌 Esto es ingeniería de formatos, no cracking.
    """

    BLOCK_SIZE = 16 # AES block size is 128 bits (16 bytes)

    def decrypt_sample(self, key: bytes, iv: bytes = None, ciphertext: bytes = None) -> bytes:
        """
        Descifra un bloque usando AES-256-CBC (Estándar RAR5).
        Adaptado a la interfaz CipherAdapter.
        
        NOTA: La interfaz define decrypt_sample(key), pero aquí necesitamos ciphertext e iv.
        Como es un adaptador específico, podemos extender los argumentos o usar un contexto previo.
        Por compatibilidad inmediata, permitimos argumentos opcionales.
        """
        if ciphertext is None or iv is None:
             # En un diseño puro, el adaptador tendría el contexto del archivo cargado.
             # Aquí lanzamos error si no se proveen.
             raise ValueError("AES256RARAdapter requires ciphertext and iv for decrypt_sample")

        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError(f"El texto cifrado debe ser múltiplo de {self.BLOCK_SIZE} bytes.")
            
        if len(key) != 32: # 256 bits
            raise ValueError("AES-256 requiere una clave de 32 bytes.")
            
        if len(iv) != 16:
            raise ValueError("AES requiere un IV de 16 bytes.")

        if _HAS_CRYPTOGRAPHY:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            # RAR maneja el padding de forma personalizada en capas superiores,
            # aquí desciframos bloques raw.
            return decryptor.update(ciphertext) + decryptor.finalize()
        
        elif _HAS_TINY_AES:
            # Fallback a implementación pura en Python (Lento, pero funciona para validación)
            cipher = AES256Cipher(key)
            return cipher.decrypt_cbc(ciphertext, iv)
        
        else:
            raise ImportError("No se encontró librería criptográfica (cryptography o tiny_aes).")

    # Mantenemos decrypt_block como alias para compatibilidad interna temporal si es necesario
    def decrypt_block(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        return self.decrypt_sample(key, iv=iv, ciphertext=ciphertext)

    def validate_structure(self, data: bytes) -> bool:
        """
        Valida alineación de bloque para AES.
        """
        if not isinstance(data, bytes):
            return False
        if len(data) == 0:
            return False
        return len(data) % self.BLOCK_SIZE == 0

    def is_available(self) -> bool:
        """Indica si el motor criptográfico real está disponible."""
        return _HAS_CRYPTOGRAPHY
