class CryptoProfile:
    """
    Representa el perfil criptográfico de un archivo RAR.
    Responsable de normalizar la información de seguridad, inferir algoritmos y configuraciones.
    """
    
    # Defaults de RAR5
    DEFAULT_ALGORITHM = "AES-256"
    DEFAULT_KDF = "PBKDF2-HMAC-SHA256"
    DEFAULT_ITERATIONS = 32768 + 32  # 2^15 + 32
    
    def __init__(self):
        self.is_encrypted = False
        self.is_header_encrypted = False
        self.algorithm = None
        self.kdf_algorithm = None
        self.salt = None
        self.iterations = None
        self.psw_check_value = None # Checksum para validar contraseña rápidamente

    def set_encrypted(self, is_encrypted=True):
        self.is_encrypted = is_encrypted
        if is_encrypted and not self.algorithm:
            self.algorithm = self.DEFAULT_ALGORITHM
            self.kdf_algorithm = self.DEFAULT_KDF

    def set_header_encrypted(self, is_header_encrypted=True):
        self.is_header_encrypted = is_header_encrypted
        self.set_encrypted(True)

    def set_salt(self, salt_bytes):
        if salt_bytes and len(salt_bytes) != 16:
            # RAR5 usa salts de 16 bytes (128 bits)
            # Podríamos lanzar warning, pero por robustez lo almacenamos
            pass
        self.salt = salt_bytes

    def set_iterations(self, count=None):
        """
        Establece el número de iteraciones.
        Si count es None o 0, asume el default de RAR5.
        """
        if count is None or count == 0:
            self.iterations = self.DEFAULT_ITERATIONS
        else:
            self.iterations = count

    def infer_from_flags(self, flags):
        """
        Infiere propiedades basadas en flags crudos del header.
        (Este método podría expandirse según la especificación de flags de RAR5)
        """
        # Placeholder para lógica futura de inferencia
        pass

    def normalize(self):
        """
        Retorna una representación normalizada del perfil, compatible con metrics.py.
        Alias de to_dict() con mapeo a claves estándar.
        """
        from reporting import metrics
        
        # Aseguramos defaults si está vacío para evitar errores en reportes
        algo = self.algorithm or self.DEFAULT_ALGORITHM
        kdf = self.kdf_algorithm or self.DEFAULT_KDF
        iterations = self.iterations or self.DEFAULT_ITERATIONS
        salt = self.salt.hex() if self.salt else None

        return {
            metrics.CIPHER_ALGO: algo,
            metrics.KDF_ALGO: kdf,
            metrics.KDF_ITERATIONS: iterations,
            metrics.SALT_HEX: salt,
            "is_encrypted": self.is_encrypted,
            "header_encrypted": self.is_header_encrypted
        }

    def to_dict(self):
        """Retorna una representación normalizada del perfil."""
        return {
            "is_encrypted": self.is_encrypted,
            "header_encrypted": self.is_header_encrypted,
            "algorithm": self.algorithm,
            "kdf": {
                "algorithm": self.kdf_algorithm,
                "iterations": self.iterations,
                "salt_hex": self.salt.hex() if self.salt else None
            },
            "check_value": self.psw_check_value.hex() if self.psw_check_value else None
        }

    def __str__(self):
        if not self.is_encrypted:
            return "CryptoProfile: [Not Encrypted]"
        
        salt_str = self.salt.hex() if self.salt else "None"
        return (f"CryptoProfile: [{self.algorithm}] "
                f"KDF={self.kdf_algorithm} (Iter={self.iterations}) "
                f"Salt={salt_str[:8]}...")
