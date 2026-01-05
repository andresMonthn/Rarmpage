class PBKDF2Model:
    """
    Representación matemática de PBKDF2 (Password-Based Key Derivation Function 2).
    Sigue la especificación RFC 2898.
    
    Esta clase es puramente descriptiva y analítica. No ejecuta criptografía real
    ni depende de librerías del sistema como hashlib.
    
    Específico para RAR5:
    - PRF: HMAC-SHA256
    - Output Length: 32 bytes (256 bits) para la clave AES.
    """

    def __init__(self, hash_algorithm='sha256', output_length=32):
        self.hash_name = hash_algorithm
        self.output_length = output_length
        # Definimos constantes conocidas para análisis teórico sin importar hashlib
        self.digest_sizes = {
            'sha256': 32,
            'sha1': 20,
            'md5': 16
        }
        self.digest_size = self.digest_sizes.get(hash_algorithm, 32)

    def describe(self):
        """Retorna una descripción textual de los parámetros configurados."""
        return {
            "PRF": f"HMAC-{self.hash_name.upper()}",
            "Output Length": f"{self.output_length} bytes ({self.output_length * 8} bits)",
            "Formula": "DK = PBKDF2(PRF, Password, Salt, c, dkLen)"
        }

    def explain_steps(self, password_len, salt_len, iterations):
        """
        Genera una explicación paso a paso del costo computacional teórico.
        """
        h_len = self.digest_size
        block_count = (self.output_length + h_len - 1) // h_len # Número de bloques (dkLen / hLen)
        
        # Para RAR5 (SHA256 -> 32 bytes) y Output 32 bytes:
        # block_count = 1. Solo se necesita calcular T_1.
        
        total_hmac_calls = block_count * iterations
        
        return [
            f"1. Inicialización: Configurar HMAC-{self.hash_name.upper()} con contraseña de {password_len} bytes.",
            f"2. Bloques: Se necesita generar {self.output_length} bytes. Hash len es {h_len} bytes.",
            f"   -> Se calcularán {block_count} bloques (T_1...T_{block_count}).",
            f"3. Iteraciones por bloque: Cada bloque requiere {iterations} iteraciones de la función F.",
            f"4. Costo Total: {total_hmac_calls} operaciones HMAC completas.",
            f"   -> Esto implica {total_hmac_calls * 2} llamadas a la función de compresión SHA-256 (inner + outer pad)."
        ]
