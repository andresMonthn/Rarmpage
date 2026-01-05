class CostEstimator:
    """
    Estima el costo computacional de atacar un archivo RAR basándose en sus parámetros criptográficos.
    Utiliza benchmarks de referencia para hardware moderno.
    """
    
    # Benchmarks de referencia para RAR5 (PBKDF2-HMAC-SHA256 con ~32k iteraciones)
    # Velocidades en Hashes/segundo (H/s)
    HARDWARE_PROFILES = {
        "legacy_cpu": 1500,       # CPU antigua / Laptop básica
        "modern_cpu": 5000,       # CPU moderna High-End (e.g., i9/Ryzen 9)
        "mid_gpu": 40000,         # GPU gama media (e.g., RTX 3060)
        "high_gpu": 130000,       # GPU gama alta (e.g., RTX 4090)
        "mining_rig": 1000000,    # Rig de 8 GPUs
        "cloud_cluster": 10000000 # Cluster pequeño en la nube
    }
    
    # Baseline de iteraciones para RAR5
    BASELINE_ITERATIONS = 32768 + 32

    def __init__(self):
        pass

    def calculate_theoretical_cost(self, iterations):
        """
        Calcula el costo teórico en operaciones HMAC fundamentales.
        Para RAR5, cada prueba de contraseña requiere 'iterations' rondas de HMAC-SHA256.
        """
        # En RAR5 (Key Length 32 bytes, Hash SHA256 32 bytes) -> 1 Bloque
        blocks = 1 
        total_hmac_ops = iterations * blocks
        
        return {
            "hmac_ops_per_try": total_hmac_ops,
            "complexity_class": f"O({iterations})",
            "relative_to_baseline": iterations / self.BASELINE_ITERATIONS
        }

    def estimate_time(self, iterations, key_space_size):
        """
        Estima el tiempo necesario para recorrer un espacio de claves (key_space_size).
        Ajusta la velocidad del hardware basado en el número de iteraciones.
        
        Si las iteraciones son el doble del baseline, la velocidad es la mitad.
        """
        scaling_factor = self.BASELINE_ITERATIONS / iterations
        estimates = {}
        
        for hw_name, base_speed in self.HARDWARE_PROFILES.items():
            # Velocidad ajustada
            real_speed = base_speed * scaling_factor
            
            # Segundos totales
            seconds = key_space_size / real_speed
            
            estimates[hw_name] = {
                "speed_h_s": round(real_speed, 2),
                "seconds": seconds,
                "human_time": self._format_time(seconds)
            }
            
        return estimates

    def _format_time(self, seconds):
        intervals = (
            ('siglos', 3153600000), # 100 años aprox
            ('años', 31536000),
            ('días', 86400),
            ('horas', 3600),
            ('minutos', 60),
            ('segundos', 1),
        )
        
        for name, count in intervals:
            value = seconds // count
            if value >= 1:
                return f"{int(value)} {name}"
        return "< 1 segundo"

    def analyze_password_complexity(self, length, charset_size):
        """Calcula el tamaño del espacio de claves."""
        return charset_size ** length
