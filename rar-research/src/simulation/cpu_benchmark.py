import time
import hashlib
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

class CPUBenchmark:
    """
    Realiza pruebas de rendimiento de CPU específicas para el algoritmo KDF de RAR5.
    Mide la velocidad en Hashes por Segundo (H/s).
    """
    
    def __init__(self, duration_seconds=2):
        self.duration = duration_seconds
        self.algorithm = 'sha256'
        # RAR5 default iterations: 32768 + 32
        self.iterations = 32800 
        self.salt = b'bench_salt_123'
        self.password = b'bench_pass'

    def _worker(self, duration):
        """Función worker que corre en un proceso separado."""
        start_time = time.time()
        end_time = start_time + duration
        count = 0
        
        # Loop de carga de trabajo
        while time.time() < end_time:
            hashlib.pbkdf2_hmac(
                self.algorithm, 
                self.password, 
                self.salt, 
                self.iterations
            )
            count += 1
            
        elapsed = time.time() - start_time
        return count, elapsed

    def run_single_core(self):
        """Mide el rendimiento en un solo núcleo."""
        count, elapsed = self._worker(self.duration)
        speed = count / elapsed
        return {
            "mode": "Single-Core",
            "hashes_per_second": speed,
            "total_hashes": count,
            "elapsed_seconds": elapsed
        }

    def run_multi_core(self):
        """
        Mide el rendimiento utilizando todos los núcleos disponibles.
        Utiliza multiprocesamiento para evitar el GIL (aunque hashlib suele liberar el GIL,
        esto asegura saturación de CPU).
        """
        cpu_count = multiprocessing.cpu_count()
        
        with ProcessPoolExecutor(max_workers=cpu_count) as executor:
            # Lanzar trabajos en paralelo
            futures = [executor.submit(self._worker, self.duration) for _ in range(cpu_count)]
            
            total_hashes = 0
            # Tomamos el tiempo desde el padre para ser justos con el overhead
            start_time = time.time()
            
            for f in futures:
                c, _ = f.result()
                total_hashes += c
                
            elapsed = time.time() - start_time
            
        speed = total_hashes / elapsed
        return {
            "mode": "Multi-Core",
            "cores": cpu_count,
            "hashes_per_second": speed,
            "total_hashes": total_hashes,
            "elapsed_seconds": elapsed
        }

def benchmark_cpu():
    """Función de utilidad para correr el benchmark completo."""
    print(f"[-] Iniciando Benchmark (Duración: {2}s por prueba)...")
    bench = CPUBenchmark(duration_seconds=2)
    
    # Single Core
    print("[-] Ejecutando Single-Core...")
    s_res = bench.run_single_core()
    print(f"    -> Velocidad: {s_res['hashes_per_second']:.2f} H/s")
    
    # Multi Core
    print(f"[-] Ejecutando Multi-Core ({multiprocessing.cpu_count()} hilos)...")
    m_res = bench.run_multi_core()
    print(f"    -> Velocidad: {m_res['hashes_per_second']:.2f} H/s")
    
    print("\n[Resumen]")
    print(f"Factor de escalado: {m_res['hashes_per_second'] / s_res['hashes_per_second']:.2f}x")
    return m_res
