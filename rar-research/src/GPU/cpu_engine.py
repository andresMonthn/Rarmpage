
import os
import subprocess
import concurrent.futures
import time
from typing import Optional, Callable

class CPUEngine:
    """
    Motor de fuerza bruta/diccionario basado en CPU utilizando UnRAR.
    Es más lento que GPU pero sirve como fallback infalible y validación.
    """
    
    def __init__(self):
        self.unrar_path = self._find_unrar()
        self.stop_flag = False

    def _find_unrar(self) -> Optional[str]:
        """Busca el ejecutable de UnRAR en el sistema."""
        candidates = [
            r"C:\Program Files\WinRAR\UnRAR.exe",
            r"C:\Program Files (x86)\WinRAR\UnRAR.exe",
            r"C:\Program Files\WinRAR\WinRAR.exe", # WinRAR CLI compatible para 't'
            "unrar", # PATH
            "rar"    # PATH
        ]
        
        for path in candidates:
            if path in ["unrar", "rar"]:
                # Check PATH
                import shutil
                if shutil.which(path):
                    return path
            elif os.path.exists(path):
                return path
                
        return None

    def start_dictionary_attack(self, rar_path: str, wordlist_path: str, 
                               callback: Optional[Callable] = None, 
                               workers: int = 20) -> Optional[str]:
        """
        Ejecuta ataque de diccionario usando CPU y múltiples hilos.
        """
        if not self.unrar_path:
            if callback:
                callback("[ERROR] No se encontró UnRAR/WinRAR. No se puede ejecutar ataque CPU.")
            return None

        if not os.path.exists(wordlist_path):
            return None

        # Leer diccionario
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
        except Exception as e:
            if callback: callback(f"[ERROR] Error leyendo diccionario: {e}")
            return None

        total = len(words)
        if callback:
            callback(f"[CPU] Iniciando ataque con {workers} hilos. Total palabras: {total}")
            callback(f"[CPU] Usando binario: {self.unrar_path}")

        found_password = None
        
        # Función para un solo intento
        def try_password(password):
            if self.stop_flag: return None
            
            # Comando: unrar t -pPASSWORD -y -inul ARCHIVO
            # -inul: Disable all messages
            cmd = [self.unrar_path, "t", f"-p{password}", "-y", "-inul", rar_path]
            
            try:
                # WinRAR.exe usa sintaxis ligeramente distinta a veces, pero 't' suele ser común.
                # Si es WinRAR.exe, flags como -inul funcionan igual.
                
                # Creationflags para ocultar ventana en Windows
                creationflags = 0
                if os.name == 'nt':
                    creationflags = 0x08000000 # CREATE_NO_WINDOW
                
                res = subprocess.run(cmd, creationflags=creationflags)
                
                if res.returncode == 0:
                    return password
            except:
                pass
            return None

        # Ejecución paralela
        # Usamos chunksize para reportar progreso
        chunk_size = 100
        processed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            # Enviar todas las tareas
            future_to_pwd = {executor.submit(try_password, pwd): pwd for pwd in words}
            
            for future in concurrent.futures.as_completed(future_to_pwd):
                if self.stop_flag:
                    break
                    
                result = future.result()
                if result:
                    found_password = result
                    self.stop_flag = True
                    # Cancelar pendientes (best effort)
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                
                processed += 1
                if callback and processed % 500 == 0:
                    progress = (processed / total) * 100
                    callback(f"[CPU] Progreso: {processed}/{total} ({progress:.1f}%)")

        return found_password

    def stop(self):
        self.stop_flag = True
