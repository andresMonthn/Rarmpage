import subprocess
import os
import sys
import time
import threading
import json
from typing import Optional, Callable

class HashcatEngine:
    """
    Controlador para ejecutar Hashcat como subproceso.
    Soporta ataque de fuerza bruta (Mascara) y Diccionario para RAR5 (Modo 13000).
    """
    
    MODE_RAR5 = "13000"
    
    def __init__(self, hashcat_path: str = None):
        """
        Args:
            hashcat_path: Ruta al ejecutable de hashcat.
                          Si es None, busca en la instalación local del proyecto (src/GPU/bin).
                          Si no lo encuentra, asume 'hashcat' en el PATH.
        """
        if hashcat_path is None:
            # Buscar en binarios locales
            from .installer import HASHCAT_EXE
            if HASHCAT_EXE.exists():
                self.hashcat_path = str(HASHCAT_EXE)
            else:
                self.hashcat_path = "hashcat"
        else:
            self.hashcat_path = hashcat_path

        print(f"[DEBUG] Engine hashcat_path: {self.hashcat_path}")
        self.process = None
        self.stop_flag = False
        self._validate_executable()

    def _validate_executable(self):
        # Intentar ejecutar --version para ver si funciona
        try:
            # En Windows necesitamos cwd si no está en PATH
            cwd = os.path.dirname(self.hashcat_path) if os.path.isabs(self.hashcat_path) else None
            
            subprocess.run([self.hashcat_path, "--version"], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE, 
                         cwd=cwd,
                         check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            print(f"[WARN] No se encontró hashcat en '{self.hashcat_path}'.")
            print("       Ejecuta 'python src/cli/main.py setup_gpu' para instalarlo automáticamente.")

    def run_benchmark(self):
        """Ejecuta el benchmark de Hashcat para RAR5"""
        cmd = [self.hashcat_path, "-b", "-m", self.MODE_RAR5]
        print(f"[GPU] Ejecutando benchmark: {' '.join(cmd)}")
        subprocess.run(cmd)

    def start_bruteforce(self, hash_string: str, mask: str = "?a?a?a?a", 
                        callback: Optional[Callable] = None,
                        extra_args: list = None) -> Optional[str]:
        """
        Inicia un ataque de máscara (Fuerza Bruta).
        """
        # Crear archivo temporal para el hash
        hash_file = os.path.abspath("target.hash")
        # Asegurar encoding y newline
        with open(hash_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(hash_string.strip() + "\n")
            
        # Construir comando principal
        cmd = [
            self.hashcat_path,
            "-m", self.MODE_RAR5,
            "-a", "3",
            "-w", "3", 
            "--status", "--status-timer", "2"
        ]
        
        if extra_args:
            cmd.extend(extra_args)
            
        cmd.append(hash_file)
        cmd.append(mask)
        
        found_password = None
        
        # Ejecutar ataque
        success = self._run_process(cmd, callback)
        
        if success:
            # Si terminó exitosamente (o dice Cracked), intentamos recuperar la contraseña con --show
            found_password = self._retrieve_password(hash_file, mask)
        
        # Limpieza
        # if os.path.exists(hash_file):
        #    os.remove(hash_file)
            
        return found_password

    def _retrieve_password(self, hash_file, mask):
        """Ejecuta hashcat --show para obtener la contraseña limpia"""
        cmd = [
            self.hashcat_path,
            "-m", self.MODE_RAR5,
            "--show",
            hash_file
        ]
        
        try:
            cwd = os.path.dirname(self.hashcat_path) if os.path.isabs(self.hashcat_path) else None
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                cwd=cwd,
                universal_newlines=True
            )
            
            output = result.stdout.strip()
            # Formato esperado: $rar5$....:password
            if output:
                # Separar por el último ':'
                # Cuidado: la contraseña puede contener ':'
                # Hashcat output para RAR5 es: hash:password
                # El hash empieza con $rar5$
                
                # Buscamos la última ocurrencia de ':'
                # Pero el hash RAR5 contiene muchos '$' y caracteres.
                # Lo más seguro es split.
                parts = output.split(':')
                if len(parts) >= 2:
                    return parts[-1]
            return None
            
        except Exception as e:
            print(f"[ERROR] Falló la recuperación de contraseña: {e}")
            return None

    def _run_process(self, cmd, callback):
        print(f"[GPU] Iniciando motor...")
        
        cwd = os.path.dirname(self.hashcat_path) if os.path.isabs(self.hashcat_path) else None
        
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            universal_newlines=True,
            bufsize=1
        )
        
        success = False
        
        while True:
            if self.stop_flag:
                self.process.terminate()
                break
                
            output = self.process.stdout.readline()
            
            if output == '' and self.process.poll() is not None:
                break
                
            if output:
                clean_line = output.strip()
                
                # Detectar éxito (Hashcat en inglés o español si estuviera localizado)
                if "Status...........: Cracked" in clean_line:
                    success = True
                    # Podemos detener el bucle, Hashcat terminará pronto
                
                if callback:
                    callback(clean_line)
                    
        rc = self.process.poll()
        # Hashcat retorna 0 si cracked all, 1 si exhausted
        if rc == 0:
            success = True
            
        return success

    def stop(self):
        self.stop_flag = True
        if self.process:
            self.process.terminate()
