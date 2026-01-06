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
                        callback: Optional[Callable] = None):
        """
        Inicia un ataque de máscara (Fuerza Bruta).
        
        Args:
            hash_string: El hash extraído del RAR ($rar5$...)
            mask: La máscara de hashcat (ej: ?a?a?a?a para 4 caracteres alfanuméricos)
            callback: Función para recibir actualizaciones de estado (stdout).
        """
        # Crear archivo temporal para el hash
        hash_file = "target.hash"
        with open(hash_file, "w") as f:
            f.write(hash_string)
            
        # Construir comando
        # -m 13000: RAR5
        # -a 3: Brute-force / Mask
        # -w 3: High workload (tunear según respuesta del sistema)
        # --status: Mostrar status automáticamente
        # --status-timer 1: Actualizar cada segundo
        cmd = [
            self.hashcat_path,
            "-m", self.MODE_RAR5,
            "-a", "3",
            "-w", "3", 
            "--status", "--status-timer", "5",
            hash_file,
            mask
        ]
        
        self._run_process(cmd, callback)
        
        # Limpieza
        if os.path.exists(hash_file):
            os.remove(hash_file)

    def _run_process(self, cmd, callback):
        print(f"[GPU] Iniciando motor: {' '.join(cmd)}")
        
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        
        found_pass = None
        
        while True:
            if self.stop_flag:
                self.process.terminate()
                break
                
            output = self.process.stdout.readline()
            
            if output == '' and self.process.poll() is not None:
                break
                
            if output:
                clean_line = output.strip()
                # Detectar contraseña encontrada
                # Hashcat imprime: hash:password
                # O "Status: Cracked" en la info de estado
                
                if callback:
                    callback(clean_line)
                    
                # Heurística simple para detectar éxito en salida estándar
                # (Mejorable parseando el archivo .potfile)
                if "Cracked" in clean_line or "Recuperado" in clean_line:
                    print(f"[GPU] ¡ÉXITO DETECTADO! -> {clean_line}")

        rc = self.process.poll()
        print(f"[GPU] Proceso terminado con código {rc}")

    def stop(self):
        self.stop_flag = True
        if self.process:
            self.process.terminate()
