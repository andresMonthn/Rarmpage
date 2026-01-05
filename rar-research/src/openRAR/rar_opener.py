import rarfile
import os
import subprocess
import shutil
import tkinter as tk
from tkinter import filedialog
import threading
import queue
import json
import string
import time
import hashlib

class BruteForceEngine:
    """
    Motor de fuerza bruta multihilo.
    Gestiona colas de trabajo y coordinación entre hilos.
    """
    def __init__(self, rar_path, json_config_path, update_callback, found_callback):
        self.rar_path = rar_path
        self.json_config_path = json_config_path
        self.update_callback = update_callback
        self.found_callback = found_callback
        
        self.stop_event = threading.Event()
        self.queue = queue.Queue()
        self.threads = []
        self.chars = sorted(string.digits + string.ascii_letters)
        self.base = len(self.chars)
        self.chunk_size = 10000 
        
        # Fast Check Params
        self.fast_salt = None
        self.fast_psw_check = None
        self.fast_iterations = 32800

    def set_fast_check_params(self, salt, psw_check, iterations=32800):
        self.fast_salt = salt
        self.fast_psw_check = psw_check
        self.fast_iterations = iterations
        print(f"[ENGINE] Fast Check Mode Enabled: Salt={salt.hex() if salt else 'None'}, Check={psw_check.hex() if psw_check else 'None'}")

    def _load_config(self):
        with open(self.json_config_path, 'r') as f:
            return json.load(f)

    def int_to_base62(self, index, length):
        indices = []
        curr = index
        for _ in range(length):
            curr, rem = divmod(curr, self.base)
            indices.append(rem)
        return ''.join(self.chars[i] for i in reversed(indices))

    def worker(self, thread_id):
        try:
            # Cada hilo tiene su propia instancia de RarFile para thread-safety
            rf = rarfile.RarFile(self.rar_path)
            
            # Buscar un archivo pequeño para probar (más rápido)
            test_file = None
            for f in rf.infolist():
                if not f.isdir():
                    test_file = f
                    break
            
            if not test_file:
                return 

            while not self.stop_event.is_set():
                try:
                    # Obtener rango: (start_index, end_index, length)
                    task = self.queue.get(timeout=0.5) 
                    start, end, length = task
                    
                    # Iterar descendente dentro del chunk
                    for i in range(end - 1, start - 1, -1):
                        if self.stop_event.is_set():
                            break
                            
                        pwd = self.int_to_base62(i, length)
                        
                        try:
                            found = False
                            
                            # Fast Check (CPU Bound, no subprocess)
                            if self.fast_salt and self.fast_psw_check:
                                key = hashlib.pbkdf2_hmac(
                                    'sha256', 
                                    pwd.encode('utf-8'), 
                                    self.fast_salt, 
                                    self.fast_iterations, 
                                    32
                                )
                                # RAR5 PSWCHECK verification
                                # SHA256(Key) truncated to 8 bytes
                                check = hashlib.sha256(key).digest()[:8]
                                if check == self.fast_psw_check:
                                    found = True
                            else:
                                # Slow Check (rarfile/unrar)
                                rf.setpassword(pwd)
                                with rf.open(test_file) as f:
                                    f.read(1)
                                found = True
                            
                            if found:
                                # Verify with rarfile just to be 100% sure if using fast check
                                if self.fast_salt:
                                     rf.setpassword(pwd)
                                     with rf.open(test_file) as f:
                                         f.read(1)
                                
                                self.found_callback(pwd)
                                self.stop_event.set()
                                self.queue.task_done()
                                return
                        except (rarfile.RarWrongPassword, rarfile.BadRarFile):
                            pass
                        except Exception:
                            pass
                        
                        # Actualizar progreso cada 100 intentos
                        if i % 100 == 0:
                             self.update_callback(thread_id, pwd)
                    
                    self.queue.task_done()
                    
                except queue.Empty:
                    if self.queue.empty():
                        return # Cola vacía y timeout, terminamos
                    continue
                except Exception as e:
                    print(f"Error en hilo {thread_id}: {e}")
                    
        except Exception as e:
            print(f"Error iniciando worker {thread_id}: {e}")

    def start(self, min_len=4, max_len=10, num_threads=4):
        try:
            config = self._load_config()
            self.stop_event.clear()
            
            breakdown = {item['length']: item for item in config['breakdown']}
            self.total_search_space = 0
            
            # Llenar la cola con rangos descendentes
            # Nota: Llenamos primero las longitudes menores o mayores?
            # El usuario dijo "descendente". Asumiremos que quiere probar primero lo más probable?
            # O quizás iterar longitudes de menor a mayor (4, 5, 6...) pero dentro de ellas descendente.
            # Probaremos longitudes en orden ascendente (más corto primero es más lógico para cracking),
            # pero los rangos internos descendentes según instrucción.
            
            for length in range(min_len, max_len + 1):
                if length not in breakdown:
                    continue
                
                data = breakdown[length]
                total_combinations = data['combinations_count']
                self.total_search_space += total_combinations
                
                # Crear chunks (start, end) desde el final hacia el principio
                curr = total_combinations
                while curr > 0:
                    start = max(0, curr - self.chunk_size)
                    end = curr
                    self.queue.put((start, end, length))
                    curr = start
                    
            # Iniciar hilos
            for i in range(num_threads):
                t = threading.Thread(target=self.worker, args=(i+1,))
                t.daemon = True
                t.start()
                self.threads.append(t)
                
        except Exception as e:
            print(f"Error iniciando motor: {e}")

    def stop(self):
        self.stop_event.set()
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=0.1)

class RarOpener:
    """
    Responsabilidad:
    Abrir archivos RAR utilizando la librería estándar 'rarfile' (backend unrar).
    Capa totalmente separada del resto del research.
    """
    
    WINRAR_PATH = r"C:\Program Files\WinRAR\WinRAR.exe"
    RAR_CLI_PATH = r"C:\Program Files\WinRAR\Rar.exe"

    def __init__(self):
        # Configuración opcional: intentar localizar unrar si no está en path
        # Por ahora asumimos que está en el sistema o rarfile lo encuentra
        pass

    def extract_with_dialog(self, rar_path: str, password: str = None) -> dict:
        """
        Abre un diálogo nativo para seleccionar destino y extrae usando WinRAR.
        """
        result = {
            "file": rar_path,
            "status": "UNKNOWN",
            "action": "EXTRACT_INTERACTIVE",
            "error": None
        }

        if not os.path.exists(rar_path):
            result["status"] = "FILE_NOT_FOUND"
            return result
            
        if not os.path.exists(self.WINRAR_PATH):
            result["status"] = "WINRAR_NOT_FOUND"
            return result

        try:
            # Inicializar Tkinter oculto
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True) # Asegurar que aparezca encima
            
            # Diálogo nativo
            dest_folder = filedialog.askdirectory(
                title="Selecciona dónde extraer el contenido",
                mustexist=True
            )
            
            root.destroy()
            
            if not dest_folder:
                result["status"] = "CANCELLED"
                result["message"] = "Selección de carpeta cancelada por el usuario."
                return result
                
            # Construir comando WinRAR
            # x: Extract with full paths
            # -p: Password
            cmd = [self.WINRAR_PATH, "x"]
            if password:
                cmd.append(f"-p{password}")
            else:
                # Si no hay pass explícito, WinRAR pedirá si es necesario
                pass
                
            cmd.append(rar_path)
            cmd.append(dest_folder)
            
            # Ejecutar
            subprocess.Popen(cmd, close_fds=True, shell=False)
            
            result["status"] = "EXTRACTING"
            result["destination"] = dest_folder
            result["message"] = f"Extracción iniciada en: {dest_folder}"
            
        except Exception as e:
            result["status"] = "ERROR"
            result["error"] = str(e)
            
        return result

    def launch_winrar(self, rar_path: str) -> dict:
        """
        Ejecuta el propio WinRAR (GUI) con el archivo especificado.
        """
        result = {
            "file": rar_path,
            "status": "UNKNOWN",
            "action": "LAUNCH_GUI",
            "error": None
        }

        if not os.path.exists(rar_path):
            result["status"] = "FILE_NOT_FOUND"
            return result

        if not os.path.exists(self.WINRAR_PATH):
            result["status"] = "WINRAR_NOT_FOUND"
            result["error"] = f"No se encontró WinRAR en: {self.WINRAR_PATH}"
            return result

        try:
            # Ejecutar WinRAR de forma no bloqueante (o bloqueante si se prefiere, pero GUI suele ser no bloqueante para el CLI)
            # Usamos Popen para no bloquear el CLI eternamente si el usuario deja la ventana abierta
            subprocess.Popen([self.WINRAR_PATH, rar_path], close_fds=True, shell=False)
            result["status"] = "LAUNCHED"
            result["message"] = "WinRAR GUI iniciado correctamente."
        except Exception as e:
            result["status"] = "ERROR"
            result["error"] = str(e)
            
        return result

    def list_contents(self, rar_path: str, password: str = None) -> dict:
        """
        Intenta listar el contenido del archivo RAR.
        Si tiene contraseña, intenta usarla.
        """
        result = {
            "file": rar_path,
            "status": "UNKNOWN",
            "files": [],
            "error": None
        }

        if not os.path.exists(rar_path):
            result["status"] = "FILE_NOT_FOUND"
            return result

        try:
            with rarfile.RarFile(rar_path) as rf:
                if password:
                    rf.setpassword(password)
                
                # Intentamos leer la lista de archivos (esto suele validar header y pass si headers están cifrados)
                for f in rf.infolist():
                    result["files"].append({
                        "filename": f.filename,
                        "file_size": f.file_size,
                        "compress_size": f.compress_size,
                        "date_time": f.date_time
                    })
                
                result["status"] = "SUCCESS"
                
        except rarfile.BadRarFile:
            result["status"] = "BAD_RAR_FILE"
            result["error"] = "El archivo no es un RAR válido o está corrupto."
        except rarfile.PasswordRequired:
            result["status"] = "PASSWORD_REQUIRED"
            result["error"] = "Se requiere contraseña."
        except rarfile.RarCannotExec:
            result["status"] = "BACKEND_ERROR"
            result["error"] = "No se encontró 'unrar' o 'rar' instalado en el sistema."
        except Exception as e:
            result["status"] = "ERROR"
            result["error"] = str(e)

        return result
