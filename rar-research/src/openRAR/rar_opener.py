import os
import subprocess
import tkinter as tk
from tkinter import filedialog
import rarfile

class RarOpener:
    """
    Responsabilidad:
    Abrir archivos RAR utilizando WinRAR (GUI) para extracción interactiva.
    """
    
    WINRAR_PATH = r"C:\Program Files\WinRAR\WinRAR.exe"

    def __init__(self):
        pass

    def extract_to(self, rar_path: str, dest_folder: str, password: str = None) -> dict:
        """
        Extrae el archivo RAR a una carpeta específica sin diálogo.
        """
        result = {
            "file": rar_path,
            "status": "UNKNOWN",
            "action": "EXTRACT_DIRECT",
            "error": None
        }

        if not os.path.exists(rar_path):
            result["status"] = "FILE_NOT_FOUND"
            return result
            
        if not os.path.exists(self.WINRAR_PATH):
            # Fallback: intentar con 'unrar' o 'rar' del sistema si no está WinRAR
            # Pero por ahora reportamos error
            result["status"] = "WINRAR_NOT_FOUND"
            return result

        try:
            # Crear carpeta si no existe
            if not os.path.exists(dest_folder):
                os.makedirs(dest_folder)

            # Construir comando WinRAR
            # x: Extract with full paths
            # -p: Password
            # -y: Assume yes on all queries
            cmd = [self.WINRAR_PATH, "x", "-y"]
            if password:
                cmd.append(f"-p{password}")
            
            cmd.append(rar_path)
            cmd.append(dest_folder)
            
            # Ejecutar bloqueante para saber si terminó
            proc = subprocess.run(cmd, capture_output=True, text=True)
            
            if proc.returncode == 0:
                result["status"] = "SUCCESS"
                result["destination"] = dest_folder
                result["message"] = f"Extracción completada en: {dest_folder}"
            else:
                result["status"] = "ERROR"
                result["error"] = proc.stderr
            
        except Exception as e:
            result["status"] = "ERROR"
            result["error"] = str(e)
            
        return result

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
