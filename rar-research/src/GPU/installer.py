import os
import requests
import subprocess
import sys
import time
from pathlib import Path

HASHCAT_VERSION = "6.2.6"
HASHCAT_URL = f"https://github.com/hashcat/hashcat/releases/download/v{HASHCAT_VERSION}/hashcat-{HASHCAT_VERSION}.7z"
SEVEN_ZIP_URL = "https://www.7-zip.org/a/7zr.exe"

INSTALL_DIR = Path(__file__).parent / "bin"
HASHCAT_BIN_DIR = INSTALL_DIR / f"hashcat-{HASHCAT_VERSION}"
HASHCAT_EXE = HASHCAT_BIN_DIR / "hashcat.exe"
SEVEN_ZIP_EXE = INSTALL_DIR / "7zr.exe"

def download_file(url, dest_path):
    print(f"[INSTALL] Descargando {url}...")
    try:
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            total_length = int(r.headers.get('content-length', 0))
            downloaded = 0
            
            with open(dest_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_length > 0:
                            percent = int(100 * downloaded / total_length)
                            sys.stdout.write(f"\r[INSTALL] Progreso: {percent}%")
                            sys.stdout.flush()
        print("\n[INSTALL] Descarga completada.")
        return True
    except Exception as e:
        print(f"\n[ERROR] Error descargando {url}: {e}")
        return False

def install_hashcat():
    if HASHCAT_EXE.exists():
        print(f"[INSTALL] Hashcat ya está instalado en: {HASHCAT_EXE}")
        return str(HASHCAT_EXE)

    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    archive_path = INSTALL_DIR / "hashcat.7z"
    
    # 1. Descargar 7zr.exe (necesario porque py7zr no soporta BCJ2)
    if not SEVEN_ZIP_EXE.exists():
        if not download_file(SEVEN_ZIP_URL, SEVEN_ZIP_EXE):
            return None

    # 2. Descargar Hashcat
    if not archive_path.exists():
        if not download_file(HASHCAT_URL, archive_path):
            return None
        
    # 3. Descomprimir usando 7zr.exe
    print("[INSTALL] Descomprimiendo archivos con 7zr (esto puede tardar)...")
    try:
        # x: eXtract with full paths
        # -y: assume Yes on all queries
        # -o: output directory
        cmd = [str(SEVEN_ZIP_EXE), "x", str(archive_path), f"-o{INSTALL_DIR}", "-y"]
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode != 0:
            print(f"[ERROR] Falló la extracción: {result.stderr}")
            return None
            
        print("[INSTALL] Extracción completada.")
        
        # 4. Limpieza
        # Esperar un momento para liberar handles
        time.sleep(1)
        try:
            if archive_path.exists():
                os.remove(archive_path)
            if SEVEN_ZIP_EXE.exists():
                os.remove(SEVEN_ZIP_EXE)
        except OSError as e:
            print(f"[WARN] No se pudieron borrar los archivos temporales: {e}")
            
        if HASHCAT_EXE.exists():
            print(f"[INSTALL] Instalación exitosa en: {HASHCAT_EXE}")
            return str(HASHCAT_EXE)
        else:
            print("[ERROR] No se encontró el ejecutable después de la instalación. Estructura inesperada?")
            return None
            
    except Exception as e:
        print(f"[ERROR] Falló el proceso de instalación: {e}")
        return None

if __name__ == "__main__":
    install_hashcat()
