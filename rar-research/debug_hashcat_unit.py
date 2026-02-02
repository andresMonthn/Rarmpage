
import os
import subprocess
import sys

# Hash obtenido
TARGET_HASH = "$rar5$16$0fc9ef0a742b7bccf0c10c0d2cedba6b$16$00000000000000000000000000000000$8$8391321a969abfb1"
PASSWORD = "banco"
DICT_FILE = "debug_dict.txt"
HASH_FILE = "debug_target.hash"
HASHCAT_PATH = r"src\GPU\bin\hashcat-6.2.6\hashcat.exe"

def debug_hashcat():
    print("=== DEBUGGING HASHCAT FAILURE ===")
    
    # 1. Crear diccionario minúsculo con codificación controlada (UTF-8)
    with open(DICT_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(PASSWORD + "\n")
    print(f"[OK] Diccionario creado con '{PASSWORD}'")
    
    # 2. Crear archivo hash
    with open(HASH_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(TARGET_HASH + "\n")
    print(f"[OK] Archivo hash creado: {TARGET_HASH}")
    
    # 3. Construir comando
    cmd = [
        os.path.abspath(HASHCAT_PATH),
        "-m", "13000",       # RAR5
        "-a", "0",           # Dictionary
        "--status",
        "--potfile-disable", # Importante para ver si falla de nuevo
        os.path.abspath(HASH_FILE),
        os.path.abspath(DICT_FILE)
    ]
    
    print(f"\n[CMD] {' '.join(cmd)}")
    
    # 4. Ejecutar capturando TODO
    try:
        cwd = os.path.dirname(os.path.abspath(HASHCAT_PATH))
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            text=True
        )
        
        stdout, stderr = proc.communicate()
        
        print("\n--- STDOUT ---")
        print(stdout)
        print("\n--- STDERR ---")
        print(stderr)
        print(f"\nReturn Code: {proc.returncode}")
        
        if "Cracked" in stdout:
            print("\n>>> RESULTADO: CRACKED (El hash es correcto y Hashcat funciona)")
        elif "Exhausted" in stdout:
            print("\n>>> RESULTADO: EXHAUSTED (El hash NO coincide con la contraseña)")
            print("    Posibles causas: Salt incorrecto, IV incorrecto, o lógica de extracción fallida.")
        else:
            print("\n>>> RESULTADO: INCIERTO")
            
    except Exception as e:
        print(f"[FATAL] {e}")

if __name__ == "__main__":
    debug_hashcat()
