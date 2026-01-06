import argparse
import sys
import os
import json

# Ajuste de path para importaciones
sys.path.append(os.path.join(os.path.dirname(__file__), '../'))

from core.rar_parser import RarParser
from core.metadata import Metadata
from core.crypto_profile import CryptoProfile
from reporting.exporter import Exporter
from orchestrator.execution_manager import ExecutionManager
from openRAR.rar_opener import RarOpener

def main():
    print(f"DEBUG ARGV: {sys.argv}")
    parser = argparse.ArgumentParser(description="Rarmpage Research CLI")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # Comando: analyze
    analyze_parser = subparsers.add_parser("analyze", help="Analiza la estructura de un archivo RAR")
    analyze_parser.add_argument("file", help="Ruta al archivo RAR")
    analyze_parser.add_argument("--format", choices=["json", "csv"], default="json", help="Formato de salida")

    # Comando: test_framework
    test_parser = subparsers.add_parser("test_framework", help="Prueba el pipeline completo con un archivo")
    test_parser.add_argument("file", help="Ruta al archivo RAR")
    test_parser.add_argument("--password", default="test", help="Contraseña para probar (default: test)")

    # Comando: open_rar (Nueva Capa)
    open_parser = subparsers.add_parser("open_rar", help="Intenta abrir un RAR usando librerías estándar (rarfile)")
    open_parser.add_argument("file", help="Ruta al archivo RAR")
    open_parser.add_argument("--password", default=None, help="Contraseña opcional")

    # Comando: extract_crypto (Simplificado)
    crypto_parser = subparsers.add_parser("extract_crypto", help="Extracción segura con contraseña conocida")
    crypto_parser.add_argument("file", help="Ruta al archivo RAR")
    crypto_parser.add_argument("--password", required=True, help="Contraseña conocida (Requerida)")

    # Comando: gpu_crack
    gpu_parser = subparsers.add_parser("gpu_crack", help="Recuperación de contraseña acelerada por GPU (Hashcat)")
    gpu_parser.add_argument("file", help="Ruta al archivo RAR")
    gpu_parser.add_argument("--mask", default="?a?a?a?a", help="Máscara de fuerza bruta (Default: ?a?a?a?a)")
    gpu_parser.add_argument("--hashcat-bin", default=None, help="Ruta al ejecutable de hashcat (Opcional si ya se instaló)")

    # Comando: setup_gpu
    subparsers.add_parser("setup_gpu", help="Descarga e instala Hashcat automáticamente en el proyecto")

    args = parser.parse_args()

    if args.command == "analyze":
        if not os.path.exists(args.file):
            print(f"Error: Archivo no encontrado: {args.file}")
            return

        print(f"Analizando: {args.file}")
        
        # 1. Parsear
        rar_parser = RarParser(args.file)
        try:
            rar_parser.parse()
        except Exception as e:
            print(f"Error durante el parsing: {e}")
            return

        # 2. Generar Perfil
        profile = CryptoProfile()
        if rar_parser.is_rar5():
            # Simulamos datos detectados
            profile.cipher_algo = "AES-256" # Default RAR5
            profile.kdf_algo = "PBKDF2-HMAC-SHA256"
            
            # Intentar obtener iteraciones reales si el parser las sacó
            ctx = rar_parser.get_crypto_context()
            if ctx and 'iterations' in ctx.params:
                 # Actualizar perfil si tenemos datos reales
                 pass

        # 3. Exportar
        normalized_data = profile.normalize()
        exporter = Exporter(normalized_data)
        
        if args.format == "json":
            print(exporter.to_json())
        else:
            print(exporter.to_csv())

    elif args.command == "test_framework":
        if not os.path.exists(args.file):
            print(f"Error: Archivo no encontrado: {args.file}")
            return
            
        print(f"Iniciando Test de Framework sobre: {args.file}")
        manager = ExecutionManager()
        result = manager.attempt_open(args.file, args.password)
        
        print("\n=== REPORTE DE EJECUCIÓN ===")
        print(json.dumps(result, indent=2))
        
    elif args.command == "open_rar":
        opener = RarOpener()
        print(f"Intentando abrir con WinRAR (GUI): {args.file}")
        
        # Si se proporciona contraseña, asumimos que el usuario quiere extraer
        if args.password:
             print(f"Modo extracción activado con contraseña. Seleccione carpeta de destino...")
             result = opener.extract_with_dialog(args.file, args.password)
        else:
             # Comportamiento default: abrir GUI
             result = opener.launch_winrar(args.file)
             
        print(json.dumps(result, indent=2, default=str))

    elif args.command == "extract_crypto":
        from openRAR.harksd import HarksdExtractor
        extractor = HarksdExtractor(args.file)
        print(f"Iniciando extracción segura: {args.file}")
        
        result = extractor.extract(args.password)
            
        print(json.dumps(result, indent=2, default=str))

    elif args.command == "gpu_crack":
        # Importación diferida para evitar errores si faltan módulos
        try:
            from GPU.extractor import RarHashExtractor
            from GPU.engine import HashcatEngine
        except ImportError as e:
            print(f"[ERROR] No se pudo importar el módulo GPU: {e}")
            return

        print(f"[*] Iniciando módulo GPU para: {args.file}")
        
        # 1. Extraer Hash
        try:
            extractor = RarHashExtractor(args.file)
            rar_hash = extractor.get_hashcat_format()
            
            if not rar_hash:
                print("[!] Error: No se pudo extraer un hash válido. Verifique:")
                print("    - Que el archivo sea RAR5")
                print("    - Que esté encriptado (con contraseña)")
                return

            print(f"[*] Hash extraído con éxito.")
            print(f"[*] Preview: {rar_hash[:60]}...")
            
            # 2. Iniciar Motor
            engine = HashcatEngine(args.hashcat_bin)
            
            def status_callback(msg):
                # Callback simple para mostrar progreso
                print(f"   >> {msg}")
                
            print(f"[*] Iniciando ataque con máscara: {args.mask}")
            print(f"[*] Usando binario hashcat: {args.hashcat_bin}")
            
            engine.start_bruteforce(rar_hash, mask=args.mask, callback=status_callback)
            
        except Exception as e:
            print(f"[FATAL] Ocurrió un error inesperado: {e}")
            import traceback
            traceback.print_exc()

    elif args.command == "setup_gpu":
        print("[*] Iniciando instalación de Hashcat...")
        try:
            from GPU.installer import install_hashcat
            path = install_hashcat()
            if path:
                print(f"[OK] Hashcat listo para usarse en: {path}")
            else:
                print("[FAIL] La instalación falló.")
        except ImportError as e:
            print(f"[ERROR] Faltan dependencias para el instalador: {e}")
            print("Intenta: pip install py7zr requests")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
