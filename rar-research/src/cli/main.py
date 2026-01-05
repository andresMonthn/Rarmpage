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

    # Comando: extract_crypto (Harksd Layer)
    crypto_parser = subparsers.add_parser("extract_crypto", help="Extracción manual criptográfica (Harksd)")
    crypto_parser.add_argument("file", help="Ruta al archivo RAR")
    crypto_parser.add_argument("--password", required=False, help="Contraseña (Opcional si se desea intentar descifrado sin pass conocido)")
    crypto_parser.add_argument("--length", type=int, required=False, help="Longitud específica de contraseña para fuerza bruta")

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
                 # (CryptoProfile es un DTO de alto nivel, CryptoContext es técnico)
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
        print(f"Iniciando extracción criptográfica manual: {args.file}")
        
        # Pasar el argumento length si existe
        if hasattr(args, 'length') and args.length:
            result = extractor.extract(args.password, length=args.length)
        else:
            result = extractor.extract(args.password)
            
        print(json.dumps(result, indent=2, default=str))

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
