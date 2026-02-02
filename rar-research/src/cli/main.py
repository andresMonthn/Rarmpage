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
    gpu_parser.add_argument("--mask", default=None, help="Máscara personalizada (ej: ?a?a?a?a). Ignora otras opciones si se usa.")
    gpu_parser.add_argument("-l", "--length", type=int, help="Longitud exacta de la contraseña")
    gpu_parser.add_argument("--min", type=int, help="Longitud mínima")
    gpu_parser.add_argument("--max", type=int, help="Longitud máxima")
    gpu_parser.add_argument("-c", "--charset", choices=["num", "lower", "upper", "alpha", "alphanum", "all", "special"], default="alphanum", help="Juego de caracteres (default: alphanum)")
    gpu_parser.add_argument("--hashcat-bin", default=None, help="Ruta al ejecutable de hashcat (Opcional)")
    gpu_parser.add_argument("-w", "--wordlist", default=None, help="Ruta a un archivo de diccionario (Ataque de diccionario)")
    gpu_parser.add_argument("-r", "--rules", default=None, help="Archivo de reglas para Hashcat (ej: best64.rule)")
    gpu_parser.add_argument("--smart", action="store_true", help="Activar modo inteligente: combina diccionario con números, fechas y años (1950+)")
    gpu_parser.add_argument("--auto-extract", action="store_true", help="Extraer automáticamente si se encuentra la contraseña (sin preguntar)")

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
                # UI Limpia: Solo mostrar progreso y estado final
                if "Progress.........:" in msg:
                    # msg format: "Progress.........: 123/456 (10.00%)"
                    try:
                        content = msg.split(":", 1)[1].strip()
                        # Usar retorno de carro \r para sobrescribir la línea
                        sys.stdout.write(f"\r[*] Probando: {content}   ")
                        sys.stdout.flush()
                    except:
                        pass
                elif "Status...........:" in msg:
                     status = msg.split(":", 1)[1].strip()
                     if status == "Cracked":
                         print(f"\n[+] Estado: ¡Encontrada!")
                     elif status == "Exhausted":
                         print(f"\n[-] Estado: Agotado (No encontrada en este rango)")
                elif "Speed.#1.........:" in msg:
                    # Opcional: Mostrar velocidad si se desea
                    pass
                
            # Construir máscara y argumentos
            mask = args.mask
            extra_args = []
            
            # Asegurar rutas absolutas para Hashcat
            if args.wordlist:
                args.wordlist = os.path.abspath(args.wordlist)
            if args.rules:
                # Si no es absoluta y existe localmente, hacerla absoluta
                if not os.path.isabs(args.rules) and os.path.exists(args.rules):
                    args.rules = os.path.abspath(args.rules)
            
            if args.rules:
                extra_args.extend(["-r", args.rules])
            
            if not args.wordlist:
                if not mask:
                    # Charset mapping
                    charset_mask = "?a" # Fallback
                    custom_charset = None
                    
                    if args.charset == "num":
                        charset_mask = "?d"
                    elif args.charset == "lower":
                        charset_mask = "?l"
                    elif args.charset == "upper":
                        charset_mask = "?u"
                    elif args.charset == "alpha":
                        custom_charset = "?l?u"
                        charset_mask = "?1"
                    elif args.charset == "alphanum":
                        custom_charset = "?l?u?d"
                        charset_mask = "?1"
                    elif args.charset == "special":
                        custom_charset = "?s"
                        charset_mask = "?1"
                    elif args.charset == "all":
                        charset_mask = "?a"
                        
                    if custom_charset:
                        extra_args.extend(["-1", custom_charset])
                        
                    # Length logic
                    if args.length:
                        mask = charset_mask * args.length
                    elif args.min or args.max:
                        # Increment mode
                        min_l = args.min if args.min else 1
                        max_l = args.max if args.max else 8
                        
                        extra_args.append("--increment")
                        extra_args.extend(["--increment-min", str(min_l)])
                        extra_args.extend(["--increment-max", str(max_l)])
                        
                        # For increment, mask needs to be the MAX length
                        mask = charset_mask * max_l
                    else:
                        # Default: Length 4 alphanum if nothing specified
                        print("[*] No se especificó longitud. Usando default: longitud 4, alfanumérico.")
                        if not custom_charset and args.charset == "alphanum": # Default charset
                             extra_args.extend(["-1", "?l?u?d"])
                             charset_mask = "?1"
                        mask = charset_mask * 4

            password = None
            if args.smart and args.wordlist:
                print(f"[*] Modo: Ataque Inteligente (Diccionario + Reglas Híbridas)")
                print(f"    - Diccionario Base: {args.wordlist}")
                print(f"    - Estrategia: Wordlist -> Wordlist + [0-9]{{1,4}} (Fechas/Años)")
                
                if not os.path.exists(args.wordlist):
                    print(f"[!] Error: No se encontró el archivo de diccionario: {args.wordlist}")
                    return
                
                password = engine.start_smart_attack(rar_hash, args.wordlist, callback=status_callback)

            elif args.wordlist:
                print(f"[*] Modo: Ataque de Diccionario")
                print(f"    - Diccionario: {args.wordlist}")
                if not os.path.exists(args.wordlist):
                    print(f"[!] Error: No se encontró el archivo de diccionario: {args.wordlist}")
                    return
                # Para diccionario no usamos extra_args de máscara, pero sí reglas
                password = engine.start_dictionary_attack(rar_hash, args.wordlist, callback=status_callback, extra_args=extra_args)
            else:
                print(f"[*] Modo: Fuerza Bruta (Máscara)")
                print(f"    - Máscara: {mask}")
                print(f"    - Charset: {args.charset}")
                if extra_args:
                    print(f"    - Extra Args: {extra_args}")
                password = engine.start_bruteforce(rar_hash, mask=mask, callback=status_callback, extra_args=extra_args)
            
            if not password and args.wordlist:
                print("\n[!] GPU no encontró la contraseña. Intentando verificación profunda con CPU (UnRAR)...")
                print("    Este método es más lento pero infalible para validar el diccionario.")
                try:
                    from GPU.cpu_engine import CPUEngine
                    cpu_engine = CPUEngine()
                    
                    def cpu_callback(msg):
                        sys.stdout.write(f"\r{msg}   ")
                        sys.stdout.flush()
                        
                    password = cpu_engine.start_dictionary_attack(args.file, args.wordlist, callback=cpu_callback)
                    print() # Newline post callback
                except Exception as e:
                    print(f"\n[!] Error en motor CPU: {e}")

            if password:
                print("\n" + "="*50)
                print(f"[*] ¡CONTRASEÑA ENCONTRADA!: {password}")
                print("="*50 + "\n")
                
                # Interacción con el usuario para extracción
                should_extract = False
                dest = "."
                
                if args.auto_extract:
                    should_extract = True
                    print(f"[*] Modo auto-extract activado.")
                else:
                    try:
                        response = input("¿Desea extraer el archivo ahora? (S/N): ").strip().lower()
                        if response == 's':
                            should_extract = True
                            user_dest = input("Ingrese la carpeta de destino (Enter para carpeta actual): ").strip()
                            if user_dest:
                                dest = user_dest
                    except KeyboardInterrupt:
                        print("\n[!] Operación cancelada por el usuario.")

                if should_extract:
                    print(f"[*] Extrayendo en: {dest} ...")
                    opener = RarOpener()
                    result = opener.extract_to(args.file, dest, password)
                    
                    if result['status'] == 'SUCCESS':
                        print(f"[OK] {result['message']}")
                        # Opción de abrir carpeta
                        if os.name == 'nt' and not args.auto_extract:
                            os.startfile(os.path.abspath(dest))
                    else:
                        print(f"[ERROR] Falló la extracción: {result.get('error')}")
                        print(f"        Verifique que WinRAR esté instalado o use la contraseña manualmente.")
            else:
                print("\n[!] No se encontró la contraseña con la máscara actual.")
            
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
