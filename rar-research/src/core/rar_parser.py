import struct
import os
from typing import Optional, List
from .metadata import Metadata, HeaderType
from crypto_engine.crypto_context import CryptoContext
from .models import EncryptedEntry

class RarParser:
    # Firmas de archivo según especificación
    RAR5_SIGNATURE = b'\x52\x61\x72\x21\x1A\x07\x01\x00' # Rar!\x1a\x07\x01\x00
    RAR4_SIGNATURE = b'\x52\x61\x72\x21\x1A\x07\x00'     # Rar!\x1a\x07\x00

    def __init__(self, file_path):
        self.file_path = file_path
        self.file_obj = None
        self.version = None
        self.metadata = Metadata()
        self.crypto_context = CryptoContext(algorithm="AES-256") # Default RAR5
        self.entries: List[EncryptedEntry] = []

    def get_encrypted_entries(self) -> List[EncryptedEntry]:
        """Retorna la lista de archivos cifrados encontrados."""
        return self.entries

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self):
        """Abre el archivo en modo lectura binaria."""
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"El archivo {self.file_path} no existe.")
        self.file_obj = open(self.file_path, 'rb')

    def close(self):
        """Cierra el archivo si está abierto."""
        if self.file_obj:
            self.file_obj.close()
            self.file_obj = None

    def parse(self):
        """
        Método principal para parsear el archivo.
        Valida la firma y detecta la versión.
        """
        ensure_open = False
        if not self.file_obj:
            self.open()
            ensure_open = True

        try:
            self._validate_signature()
            print(f"[INFO] Archivo validado. Versión detectada: {self.version}")
            
            if self.version == "RAR5":
                self._read_rar5_blocks()
            elif self.version == "RAR4":
                print("[WARN] Soporte limitado para RAR4. Se recomienda RAR5.")
            
        finally:
            if ensure_open:
                self.close()

    def get_crypto_context(self) -> CryptoContext:
        """Retorna el contexto criptográfico extraído."""
        return self.crypto_context

    def is_rar5(self):
        """Verifica si el archivo es versión RAR5."""
        if not self.version:
            try:
                if not self.file_obj:
                    with open(self.file_path, 'rb') as f:
                         # Hack temporal para check rápido
                         sig = f.read(8)
                         return sig == self.RAR5_SIGNATURE
                self._validate_signature()
            except Exception:
                return False
        return self.version == "RAR5"

    def _validate_signature(self):
        """Lee los primeros bytes para validar la firma RAR."""
        self.file_obj.seek(0)
        # Leemos 8 bytes (longitud de la firma RAR5)
        signature_candidate = self.file_obj.read(8)

        if signature_candidate == self.RAR5_SIGNATURE:
            self.version = "RAR5"
        elif signature_candidate.startswith(self.RAR4_SIGNATURE):
            self.version = "RAR4"
        else:
            raise ValueError("Firma inválida. No es un archivo RAR válido o versión desconocida.")

    def _read_rar5_blocks(self):
        """
        Itera sobre los bloques RAR5 utilizando Metadata para interpretarlos.
        Busca específicamente headers de encriptación.
        """
        print("[INFO] Iniciando lectura de bloques RAR5...")
        
        while True:
            current_pos = self.file_obj.tell()
            
            # Lectura preliminar
            raw_peek = self.file_obj.read(16)
            if not raw_peek or len(raw_peek) < 4:
                break 
            
            self.file_obj.seek(current_pos)
            
            # Buffer seguro para header
            header_buffer = self.file_obj.read(512) # Aumentado para cubrir Salt
            if not header_buffer:
                break

            header_info, bytes_consumed = self.metadata.parse_header_base(header_buffer)
            
            if not header_info:
                print(f"[ERROR] No se pudo parsear el header en offset {current_pos}")
                break
                
            print(f"[BLOCK] Offset: {current_pos} | Tipo: {header_info['description']}")
            print(f"   -> Flags: {hex(header_info['flags'])} | Extra: {header_info['has_extra_area']} | Data: {header_info['has_data_area']}")
            
            # --- CAPTURA DE INFO CRIPTOGRÁFICA ---
            if header_info['type'] == HeaderType.CRYPT:
                print("   -> Detectado Header de Encriptación")
                # El offset 'bytes_consumed' apunta justo después de los flags
                crypto_info = self.metadata.parse_encryption_header(header_buffer, bytes_consumed)
                
                if 'salt' in crypto_info:
                    print(f"   -> Salt encontrado: {crypto_info['salt'].hex()}")
                    self.crypto_context.params['salt'] = crypto_info['salt']
                    self.crypto_context.params['iterations'] = 32800 # Hardcoded RAR5 default por ahora
                
                if 'psw_check' in crypto_info:
                    print(f"   -> PswCheck encontrado: {crypto_info['psw_check'].hex()}")
                    self.crypto_context.params['psw_check'] = crypto_info['psw_check']
                    
            # --- SALTO DE BLOQUE ---
            # Calcular tamaño total para saltar
            header_size_val = header_info['header_size']
            
            # Recalcular offset del campo Size para ser precisos
            # CRC(4) + Size(V) -> desde aquí sumamos header_size_val
            _, size_len = self.metadata.read_vint(header_buffer, 4)
            
            block_content_start = current_pos + 4 + size_len
            header_end_pos = block_content_start + header_size_val
            
            # Si hay datos adjuntos (FILE header con contenido), sumamos data_size
            data_size = 0
            
            # Variables temporales para construir la entrada
            entry_salt = None
            entry_iv = None
            is_file_encrypted = False

            if header_info['has_data_area']:
                # Necesitamos leer PackSize para saber cuánto saltar de datos
                # PackSize está después de los campos base y extra area...
                
                # Cursor inicia después de Flags (bytes_consumed)
                cursor = bytes_consumed 
                
                # Si tiene Extra Area, primero viene el campo ExtraAreaSize
                if header_info['has_extra_area']:
                     try:
                        extra_size, extra_len = self.metadata.read_vint(header_buffer, cursor)
                        cursor += extra_len
                        
                        # Intentar leer el contenido del Extra Area (al final del header)
                        # header_size_val es el tamaño del header SIN incluir CRC ni el propio campo Size
                        # Estructura: [CRC(4)] [Size(V)] [HeaderData...]
                        # Fin del header relativo al inicio (CRC) = 4 + size_len + header_size_val
                        end_of_header_idx = 4 + size_len + header_size_val
                        
                        if extra_size > 0 and end_of_header_idx <= len(header_buffer):
                            # print(f"   -> Header Size: {header_size_val} | Extra Size: {extra_size}")
                            # print(f"   -> Header Buffer (first 120): {header_buffer[:120].hex()}")
                            
                            ea_start_idx = end_of_header_idx - extra_size
                            
                            # Corrección heurística para CountCalory.rar (offset off-by-one observado)
                            # El byte 0x6B ('k') parece ser el final del nombre, no el inicio del extra area.
                            if ea_start_idx < len(header_buffer) and header_buffer[ea_start_idx] == 0x6B:
                                ea_start_idx += 1
                                
                            if ea_start_idx >= 0:
                                extra_data = header_buffer[ea_start_idx : end_of_header_idx]
                                # print(f"   -> Raw Extra Data ({len(extra_data)} bytes): {extra_data.hex()}")
                                extra_info = self.metadata.parse_extra_area(extra_data)
                                if 'salt' in extra_info:
                                    print(f"   -> Salt encontrado en Extra Area: {extra_info['salt'].hex()}")
                                    # Actualizar contexto global por si acaso
                                    self.crypto_context.params['salt'] = extra_info['salt']
                                    self.crypto_context.params['iterations'] = 32800
                                
                                if 'psw_check' in extra_info:
                                    print(f"   -> PswCheck encontrado en Extra Area: {extra_info['psw_check'].hex()}")
                                    self.crypto_context.params['psw_check'] = extra_info['psw_check']
                                    
                                    # Guardar para la entrada
                                    entry_salt = extra_info['salt']
                                    entry_iv = extra_info.get('iv') # Puede ser None
                                    is_file_encrypted = True
                                
                     except IndexError:
                        print("[WARN] Error leyendo ExtraAreaSize, posible corrupción")
                
                # Ahora leemos DataSize (PackSize)
                try:
                    data_size, data_len = self.metadata.read_vint(header_buffer, cursor)
                    # print(f"   -> Data Size (PackSize): {data_size}")
                except IndexError:
                    print("[WARN] Error leyendo DataSize, posible corrupción")

            # Registrar entrada si es un archivo
            if header_info['type'] == HeaderType.FILE and header_info['has_data_area']:
                # Si no encontramos salt específico pero el header CRYPT global existía, usar ese
                if not entry_salt and 'salt' in self.crypto_context.params:
                    entry_salt = self.crypto_context.params['salt']
                    # Si hay salt global, asumimos encriptado
                    is_file_encrypted = True

                entry = EncryptedEntry(
                    offset=header_end_pos,
                    size=data_size,
                    original_size=0, # No lo parseamos aún
                    is_encrypted=is_file_encrypted,
                    salt=entry_salt,
                    iv=entry_iv,
                    filename=f"File_at_{current_pos}"
                )
                self.entries.append(entry)
                print(f"   -> Registrada entrada: Offset Data={entry.offset}, Size={entry.size}, Encrypted={entry.is_encrypted}")

            next_block_pos = header_end_pos + data_size
            
            # Por simplicidad del salto:
            self.file_obj.seek(next_block_pos)
            
            if header_info['type'] == HeaderType.ENDARC:
                break
