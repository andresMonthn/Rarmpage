import os
import struct
import binascii
from typing import Optional, Tuple
from ..core.metadata import Metadata, HeaderType, HeaderFlags

class RarHashExtractor:
    """
    Extractor especializado en obtener la cadena de hash (formato Hashcat/John)
    de archivos RAR5.
    """
    
    RAR5_SIGNATURE = b'\x52\x61\x72\x21\x1A\x07\x01\x00'

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.metadata = Metadata()

    def get_hashcat_format(self) -> Optional[str]:
        """
        Analiza el archivo y devuelve la cadena formateada para Hashcat (modo 13000).
        Retorna None si no es un RAR5 encriptado soportado.
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Archivo no encontrado: {self.file_path}")

        with open(self.file_path, 'rb') as f:
            # Validar firma
            sig = f.read(8)
            if sig != self.RAR5_SIGNATURE:
                # Podría ser RAR4, pero por ahora nos enfocamos en RAR5 (Scope del proyecto)
                return None

            # Buscar headers
            while True:
                current_pos = f.tell()
                
                # Leer base del header
                # Necesitamos un buffer suficiente para leer los VINTs iniciales
                raw_peek = f.read(512) 
                if not raw_peek or len(raw_peek) < 4:
                    break
                
                # Reset para leer correctamente con el parser
                f.seek(current_pos)
                
                # Usamos la metadata existente para parsear la estructura base
                # Nota: Metadata.parse_header_base espera bytes, no un file handle
                header_info, bytes_consumed = self.metadata.parse_header_base(raw_peek)
                
                if not header_info:
                    break

                # Caso 1: Header Encryption (-hp)
                # La información de encriptación está en un header tipo CRYPT (0x02)
                if header_info['type'] == HeaderType.CRYPT:
                    # Parsear el header de encriptación
                    crypto_info = self.metadata.parse_encryption_header(raw_peek, bytes_consumed)
                    
                    if 'salt' in crypto_info and 'psw_check' in crypto_info:
                        # Tenemos lo necesario para un hash tipo -hp (Header Encrypted)
                        # Formato Hashcat: $rar5$16$SALT$15$0$8$PSW_CHECK$0
                        # Nota: method suele ser 0 para AES-256
                        salt_hex = crypto_info['salt'].hex()
                        psw_check_hex = crypto_info['psw_check'].hex()
                        
                        return f"$rar5$16${salt_hex}$15$000000000000000000000000000000$8${psw_check_hex}$0"

                # Caso 2: File Encryption (-p)
                # La información está en el FILE header (0x01) dentro del Extra Area
                elif header_info['type'] == HeaderType.FILE and header_info['has_extra_area']:
                    # Necesitamos localizar el Extra Area
                    # bytes_consumed apunta al fin de los flags.
                    cursor = bytes_consumed
                    
                    try:
                        extra_size, extra_len = self.metadata.read_vint(raw_peek, cursor)
                        # Calcular dónde empieza el extra area
                        # Estructura: [Base] [ExtraSize(V)] [DataSize(V)?] ... [ExtraData]
                        # Es complejo calcular el offset exacto sin parsear todo, 
                        # pero sabemos que ExtraData está al FINAL del header.
                        
                        header_size = header_info['header_size'] # Tamaño total del header (sin CRC/Size)
                        # Offset relativo al inicio del bloque (CRC) donde termina el header
                        # CRC(4) + Size(V) + header_size
                        _, size_len = self.metadata.read_vint(raw_peek, 4)
                        block_end_rel = 4 + size_len + header_size
                        
                        extra_start_rel = block_end_rel - extra_size
                        
                        if extra_start_rel > 0 and extra_start_rel < len(raw_peek):
                            extra_data = raw_peek[extra_start_rel : block_end_rel]
                            extra_info = self.metadata.parse_extra_area(extra_data)
                            
                            if 'salt' in extra_info and 'psw_check' in extra_info:
                                # Encontrado!
                                salt_hex = extra_info['salt'].hex()
                                psw_check_hex = extra_info['psw_check'].hex()
                                # Para archivos normales, Hashcat suele preferir tener algo de datos cifrados (IV + Data)
                                # Pero el modo -hp (solo psw_check) a veces funciona si solo queremos validar pass.
                                # Sin embargo, para mayor robustez, intentemos el formato completo si hay IV.
                                
                                # Si tenemos IV y DataSize > 0, podríamos sacar un hash más completo.
                                # Pero el formato simple (solo psw_check) es mucho más rápido de hashear
                                # y suficiente para verificar la contraseña en el 99% de casos RAR5.
                                
                                # Formato simplificado basado en psw_check (UsePswCheck=1)
                                return f"$rar5$16${salt_hex}$15$000000000000000000000000000000$8${psw_check_hex}$0"

                    except Exception as e:
                        # Si falla el parsing de este bloque, seguimos al siguiente
                        pass

                # Avanzar al siguiente bloque
                # Recalcular tamaño total del bloque actual
                header_size_val = header_info['header_size']
                _, size_len = self.metadata.read_vint(raw_peek, 4)
                
                # Calcular salto
                skip = 4 + size_len + header_size_val
                
                if header_info['has_data_area']:
                     # Leer DataSize (PackSize) para saltar los datos comprimidos
                     # PackSize está después de ExtraSize (si existe)
                     cursor = bytes_consumed
                     if header_info['has_extra_area']:
                         e_sz, e_len = self.metadata.read_vint(raw_peek, cursor)
                         cursor += e_len
                     
                     try:
                        data_size, _ = self.metadata.read_vint(raw_peek, cursor)
                        skip += data_size
                     except:
                        pass
                
                f.seek(current_pos + skip)

        return None
