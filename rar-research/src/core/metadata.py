import struct
from typing import Tuple, Dict, Any, Optional

class HeaderType:
    MAIN = 1
    FILE = 2
    SERVICE = 3
    CRYPT = 4
    ENDARC = 5

class HeaderFlags:
    # Common flags
    EXTRA_AREA = 0x0001
    DATA_AREA = 0x0002
    SKIP_IF_UNKNOWN = 0x0004
    SPLIT_BEFORE = 0x0008
    SPLIT_AFTER = 0x0010
    CHILD = 0x0020
    INHERITED = 0x0040

class Metadata:
    """
    Clase responsable de interpretar la estructura de bajo nivel de los bloques RAR.
    Traduce bytes a significado estructural, maneja VINTs y flags.
    """
    def __init__(self):
        self.headers = []
        self.is_encrypted = False

    @staticmethod
    def read_vint(data, offset=0):
        """
        Lee un entero de longitud variable (VINT) desde un buffer de bytes.
        Retorna (valor, nuevos_bytes_leidos).
        """
        value = 0
        shift = 0
        bytes_read = 0
        
        while offset + bytes_read < len(data):
            byte = data[offset + bytes_read]
            bytes_read += 1
            
            # Los 7 bits bajos son datos
            value |= (byte & 0x7F) << shift
            
            # Si el bit alto es 0, es el último byte
            if not (byte & 0x80):
                break
            
            shift += 7
            if shift > 64: # Protección contra VINTs malformados/maliciosos
                raise ValueError("VINT demasiado largo")
                
        return value, bytes_read

    def parse_header_base(self, raw_data):
        """
        Parsea la estructura base común de un bloque RAR5:
        [CRC32 (4)] [Size (VINT)] [Type (VINT)] [HeaderFlags (VINT)]
        
        Retorna un diccionario con los campos base y el tamaño total del header consumido.
        """
        offset = 0
        
        # 1. CRC32 (4 bytes)
        if len(raw_data) < 4:
            return None, 0
        crc = struct.unpack('<I', raw_data[0:4])[0]
        offset += 4
        
        # 2. Header Size (VINT)
        try:
            size, v_len = self.read_vint(raw_data, offset)
            offset += v_len
        except IndexError:
            return None, 0

        # 3. Header Type (VINT)
        try:
            header_type, v_len = self.read_vint(raw_data, offset)
            offset += v_len
        except IndexError:
            return None, 0

        # 4. Header Flags (VINT)
        try:
            flags, v_len = self.read_vint(raw_data, offset)
            offset += v_len
        except IndexError:
            return None, 0
            
        header_info = {
            'crc': crc,
            'header_size': size,
            'type': header_type,
            'flags': flags,
            'has_extra_area': bool(flags & HeaderFlags.EXTRA_AREA),
            'has_data_area': bool(flags & HeaderFlags.DATA_AREA),
            'header_data_offset': offset  # Donde terminan los campos base
        }
        
        # Analizar flags específicos si es necesario
        if header_type == HeaderType.CRYPT:
            self.is_encrypted = True
            header_info['description'] = "Encryption Header"
        elif header_type == HeaderType.MAIN:
            header_info['description'] = "Main Header"
        elif header_type == HeaderType.FILE:
            header_info['description'] = "File Header"
        elif header_type == HeaderType.SERVICE:
            header_info['description'] = "Service Header"
        elif header_type == HeaderType.ENDARC:
            header_info['description'] = "End of Archive"
        else:
            header_info['description'] = f"Unknown Header ({header_type})"

        return header_info, offset

    def get_data_size(self, header_info, raw_data, offset):
        """
        Si el header tiene área de datos, intenta leer su tamaño (PackSize).
        El PackSize es otro VINT que aparece justo después de los campos base
        si el flag DATA_AREA está activo.
        """
        if not header_info['has_data_area']:
            return 0, 0
            
        try:
            pack_size, v_len = self.read_vint(raw_data, offset)
            return pack_size, v_len
        except IndexError:
            return 0, 0

    def parse_encryption_header(self, raw_data: bytes, offset: int) -> Dict[str, Any]:
        """
        Extrae información específica del Encryption Header (Type 04).
        Estructura Típica:
        [Encryption Flags (VINT)]
        [Salt (16 bytes) if flag set]
        """
        info = {}
        current_offset = offset
        
        # 1. Encryption Flags
        try:
            enc_flags, v_len = self.read_vint(raw_data, current_offset)
            current_offset += v_len
            info['enc_flags'] = enc_flags
        except IndexError:
            return info

        # Flag 0x01: Password Check?
        # Flag 0x02: ?
        # En RAR5, el salt está casi siempre presente salvo que se reutilice?
        # Vamos a asumir presencia de Salt por defecto para este research scope
        # (La spec completa es compleja, pero para CountCalory.rar seguro tiene salt)
        
        # Salt es 16 bytes
        if len(raw_data) >= current_offset + 16:
            salt = raw_data[current_offset : current_offset + 16]
            info['salt'] = salt
            current_offset += 16
        
        # Hay más campos como 'CheckValue' (para verificar password rápidamente)
        # CheckValue (8 bytes?) - útil para 'validate_password' rápido sin descifrar todo
        
        return info

    def parse_extra_area(self, raw_data: bytes) -> Dict[str, Any]:
        """
        Parsea el Extra Area buscando registros conocidos, especialmente Encriptación.
        Retorna un dict con lo encontrado (ej. {'salt': ..., 'iv': ...}).
        """
        info = {}
        offset = 0
        limit = len(raw_data)
        
        while offset < limit:
            try:
                # Extra Record Structure: [Size (VINT)] [Type (VINT)] [Data...]
                rec_size, s_len = self.read_vint(raw_data, offset)
                if rec_size == 0: break # Evitar bucle infinito si hay ceros
                
                type_offset = offset + s_len
                rec_type, t_len = self.read_vint(raw_data, type_offset)
                
                # Payload start
                payload_offset = type_offset + t_len
                # Payload length = rec_size - s_len - t_len
                
                # Type 0x01 = Encryption
                if rec_type == 0x01:
                    # Empiric adjustment: Latest WinRAR puts a version/reserved byte (0x00) before flags
                    # Check if next byte is 0x00 and flags are 0, might need to skip
                    # RawEA example: 30 01 00 03 ... (Size, Type, 00, Flags=3)
                    
                    # Peek first byte of payload
                    if payload_offset < limit and raw_data[payload_offset] == 0x00:
                         # Read ahead to see if it makes sense
                         if payload_offset + 1 < limit:
                             next_byte = raw_data[payload_offset + 1]
                             # If next byte looks like valid flags (e.g., 0x03), assume skip
                             if next_byte & 0x03: 
                                 payload_offset += 1
                    
                    enc_flags, f_len = self.read_vint(raw_data, payload_offset)
                    current_p = payload_offset + f_len
                    
                    # print(f"[DEBUG] Enc Header Found. Flags: {bin(enc_flags)}")
                    info['enc_flags'] = enc_flags
                    
                    # Parsear campos condicionales (Orden: Salt -> IV -> PswCheck)
                    # Flags: 0x01=PswCheck, 0x02=Salt, 0x04=IV
                    
                    if enc_flags & 0x02: # Has Salt
                        if limit >= current_p + 16:
                            info['salt'] = raw_data[current_p : current_p + 16]
                            current_p += 16
                            
                    if enc_flags & 0x04: # Has IV
                        if limit >= current_p + 16:
                            info['iv'] = raw_data[current_p : current_p + 16]
                            current_p += 16
                            
                    if enc_flags & 0x01: # Has PswCheck
                        # PswCheck es 8 bytes
                        if limit >= current_p + 8:
                            info['psw_check'] = raw_data[current_p : current_p + 8]
                            current_p += 8
                            
                # Avanzar al siguiente record
                offset += rec_size
                
            except Exception:
                break
                
        return info
