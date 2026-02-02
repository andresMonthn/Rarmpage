import os

class RarHashExtractor:
    """
    Extractor robusto y autocontenido de hashes RAR5 para Hashcat.
    No depende de módulos externos para facilitar debugging y portabilidad.
    Soporta formato Hashcat -m 13000.
    """
    
    RAR5_SIGNATURE = b'\x52\x61\x72\x21\x1A\x07\x01\x00'
    
    # Header Types
    HEAD_MAIN = 0x01
    HEAD_FILE = 0x02
    HEAD_SERVICE = 0x03
    HEAD_CRYPT = 0x04
    HEAD_ENDARC = 0x05

    # Flags
    HFL_EXTRA = 0x0001
    HFL_DATA = 0x0002

    def __init__(self, file_path: str, debug: bool = False):
        self.file_path = file_path
        self.debug = debug

    def log(self, msg):
        if self.debug:
            print(f"[Extractor] {msg}")

    @staticmethod
    def read_vint(data, offset):
        """Lee un entero de longitud variable (VINT). Retorna (valor, bytes_leidos)."""
        value = 0
        shift = 0
        i = 0
        while offset + i < len(data):
            byte = data[offset + i]
            i += 1
            value |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                return value, i
            shift += 7
            if shift > 64: raise ValueError("VINT too large")
        return 0, 0

    def get_hashcat_format(self) -> str:
        if not os.path.exists(self.file_path):
            return None

        with open(self.file_path, 'rb') as f:
            sig = f.read(8)
            if sig != self.RAR5_SIGNATURE:
                self.log(f"Invalid signature: {sig.hex()}")
                return None
            self.log("Signature OK")

            while True:
                base_pos = f.tell()
                # Leer suficiente buffer para header base
                buf = f.read(128)
                if len(buf) < 4: 
                    self.log("EOF or short buf")
                    break
                
                # 1. CRC (4 bytes) - Skip
                
                # 2. Header Size (VINT) @ offset 4
                header_size, sz_len = self.read_vint(buf, 4)
                if sz_len == 0: 
                    self.log("Invalid header size VINT")
                    break
                
                # 3. Header Type (VINT)
                h_type, type_len = self.read_vint(buf, 4 + sz_len)
                
                # 4. Header Flags (VINT)
                h_flags, flags_len = self.read_vint(buf, 4 + sz_len + type_len)
                
                self.log(f"Header @ {base_pos}: Type={h_type} Size={header_size} Flags={h_flags}")

                header_data_offset = 4 + sz_len + type_len + flags_len
                
                # Total block size calculation (to skip later)
                block_size = 4 + sz_len + header_size
                
                # -- Logic for Encryption Header (0x04) --
                if h_type == self.HEAD_CRYPT:
                    # Este header se usa cuando los headers están encriptados (-hp)
                    # Structure: [Flags(V)] [Salt(16)] ...
                    
                    # Leer el resto del header si es necesario
                    f.seek(base_pos + header_data_offset)
                    # Necesitamos leer lo que queda del header
                    remaining_header = header_size - (type_len + flags_len)
                    crypt_data = f.read(remaining_header)
                    
                    # Parse crypt data
                    c_flags, c_flags_len = self.read_vint(crypt_data, 0)
                    curr = c_flags_len
                    
                    # 0x01 = Password Check?
                    # Normalmente tiene Salt (16) y PswCheck (8) + Integrity (4)
                    # En RAR5 spec, CryptHeader es:
                    # Flags (VINT)
                    # Salt (16)
                    # PswCheck (8) (si flag CHFL_PSWCHECK 0x01 está set? No, siempre?)
                    # IntegrityCheck (4) (si flag CHFL_HASH está set?)
                    
                    # Asumimos estructura standard RAR5 Crypt Header:
                    salt = crypt_data[curr : curr+16]
                    curr += 16
                    # PswCheck son 8 bytes para verification
                    psw_check = crypt_data[curr : curr+8]
                    
                    # Hashcat format for Header Encrypted:
                    # $rar5$salt_len$salt$iter_log2$iv_len$iv$psw_check_len$psw_check
                    
                    salt_hex = salt.hex()
                    psw_check_hex = psw_check.hex()
                    # Header encryption no tiene IV explícito usualmente, usa ceros
                    iv_hex = "0" * 32 
                    
                    # Iteraciones default 15 (32768)
                    return f"$rar5$16${salt_hex}$15$16${iv_hex}$8${psw_check_hex}"

                # -- Logic for File Header (0x02) with Encryption --
                if h_type == self.HEAD_FILE:
                    has_extra = (h_flags & self.HFL_EXTRA)
                    has_data = (h_flags & self.HFL_DATA)
                    
                    if has_extra:
                        # Necesitamos encontrar el Extra Area
                        # Layout: [Base] [ExtraSize(V)] [DataSize(V) if DATA] ... [ExtraData]
                        
                        # Re-leer buffer un poco más grande para asegurar VINTs
                        f.seek(base_pos)
                        full_header_buf = f.read(4 + sz_len + header_size)
                        
                        cursor = header_data_offset
                        extra_size, es_len = self.read_vint(full_header_buf, cursor)
                        self.log(f"  ExtraSize={extra_size} (len={es_len})")
                        cursor += es_len
                        
                        if has_data:
                            data_size, ds_len = self.read_vint(full_header_buf, cursor)
                            self.log(f"  DataSize={data_size} (len={ds_len})")
                            cursor += ds_len
                        else:
                            data_size = 0
                            
                        # El resto hasta el final del header debería ser fileName, etc... 
                        # Y al final el Extra Area.
                        # Extra Area Start = Total Header End - Extra Size
                        # header_size does NOT include the 4+sz_len bytes of the header definition itself?
                        # Wait. "Header Size" in RAR5 usually implies size of the *rest* of the header?
                        # Spec: "Header size: size of header data starting from header type field."
                        # So total block size = 4 (CRC) + sz_len + header_size.
                        # My 'header_size' variable is the value read.
                        
                        total_header_len = 4 + sz_len + header_size
                        extra_start = total_header_len - extra_size
                        self.log(f"  TotalHeaderLen={total_header_len}, ExtraStart={extra_start}")
                        
                        if extra_start > 0:
                            extra_data = full_header_buf[extra_start:]
                            self.log(f"  ExtraData len={len(extra_data)}")
                            
                            # Parse Extra Records
                            e_ptr = 0
                            while e_ptr < len(extra_data):
                                try:
                                    rec_size, rs_len = self.read_vint(extra_data, e_ptr)
                                    if rec_size == 0: break
                                    
                                    rec_type, rt_len = self.read_vint(extra_data, e_ptr + rs_len)
                                    self.log(f"    Rec Type={rec_type} Size={rec_size}")
                                    
                                    # Type 0x01 is Encryption
                                    if rec_type == 0x01:
                                        # Found Encryption Record!
                                        payload_start = e_ptr + rs_len + rt_len
                                        payload = extra_data[payload_start : e_ptr + rec_size]
                                        self.log(f"    Payload hex: {payload.hex()}")
                                        
                                        # Parse Encryption Record
                                        # Structure observed: [Version(V)] [Flags(V)] [KDF(1)] [Salt(16)] [IV(16)] [Check(8)] ...
                                        
                                        p_ptr = 0
                                        
                                        # 1. Version
                                        ver, v_len = self.read_vint(payload, p_ptr)
                                        p_ptr += v_len
                                        
                                        # 2. Flags
                                        enc_flags, ef_len = self.read_vint(payload, p_ptr)
                                        p_ptr += ef_len
                                        
                                        # 3. KDF Count (1 byte)
                                        kdf_count = payload[p_ptr]
                                        p_ptr += 1
                                        
                                        self.log(f"    Ver={ver} Flags={enc_flags} KDF={kdf_count}")
                                        
                                        salt = None
                                        iv = None
                                        psw_check = None
                                        
                                        # Interpret Flags (Empirical/Spec)
                                        # 0x01: Salt present
                                        # 0x02: IV present?
                                        # Check is likely mandatory or implied.
                                        
                                        has_salt = enc_flags & 0x01
                                        has_iv = enc_flags & 0x02 # Changed from 0x08 based on observation (flags=3)
                                        
                                        # Always try to read Salt/IV if flags set
                                        # If flags=3, we expect Salt and IV.
                                        
                                        if has_salt:
                                            salt = payload[p_ptr : p_ptr+16]
                                            p_ptr += 16
                                            
                                        if has_iv:
                                            iv = payload[p_ptr : p_ptr+16]
                                            p_ptr += 16
                                            
                                        # PswCheck (8 bytes) seems to follow
                                        # Assuming mandatory for now or implied by context
                                        check_len = 8
                                        if p_ptr + check_len <= len(payload):
                                            psw_check = payload[p_ptr : p_ptr+check_len]
                                            p_ptr += check_len
                                        
                                        if salt and psw_check:
                                            salt_hex = salt.hex()
                                            psw_check_hex = psw_check.hex()
                                            iv_hex = iv.hex() if iv else ("0" * 32)
                                            
                                            # Formato: $rar5$16$SALT$15$IV$8$PSWCHECK
                                            # Use actual kdf_count
                                            # Note: Hashcat example shows NO IV length field, just IV hex directly.
                                            # Example: $rar5$16$SALT$15$IV_HEX$8$CHECK_HEX
                                            return f"$rar5$16${salt_hex}${kdf_count}${iv_hex}$8${psw_check_hex}"
                                    
                                    e_ptr += rec_size
                                except:
                                    break

                    # Calcular salto al siguiente bloque
                    skip = block_size
                    if has_data:
                        # Si hay data area, el PackSize nos dice cuánto saltar adicionalmente
                        # Ya leímos data_size arriba
                        skip += data_size
                    
                    f.seek(base_pos + skip)
                    continue
                
                # Otros headers, solo saltar
                skip = block_size
                # Verificar si tienen data
                if (h_flags & self.HFL_DATA):
                     # Leer data size si no lo hemos leído
                     # Necesitamos offset correcto.
                     f.seek(base_pos)
                     full_header = f.read(block_size)
                     # DataSize está después de ExtraSize (si hay extra)
                     cursor = header_data_offset
                     if (h_flags & self.HFL_EXTRA):
                         _, es_len = self.read_vint(full_header, cursor)
                         cursor += es_len
                     
                     try:
                         d_sz, _ = self.read_vint(full_header, cursor)
                         skip += d_sz
                     except:
                         pass
                
                f.seek(base_pos + skip)

        return None
