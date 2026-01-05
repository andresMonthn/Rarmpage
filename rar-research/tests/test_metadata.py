import os
import sys

# Añadir src al path
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from core.rar_parser import RarParser

def create_mock_rar5(filename):
    """
    Crea un archivo con estructura RAR5 válida mínima para probar el parser de bloques.
    Estructura:
    1. Firma
    2. Main Header (Type 1)
    3. End of Archive (Type 5)
    """
    signature = b'\x52\x61\x72\x21\x1A\x07\x01\x00'
    
    # Helper para VINT
    def to_vint(val):
        out = []
        while val >= 0x80:
            out.append((val & 0x7f) | 0x80)
            val >>= 7
        out.append(val)
        return bytes(out)

    # Construcción de Main Header (Type 1)
    # CRC(4) + Size(V) + Type(V) + Flags(V) + [Extra] + [Data]
    # Type = 1
    # Flags = 0
    # Size = len(Type) + len(Flags)
    mh_type = to_vint(1)
    mh_flags = to_vint(0)
    mh_size_val = len(mh_type) + len(mh_flags)
    mh_size = to_vint(mh_size_val)
    mh_crc = b'\x00\x00\x00\x00' # CRC fake
    
    main_header = mh_crc + mh_size + mh_type + mh_flags

    # Construcción End of Archive (Type 5)
    ea_type = to_vint(5)
    ea_flags = to_vint(0)
    ea_size_val = len(ea_type) + len(ea_flags)
    ea_size = to_vint(ea_size_val)
    ea_crc = b'\x00\x00\x00\x00'
    
    end_header = ea_crc + ea_size + ea_type + ea_flags
    
    with open(filename, 'wb') as f:
        f.write(signature)
        f.write(main_header)
        f.write(end_header)
        
    print(f"Creado mock RAR5: {filename}")

def test_metadata_parsing():
    rar_file = "test_mock_v5.rar"
    create_mock_rar5(rar_file)
    
    print(f"\n--- Probando Parser con {rar_file} ---")
    try:
        with RarParser(rar_file) as parser:
            parser.parse()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if os.path.exists(rar_file):
            os.remove(rar_file)

if __name__ == "__main__":
    test_metadata_parsing()
