from dataclasses import dataclass, field
from typing import Optional

@dataclass(frozen=True)
class CryptoProfile:
    archive_format: str
    cipher_algorithm: str
    kdf_algorithm: str
    kdf_iterations: int
    salt: Optional[bytes]
    header_encrypted: bool

@dataclass
class EncryptedEntry:
    """
    Representa una entrada (archivo/bloque) cifrada dentro del archivo RAR.
    Desacopla la lógica de parsing de la extracción.
    """
    offset: int          # Offset absoluto donde comienzan los datos (después del header)
    size: int            # Tamaño de los datos comprimidos/cifrados
    original_size: int   # Tamaño original (si disponible)
    is_encrypted: bool   # Flag de encriptación
    salt: Optional[bytes] = None # Salt específico de este archivo (si existe)
    iv: Optional[bytes] = None   # Vector de inicialización (si existe)
    filename: str = "Unknown"    # Nombre del archivo para referencia
