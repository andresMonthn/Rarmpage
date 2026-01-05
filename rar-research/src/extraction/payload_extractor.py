import os
from typing import Optional
from core.models import EncryptedEntry

class PayloadExtractor:
    """
    Responsabilidad:
    Capa de Extracción.
    Se encarga de operaciones de I/O de bajo nivel para recuperar 
    el payload cifrado (ciphertext) desde el archivo físico,
    basándose en la información provista por el Parser (EncryptedEntry).
    """

    def __init__(self, rar_path: str):
        self.rar_path = rar_path

    def extract_chunk(self, entry: EncryptedEntry, size: int = 16) -> bytes:
        """
        Extrae un fragmento del payload cifrado.
        Ideal para validación rápida (solo necesitamos el primer bloque).
        
        Args:
            entry: Metadatos de la entrada cifrada.
            size: Cantidad de bytes a leer (default 16 para un bloque AES).
            
        Returns:
            bytes: El ciphertext crudo.
        """
        if not os.path.exists(self.rar_path):
            raise FileNotFoundError(f"Archivo no encontrado: {self.rar_path}")

        if entry.size < size:
            # Si el archivo es muy pequeño, leemos lo que haya
            read_size = entry.size
        else:
            read_size = size

        with open(self.rar_path, 'rb') as f:
            f.seek(entry.offset)
            data = f.read(read_size)
            
        return data

    def extract_full(self, entry: EncryptedEntry) -> bytes:
        """
        Extrae todo el payload cifrado.
        Cuidado: Puede ser grande.
        """
        return self.extract_chunk(entry, size=entry.size)
