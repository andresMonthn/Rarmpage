import os
from .rar_opener import RarOpener

class HarksdExtractor:
    """
    Versión simplificada de HarksdExtractor.
    Eliminada toda lógica de criptografía manual, fuerza bruta y análisis complejo.
    Solo delega la extracción con contraseña conocida a RarOpener.
    """
    def __init__(self, rar_path):
        self.rar_path = rar_path
        
    def extract(self, password=None, length=None):
        """
        Inicia el proceso de extracción interactiva.
        Ignora el parámetro 'length' ya que no hay fuerza bruta.
        """
        if not password:
            return {"status": "ERROR", "message": "Se requiere una contraseña para esta operación."}

        opener = RarOpener()
        return opener.extract_with_dialog(self.rar_path, password)
