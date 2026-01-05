import json
import csv
import io

class Exporter:
    """
    Responsabilidad: Convertir resultados a formatos externos (JSON, CSV).
    NO imprime a consola.
    NO realiza cálculos.
    """
    
    def to_json(self, data) -> str:
        """
        Convierte datos a string JSON formateado.
        
        Args:
            data (dict | list): Datos a exportar.
            
        Returns:
            str: Representación JSON.
        """
        # ensure_ascii=False para permitir caracteres unicode si fuera necesario
        return json.dumps(data, indent=4, ensure_ascii=False)

    def to_csv(self, data) -> str:
        """
        Convierte una lista de diccionarios a formato CSV.
        
        Args:
            data (list | dict): Lista de diccionarios (filas) o un solo diccionario.
            
        Returns:
            str: Contenido CSV completo.
        """
        if isinstance(data, dict):
            data = [data]
            
        if not data:
            return ""
            
        # Asumimos que todos los diccionarios tienen las mismas claves
        # basadas en el primer elemento.
        fieldnames = list(data[0].keys())
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        
        writer.writeheader()
        writer.writerows(data)
        
        return output.getvalue()
