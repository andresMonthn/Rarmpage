import requests
import os
import sys
import json

def download_spanish_dictionary():
    # Lista de fuentes de alta calidad
    # Tuples: (URL, Type) where Type is 'text' or 'json'
    sources = [
        ("https://raw.githubusercontent.com/JorgeDuenasLerin/diccionario-espanol-txt/master/0_palabras_todas.txt", "text"),
        ("https://raw.githubusercontent.com/xavier-hernandez/spanish-wordlist/master/text/spanish_words.txt", "text"), 
        ("https://raw.githubusercontent.com/lorenbr/spanish-wordlist/master/spanish_words.txt", "text"),
        ("https://raw.githubusercontent.com/titoBouzout/Dictionaries/master/Spanish.txt", "text"),
        ("https://raw.githubusercontent.com/words/an-array-of-spanish-words/master/index.json", "json"),
        ("https://raw.githubusercontent.com/guilhermecomum/rf-diccionario-espanol/master/spanish-words.txt", "text")
    ]
    
    dest_dir = os.path.dirname(os.path.abspath(__file__))
    dest_path = os.path.join(dest_dir, "spanish.txt")
    
    unique_words = set()
    
    print(f"[*] Iniciando descarga de diccionarios desde {len(sources)} fuentes...")
    
    for url, fmt in sources:
        print(f"[*] Descargando ({fmt}): {url}")
        try:
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                content = response.content.decode('utf-8', errors='ignore')
                count_before = len(unique_words)
                
                if fmt == 'text':
                    lines = content.splitlines()
                    for line in lines:
                        # Limpieza: quitar espacios, saltos, y posibles comentarios
                        word = line.strip()
                        # Filtrar basura común en diccionarios raw (ej: "345/3")
                        if word and not word.startswith('#') and len(word) < 50:
                            # Quitar sufijos de Hunspell si existen (ej: palabra/S)
                            if '/' in word:
                                word = word.split('/')[0]
                            unique_words.add(word)
                            
                elif fmt == 'json':
                    try:
                        words_list = json.loads(content)
                        for word in words_list:
                            if word:
                                unique_words.add(word.strip())
                    except json.JSONDecodeError:
                        print("    [!] Error parseando JSON")
                        
                added = len(unique_words) - count_before
                print(f"    [+] Agregadas {added} palabras nuevas.")
            else:
                print(f"    [!] Falló con status: {response.status_code}")
                
        except Exception as e:
            print(f"    [!] Error descargando: {e}")
            
    if not unique_words:
        print("[!] No se pudieron descargar palabras de ninguna fuente.")
        return None
        
    print(f"[*] Total de palabras únicas encontradas: {len(unique_words)}")
    print("[*] Ordenando alfabéticamente...")
    
    # Ordenar ignorando acentos/case para un orden alfabético más natural, 
    # pero Python sort default está bien para propósitos técnicos.
    # Usaremos locale-aware si fuera crítico, pero standard sort es más rápido y compatible.
    sorted_words = sorted(list(unique_words), key=str.lower)
    
    print(f"[*] Guardando en: {dest_path}")
    try:
        with open(dest_path, 'w', encoding='utf-8') as f:
            for word in sorted_words:
                f.write(word + '\n')
        print("[+] ¡Diccionario generado exitosamente!")
        return dest_path
    except Exception as e:
        print(f"[!] Error guardando archivo: {e}")
        return None

if __name__ == "__main__":
    download_spanish_dictionary()
