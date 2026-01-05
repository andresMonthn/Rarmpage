import json
import os
import string

output_path = r"C:\Users\Admin\Documents\.atomLogic\Rarmpage\rar-research\src\openRAR\combinaciones_10char_ordered.json"
target_size_mb = 100
target_size_bytes = target_size_mb * 1024 * 1024

# Definir alfabeto ordenado (Digitos -> Mayusculas -> Minusculas)
# Esto sigue el orden ASCII estándar
chars = sorted(string.digits + string.ascii_letters)
base = len(chars)

print(f"Generando archivo JSON (~{target_size_mb} MB) con combinaciones alfanuméricas ordenadas...")
print(f"Alfabeto base ({base} caracteres): {''.join(chars[:10])}...{''.join(chars[-10:])}")

def get_combination(index, length=10):
    """Convierte un índice entero a una cadena base-62 con padding"""
    indices = []
    curr = index
    for _ in range(length):
        curr, rem = divmod(curr, base)
        indices.append(rem)
    # indices está en orden inverso (least significant first), lo invertimos para big-endian (lectura humana)
    return ''.join(chars[i] for i in reversed(indices))

with open(output_path, 'w', encoding='utf-8') as f:
    f.write('[\n')
    
    current_bytes = 0
    i = 0
    first = True
    
    while current_bytes < target_size_bytes:
        combo = get_combination(i)
        
        # Estructura del objeto
        obj = {
            "id": i + 1,
            "combination": combo
        }
        
        # Formato JSON manual para streaming
        json_str = json.dumps(obj)
        
        if not first:
            f.write(',\n')
        else:
            first = False
            
        f.write('  ' + json_str)
        
        i += 1
        
        # Verificar tamaño cada 1000 iteraciones para no hacer flush/stat constante
        if i % 1000 == 0:
            f.flush()
            current_bytes = os.path.getsize(output_path)
            print(f"Generados: {i:,} | Tamaño actual: {current_bytes / 1024 / 1024:.2f} MB", end='\r')

    f.write('\n]')

print(f"\n\nProceso completado.")
print(f"Total registros: {i:,}")
print(f"Archivo final: {output_path}")
print(f"Tamaño final: {os.path.getsize(output_path) / 1024 / 1024:.2f} MB")
