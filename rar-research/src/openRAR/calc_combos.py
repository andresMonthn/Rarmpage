import json
import os
import string

output_dir = r"C:\Users\Admin\Documents\.atomLogic\Rarmpage\rar-research\src\openRAR"
output_file = os.path.join(output_dir, "combinations_calculations.json")

# Base: 62 (digits + letters) sorted
# Orden: 0-9, A-Z, a-z
chars = sorted(string.digits + string.ascii_letters)
base = len(chars)
min_length = 2
max_length = 15

def get_combination(index, length):
    """Convierte un índice entero a una cadena base-62 con padding"""
    # Si index es el total, necesitamos el ultimo posible (index-1)
    # Pero aquí nos piden la combinación "en la posición X" (1-based), así que ajustamos a 0-based
    # Si nos piden la 961, es el índice 960
    real_index = index - 1
    
    indices = []
    curr = real_index
    for _ in range(length):
        curr, rem = divmod(curr, base)
        indices.append(rem)
    return ''.join(chars[i] for i in reversed(indices))

results = []

total_combinations = 0

for length in range(min_length, max_length + 1):
    count = base ** length
    total_combinations += count
    
    # Calcular bloques (división entre 4 acumulativa)
    quarter = count // 4
    block_1 = quarter
    block_2 = quarter + block_1
    block_3 = quarter + block_2
    block_4 = count 
    
    # Calcular la combinación real en esos puntos de corte
    # Nota: block_1 es un número (cantidad), queremos saber "cual es la comb numero block_1"
    combo_b1 = get_combination(block_1, length)
    combo_b2 = get_combination(block_2, length)
    combo_b3 = get_combination(block_3, length)
    combo_b4 = get_combination(block_4, length) # Será la última posible

    results.append({
        "length": length,
        "combinations_count": count,
        "combinations_scientific": f"{count:.2e}",
        "description": f"Alphanumeric combinations of length {length}",
        "blocks": {
            "block_1": {
                "count": block_1,
                "combination": combo_b1
            },
            "block_2": {
                "count": block_2,
                "combination": combo_b2
            },
            "block_3": {
                "count": block_3,
                "combination": combo_b3
            },
            "block_4_total": {
                "count": block_4,
                "combination": combo_b4
            }
        }
    })

final_data = {
    "base_charset_size": base,
    "charset_description": "0-9, A-Z, a-z (Sorted)",
    "range": f"{min_length}-{max_length}",
    "total_cumulative_combinations": total_combinations,
    "total_cumulative_scientific": f"{total_combinations:.2e}",
    "breakdown": results
}

with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(final_data, f, indent=2)

print(f"File created at: {output_file}")
