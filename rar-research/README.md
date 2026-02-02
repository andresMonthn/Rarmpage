# RAR Research Project

Herramienta de investigación y análisis de seguridad para el formato de archivo RAR5.

## Estructura del Proyecto

*   **`src/core/`**: Parsers de bajo nivel (lectura binaria, extracción de firmas).
*   **`src/kdf/`**: Modelado matemático de funciones de derivación de claves (PBKDF2).
*   **`src/simulation/`**: Benchmarks de rendimiento de CPU para estimación de costos.
*   **`src/reporting/`**: Exportación de resultados a JSON/CSV.
*   **`docs/`**: Documentación teórica y legal.

## Tecnologías Implementadas

Este proyecto integra múltiples capas tecnológicas para el análisis y auditoría de seguridad:

*   **Lenguaje Core:** Python 3.8+ (Tipado estático, Async IO).
*   **Motor de Criptografía:**
    *   Implementación nativa de **PBKDF2-HMAC-SHA256** para análisis.
    *   Integración con **Hashcat** (Modo 13000) para fuerza bruta acelerada por hardware.
*   **Formatos y Protocolos:**
    *   **RAR5:** Parsing binario de bajo nivel (VINT, Headers, Encryption Flags).
    *   **OpenCL / CUDA:** Para cómputo paralelo en GPU.
*   **Librerías Clave:**
    *   `rarfile`: Wrapper para interactuar con librerías `unrar`.
    *   `py7zr`: Gestión de archivos comprimidos auxiliares.

## Requisitos del Sistema

### Software Mínimo
*   **Sistema Operativo:** Windows 10/11 (Recomendado para soporte WinRAR nativo) o Linux.
*   **Python:** Versión 3.8 o superior.
*   **WinRAR / UnRAR:** Debe estar instalado.
    *   *Windows:* Se busca automáticamente en `C:\Program Files\WinRAR\`.
    *   *Linux:* El paquete `unrar` debe estar en el PATH.

### Hardware Recomendado
*   **GPU:** NVIDIA GeForce (Serie GTX 1000 o superior) con drivers actualizados.
    *   *Nota:* Las gráficas integradas (Intel HD/Iris) funcionan vía OpenCL pero con menor rendimiento.
*   **CPU:** Procesador moderno (para orquestación y benchmarks de referencia).

## Documentación Clave

Antes de operar la herramienta, es **obligatorio** leer:

1.  **[Research Scope](docs/research_scope.md)**: Qué analizamos y qué ignoramos.
2.  **[Threat Model](docs/threat_model.md)**: Modelo de atacantes y aviso legal.
3.  **[Crypto Pipeline](docs/crypto_pipeline.md)**: Flujo técnico de derivación de claves.

## Uso del CLI

El punto de entrada es `src/cli/main.py`.

### 1. Analizar un archivo
Extrae metadatos y perfil criptográfico de un archivo `.rar`.
```bash
python src/cli/main.py analyze "ruta/al/archivo.rar" --format json
```

### 2. Benchmark de Hardware
Mide la velocidad real de tu CPU calculando hashes PBKDF2 (RAR5 compliant).

```bash
python src/cli/main.py benchmark --duration 5
```

### 3. Recuperación Acelerada por GPU (Hashcat)
Utiliza la potencia de la GPU para auditar contraseñas RAR5 (Modo 13000).

**Requisitos:**
- NVIDIA GPU (Drivers instalados) o CPU OpenCL compatible.
- Hashcat instalado (se puede instalar con `python src/cli/main.py setup_gpu`).

**Comandos Principales:**

*   **Ataque Inteligente (Recomendado):**
    Combina un diccionario base con patrones comunes (años 1950+, fechas DDMM/MMDD, números 1-4 dígitos).
    ```bash
    python src/cli/main.py gpu_crack "<archivo>.rar" --wordlist "<diccionario.txt>" --smart --auto-extract
    ```

*   **Ataque de Diccionario Simple:**
    ```bash
    python src/cli/main.py gpu_crack "archivo.rar" --wordlist "<diccionario.txt>"
    ```

*   **Fuerza Bruta (Máscara):**
    Personaliza la máscara (ej: 4 dígitos numéricos `?d?d?d?d`).
    ```bash
    python src/cli/main.py gpu_crack "archivo.rar" --mask "?d?d?d?d" --auto-extract
    ```

**Parámetros Clave:**
- `--wordlist`: Ruta al diccionario base.
- `--smart`: Activa el modo híbrido (Diccionario + Sufijos Numéricos/Fechas/Años).
- `--auto-extract`: Extrae el contenido automáticamente si encuentra la contraseña.
- `--mask`: Define una máscara personalizada para fuerza bruta (ej: `?a?a?a` para 3 caracteres alfanuméricos).
- `--charset`: Predefine juegos de caracteres (`num`, `alpha`, `alphanum`, `all`).

## Tests

Para verificar la integridad del sistema:

```bash
python -m unittest discover tests
```
