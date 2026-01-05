# RAR Research Project

Herramienta de investigación y análisis de seguridad para el formato de archivo RAR5.

## Estructura del Proyecto

*   **`src/core/`**: Parsers de bajo nivel (lectura binaria, extracción de firmas).
*   **`src/kdf/`**: Modelado matemático de funciones de derivación de claves (PBKDF2).
*   **`src/simulation/`**: Benchmarks de rendimiento de CPU para estimación de costos.
*   **`src/reporting/`**: Exportación de resultados a JSON/CSV.
*   **`docs/`**: Documentación teórica y legal.

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

## Tests

Para verificar la integridad del sistema:

```bash
python -m unittest discover tests
```
