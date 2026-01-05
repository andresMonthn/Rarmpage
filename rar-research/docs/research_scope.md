# Research Scope

## Objetivo del Estudio
El objetivo principal de esta investigación es analizar la seguridad y robustez del formato de archivo RAR (versión 5.0 y posteriores) desde una perspectiva académica y de seguridad defensiva. Nos centramos en comprender los mecanismos de derivación de claves y cifrado implementados en el estándar.

## Qué Estudiamos (In Scope)
*   **Mecanismo de Derivación de Claves (KDF):** Análisis detallado de la implementación de PBKDF2-HMAC-SHA256 en RAR5.
*   **Algoritmos de Cifrado:** Estudio del uso de AES-256 en modo CBC o CTR según la especificación RAR.
*   **Metadatos:** Análisis de la información expuesta en cabeceras no cifradas (nombres de archivos en cifrado parcial, tiempos de modificación, atributos).
*   **Resistencia a Ataques de Fuerza Bruta:** Evaluación teórica y práctica del costo computacional para recuperar la contraseña original dado un hash extraído.

## Qué NO Estudiamos (Out of Scope)
*   **Vulnerabilidades de Implementación de Software Específico:** No buscamos exploits de desbordamiento de búfer o ejecución de código en WinRAR, 7-Zip o unrar.dll.
*   **Versiones Antiguas (RAR4 e inferiores):** El foco es exclusivamente el formato RAR5 moderno.
*   **Ataques de Canal Lateral:** No realizaremos análisis de consumo de energía o radiación electromagnética.
*   **Ingeniería Social:** No se evalúan métodos para obtener contraseñas mediante engaño a usuarios.
