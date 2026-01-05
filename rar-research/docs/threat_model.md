# Threat Model

## Propósito
Este documento define el modelo de amenazas para contextualizar la investigación sobre la seguridad de archivos RAR. Su propósito es puramente académico y educativo, destinado a mejorar la comprensión de la criptografía aplicada y la seguridad de datos.

## Actores (Attackers)

### 1. Atacante Oportunista (Script Kiddie)
*   **Recursos:** Limitados. Uso de herramientas públicas genéricas sin personalización.
*   **Objetivo:** Acceso rápido a archivos con contraseñas débiles o comunes.
*   **Capacidad:** Fuerza bruta de bajo volumen, ataques de diccionario básicos.

### 2. Atacante Dedicado (Entusiasta/Investigador)
*   **Recursos:** Hardware de consumo de gama alta (GPU modernas).
*   **Objetivo:** Recuperación de datos propios o desafíos técnicos.
*   **Capacidad:** Uso de herramientas optimizadas (Hashcat, John the Ripper), ataques de diccionario híbridos y máscaras personalizadas.

### 3. Actor Estatal / Crimen Organizado (Advanced Persistent Threat)
*   **Recursos:** Granjas de servidores, ASICs, computación distribuida masiva.
*   **Objetivo:** Objetivos de alto valor estratégico.
*   **Capacidad:** Fuerza bruta exhaustiva, criptoanálisis avanzado. *Nota: Este nivel de amenaza se considera teóricamente pero está fuera del alcance de mitigación práctica para un usuario promedio.*

## Vectores de Ataque Considerados
*   **Ataque de Diccionario:** Probar una lista predefinida de contraseñas probables.
*   **Fuerza Bruta:** Probar todas las combinaciones posibles de caracteres dentro de una longitud dada.
*   **Ataque Híbrido:** Combinación de diccionario con reglas de mutación (leetspeak, sufijos numéricos).

## Vectores NO Considerados (Out of Scope)
*   **Compromiso del Endpoint:** Keyloggers o malware en la máquina de la víctima que capturen la contraseña al escribirla.
*   **Vulnerabilidades del Algoritmo AES:** Asumimos que AES-256 es matemáticamente seguro y no tiene puertas traseras conocidas públicamente que sean explotables.
*   **Extracción de Claves en Memoria:** Ataques tipo *cold boot* o volcados de memoria RAM mientras el archivo está abierto.

## Aviso Legal y Ético
Esta investigación se realiza en un entorno controlado utilizando datos de prueba generados específicamente para este propósito. **No se analiza, ataca ni se intenta vulnerar archivos de terceros sin autorización explícita.** El objetivo es demostrar la efectividad de las funciones de derivación de claves (KDF) y la importancia de contraseñas fuertes, no facilitar actividades ilícitas.
