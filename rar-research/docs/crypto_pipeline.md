# Crypto Pipeline: RAR5

Este documento detalla el flujo criptográfico implementado en RAR5 y simulado en este proyecto.

## Diagrama de Flujo

```mermaid
graph LR
    User[Usuario] -->|Contraseña| P[Password Bytes]
    R[RAR Header] -->|Salt (16 bytes)| KDF
    R -->|Iteraciones (c)| KDF
    
    subgraph "Key Derivation (src/kdf/pbkdf2_model.py)"
    P --> KDF[PBKDF2-HMAC-SHA256]
    KDF -->|Derivación| DK[Derived Key (32 bytes)]
    end
    
    subgraph "Encryption (src/core/crypto_profile.py)"
    DK -->|Clave AES| AES[AES-256-CBC]
    AES -->|Descifrado| D[Datos Descomprimidos]
    end
```

## Implementación en el Proyecto

### 1. Modelo KDF (`src/kdf/pbkdf2_model.py`)
El módulo `PBKDF2Model` representa matemáticamente la función de derivación:

$$ DK = PBKDF2(PRF, Password, Salt, c, dkLen) $$

*   **PRF**: Pseudo-Random Function. En RAR5 es `HMAC-SHA256`.
*   **Password**: Contraseña en UTF-8.
*   **Salt**: 16 bytes aleatorios extraídos del header.
*   **c (Iteraciones)**: Definido por `HeaderFlags` o default ($2^{15} + 32 = 32800$).
*   **dkLen**: 32 bytes (256 bits) para coincidir con la clave AES.

### 2. Perfil Criptográfico (`src/core/crypto_profile.py`)
La clase `CryptoProfile` normaliza estos parámetros extraídos del archivo `.rar` real:

| Parámetro | Valor Default RAR5 | Variable en Código |
|-----------|--------------------|--------------------|
| Algoritmo | AES-256 | `metrics.CIPHER_ALGO` |
| KDF | PBKDF2-HMAC-SHA256 | `metrics.KDF_ALGO` |
| Iteraciones | 32800 | `metrics.KDF_ITERATIONS` |

### 3. Estimación de Costo
El costo computacional se calcula como:
`Total HMAC Operations = Iterations * (dkLen / hLen)`
Para RAR5: `32800 * (32 / 32) = 32800` operaciones por intento.

## Referencias
*   [RarParser](file:///src/core/rar_parser.py): Extracción de firma y metadatos.
*   [Metrics](file:///src/reporting/metrics.py): Definición de estándares de reporte.
