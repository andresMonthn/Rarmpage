from typing import Dict, Any, Optional

class CryptoContext:
    """
    Responsabilidad:
    Mantener el estado criptográfico de una ejecución.
    
    Contiene:
    - Algoritmo (ej. AES-256)
    - Parámetros (ej. Salt, IV)
    - Flags (ej. Encrypted Header)
    - Referencias a adaptadores (ej. KDF Adapter)
    
    NO hace:
    - No calcula nada (lógica pasiva).
    - No guarda secretos persistentes (claves privadas).
    """

    def __init__(self, algorithm: str = "Unknown", params: Optional[Dict[str, Any]] = None, flags: Optional[Dict[str, bool]] = None):
        self.algorithm = algorithm
        self.params = params if params else {}
        self.flags = flags if flags else {}
        self.adapter_refs: Dict[str, Any] = {} # Referencias a instancias de adaptadores (ej. PBKDF2Adapter)
        self._runtime_state: Dict[str, Any] = {} # Estado transitorio de la ejecución

    def register_adapter(self, name: str, adapter_instance: Any):
        """Registra una referencia a un adaptador (sin ejecutarlo)."""
        self.adapter_refs[name] = adapter_instance

    def get_adapter(self, name: str) -> Optional[Any]:
        return self.adapter_refs.get(name)

    def set_runtime_value(self, key: str, value: Any):
        """Almacena un valor temporal de ejecución (ej. clave derivada en memoria)."""
        # No persistimos secretos en disco, esto vive solo en memoria del objeto
        self._runtime_state[key] = value

    def get_runtime_value(self, key: str) -> Any:
        return self._runtime_state.get(key)

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialización segura para logs/debug (excluye secretos y objetos complejos).
        """
        return {
            "algorithm": self.algorithm,
            "params": {k: v for k, v in self.params.items() if k not in ['password', 'key']}, # Filtrado básico
            "flags": self.flags,
            "registered_adapters": list(self.adapter_refs.keys())
        }

    def __repr__(self):
        return f"<CryptoContext algo={self.algorithm} adapters={len(self.adapter_refs)}>"
