from dataclasses import dataclass

@dataclass(frozen=True)
class ExecutionPolicy:
    """
    Política de ejecución (tu “cinturón de seguridad”).
    
    Garantiza que:
    - nada se ejecute fuera de control
    - todo sea auditable
    - puedas demostrar límites claros
    """
    max_steps: int
    timeout_seconds: int
    safe_mode: bool = True
