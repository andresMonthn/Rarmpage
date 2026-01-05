from dataclasses import dataclass

@dataclass
class ExecutionMetrics:
    elapsed_time_ms: float
    memory_usage_kb: int
    steps_executed: int
