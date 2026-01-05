from abc import ABC, abstractmethod

class ExecutionStrategy(ABC):

    @abstractmethod
    def prepare(self) -> None:
        pass

    @abstractmethod
    def execute_step(self) -> None:
        pass

    @abstractmethod
    def finalize(self) -> None:
        pass
