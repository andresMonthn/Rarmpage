from abc import ABC, abstractmethod
from core.models import CryptoProfile

class Orchestrator(ABC):

    @abstractmethod
    def load_profile(self, profile: CryptoProfile) -> None:
        pass

    @abstractmethod
    def execute(self) -> None:
        pass

    @abstractmethod
    def report(self) -> dict:
        pass
