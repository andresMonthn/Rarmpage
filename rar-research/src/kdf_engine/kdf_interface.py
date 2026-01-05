from abc import ABC, abstractmethod
class KDFEngine(ABC):

    @abstractmethod
    def derive_key(self, secret: bytes) -> bytes:
        """Derivación controlada (no optimizada)"""
        pass

    @abstractmethod
    def cost_profile(self) -> dict:
        pass
