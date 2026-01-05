from abc import ABC, abstractmethod
class CipherAdapter(ABC):

    @abstractmethod
    def validate_structure(self, data: bytes) -> bool:
        pass

    @abstractmethod
    def decrypt_sample(self, key: bytes) -> bytes:
        """Solo bloques mínimos para validación"""
        pass
