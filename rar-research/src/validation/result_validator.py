from enum import Enum

class ValidationResult(Enum):
    VALID_STRUCTURE = "valid_structure"
    INVALID_KEY = "invalid_key"
    CORRUPT_DATA = "corrupt_data"
