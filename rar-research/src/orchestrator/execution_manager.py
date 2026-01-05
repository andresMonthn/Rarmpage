import time
import os
import sys

# Ajuste de path
sys.path.append(os.path.join(os.path.dirname(__file__), '../'))

from core.rar_parser import RarParser
from kdf_engine.pbkdf2_adapter import PBKDF2Adapter
from cipher.aes256_rar_adapter import AES256RARAdapter
from validation.structure_validator import StructureValidator
from validation.result_classifier import ValidationState, ResultClassifier
from metrics.execution_metrics import ExecutionMetrics
from extraction.payload_extractor import PayloadExtractor

class ExecutionManager:
    """
    Responsabilidad:
    Coordinar el flujo completo de intento de apertura.
    
    Orquesta:
    1. Parseo (RarParser)
    2. Derivación de Clave (KDF Engine)
    3. Descifrado (Cipher Engine)
    4. Validación (Validation System)
    5. Métricas (Metrics)
    """

    def __init__(self):
        self.metrics = ExecutionMetrics()
        self.kdf = PBKDF2Adapter()
        self.cipher = AES256RARAdapter()
        self.validator = StructureValidator()

    def attempt_open(self, rar_path: str, password: str) -> dict:
        """
        Intenta abrir un archivo RAR con una contraseña dada.
        Retorna un reporte completo.
        """
        report = {
            "file": rar_path,
            "password_used": "***" if password else "None", # No loguear pass real en prod
            "status": "UNKNOWN",
            "metrics": {},
            "details": ""
        }
        
        self.metrics.start()
        
        try:
            # 1. Parseo y Extracción de Contexto
            print(f"[EXEC] Analizando {rar_path}...")
            parser = RarParser(rar_path)
            
            with parser:
                parser.parse()
                ctx = parser.get_crypto_context()
            
            salt = ctx.params.get('salt')
            if not salt:
                report["status"] = "NO_ENCRYPTION_FOUND"
                report["details"] = "No se detectó header de encriptación o salt."
                return report
            
            iterations = ctx.params.get('iterations', 32800)
            
            # 2. Derivación de Clave
            print(f"[EXEC] Derivando clave (Salt: {salt.hex()[:8]}..., Iter: {iterations})...")
            kdf_params = {
                "salt": salt,
                "iterations": iterations,
                "dklen": 32 # AES-256
            }
            
            # Password a bytes
            pass_bytes = password.encode('utf-8')
            derived_key = self.kdf.derive_key(pass_bytes, kdf_params)
            
            # 3. Extracción y Descifrado
            entries = parser.get_encrypted_entries()
            
            if not entries:
                report["status"] = "NO_PAYLOAD_FOUND"
                report["details"] = "Se encontró Salt pero no se identificaron archivos cifrados para probar."
                report["validation_state"] = "NOT_VERIFIED"
                report["validation_desc"] = "No hay datos cifrados accesibles."
            else:
                target_entry = entries[0]
                print(f"[EXEC] Intentando descifrar entrada: {target_entry.filename} (Offset: {target_entry.offset})")
                
                extractor = PayloadExtractor(rar_path)
                # Leemos un bloque (16 bytes) para validación rápida
                ciphertext = extractor.extract_chunk(target_entry, size=16)
                
                # Definir IV
                iv = target_entry.iv
                if not iv:
                     # Fallback para RAR5: El IV suele derivarse o estar en los datos.
                     # Si Metadata no lo encontró, usamos una heurística básica (Salt[:16])
                     # NOTA: En RAR5 real, el IV se inicializa a menudo con parte del Salt o se lee del stream.
                     iv = salt[:16] if salt and len(salt)>=16 else b'\x00'*16
                     # print("[WARN] No se detectó IV explícito, usando fallback.")

                try:
                    plaintext = self.cipher.decrypt_block(ciphertext, derived_key, iv)
                    
                    # 4. Validación
                    val_state = self.validator.validate_decrypted_block(plaintext)
                    
                    report["validation_state"] = val_state.name
                    report["validation_desc"] = ResultClassifier.describe(val_state)
                    
                    if val_state == ValidationState.VALID_STRUCTURE:
                        report["status"] = "SUCCESS_LIKELY"
                        report["details"] = "Descifrado exitoso con estructura válida detectada."
                    else:
                         report["status"] = "FAIL_INVALID_KEY"
                         report["details"] = "Descifrado completado pero el resultado parece basura (Clave incorrecta)."

                except Exception as e:
                     report["status"] = "ERROR_DECRYPT"
                     report["details"] = f"Error en descifrado: {e}"
                     report["validation_state"] = "ERROR"

        except Exception as e:
            report["status"] = "ERROR"
            report["details"] = str(e)
            print(f"[ERROR] Excepción durante ejecución: {e}")
            import traceback
            traceback.print_exc()
        finally:
            m = self.metrics.stop()
            report["metrics"] = m
        
        return report

if __name__ == '__main__':
    # Test rápido manual
    pass
