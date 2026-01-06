import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from GPU.extractor import RarHashExtractor

file_path = r"C:\Users\Admin\Documents\.atomLogic\Rarmpage\junke.rar"
extractor = RarHashExtractor(file_path)
h = extractor.get_hashcat_format()
print(f"HASH LEN: {len(h)}")
print(f"HASH: {h}")
