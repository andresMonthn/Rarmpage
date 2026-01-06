import subprocess
import os

hashes = [
    # No trailing $0
    "$rar5$16$0ffab1a898b8e26c67f63916676e53d5$16$00000000000000000000000000000000$8$ca43553440075fcd",
]

hashcat_bin = r"C:\Users\Admin\Documents\.atomLogic\Rarmpage\rar-research\src\GPU\bin\hashcat-6.2.6\hashcat.exe"

for i, h in enumerate(hashes):
    # Need absolute path for hash file because we change CWD for hashcat
    fname = os.path.abspath(f"test_{i}.hash")
    with open(fname, "w", encoding="utf-8", newline="\n") as f:
        f.write(h + "\n")
        
    print(f"Testing Hash {i}: {h}")
    cmd = [hashcat_bin, "-m", "13000", fname, "--show"]
    try:
        cwd = os.path.dirname(hashcat_bin)
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        print(f"STDOUT: {res.stdout}")
        print(f"STDERR: {res.stderr}")
    except subprocess.TimeoutExpired as e:
        print("Timeout reached (Success? It started running!)")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
    except Exception as e:
        print(f"Error: {e}")
    print("-" * 20)
