import subprocess
import sys

def run(filename):
    try:
        comp = subprocess.run(["richprint", filename], capture_output=True)
        return "\n" + comp.stdout.decode("utf-8")
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
