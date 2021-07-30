import subprocess

def run(filename):
    comp = subprocess.run(["richprint", filename], capture_output=True)
    return comp.stdout.decode("utf-8").rstrip("\n")
