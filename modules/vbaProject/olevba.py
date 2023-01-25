import sys
import subprocess

def run(filename):
    try:
        comp = subprocess.run(["olevba", filename], capture_output=True)
        with open(filename + ".olevba", "wb") as outfile:
            outfile.write(comp.stdout)
        return "output saved as {}".format(filename + ".olevba")
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        return None
