import os

def run(filename):
    outfile = filename + ".olevba"
    os.system("olevba {} 2>/dev/null > {}".format(filename, outfile))
    return "output saved as {}".format(outfile)
