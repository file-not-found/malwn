import os
import sys

def import_all(folder):
    modules = []
    if not os.path.exists(folder):
        print("Invalid path: {}".format(folder))
    elif os.path.isdir(folder):
        for modulename in os.listdir(folder):
            if modulename.endswith(".py"):
                modulename = modulename[:-3]
                sys.path.append(os.path.abspath(folder))
                modules.append(__import__(modulename))
    return modules
