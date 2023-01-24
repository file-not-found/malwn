import os.path
import sys

modules = {}

def add_args(parser):
    parser.add_argument("-M", "--allmodules", default=False, action="store_true", help="run all supported modules")
    parser.add_argument("-m", "--module", help="module to run")
    return parser

def import_modules(folder):
    global modules
    if not os.path.exists(folder):
        print("Invalid path to malwn modules {}".format(folder))
        return
    if os.path.isdir(folder):
        for rulename in os.listdir(folder):
            if os.path.isdir(folder + "/" + rulename):
                if rulename not in modules:
                    modules[rulename] = []
                for modulename in os.listdir(folder + "/" + rulename):
                    if modulename.endswith(".py"):
                        modulename = modulename[:-3]
                        sys.path.append(os.path.abspath(folder + "/" + rulename ))
                        modules[rulename].append(__import__(modulename))

def get_compatible_modules(rulenames):
    global modules
    compatible_modules = {}
    for r in rulenames:
        if r in modules:
            compatible_modules[r] = modules[r]
    return compatible_modules

def run(filename, compatible_modules, args):
    for r in compatible_modules.keys():
        if args.allmodules or (args.module and args.module.split("/")[0] == r):
            for module in modules[r]:
                if args.allmodules or not "/" in args.module or args.module.split("/")[1] == module.__name__:
                    result = module.run(filename)
                    print(" ### {} module: {}".format(module.__name__, result))
