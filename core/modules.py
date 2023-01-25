import os.path
import sys

import core.loader as loader

modules = {}

def add_args(parser):
    parser.add_argument("-M", "--allmodules", default=False, action="store_true", help="run all supported modules")
    parser.add_argument("-m", "--module", help="module to run")
    return parser

def init_modules(folder):
    global modules
    if os.path.isdir(folder):
        for rulename in os.listdir(folder):
            p = folder + "/" + rulename
            if os.path.isdir(p):
                modules[rulename] = loader.import_all(p)

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
