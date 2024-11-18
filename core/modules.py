import os.path
import sys

import core.loader as loader

modules = {}

def add_args(parser):
    parser.add_argument("-M", "--allmodules", default=False, action="store_true", help="run all supported modules")
    parser.add_argument("-m", "--module", action="append", help="module to run")
    return parser

def init_modules(folder, args):
    global modules
    if args.allmodules == False and args.module == False:
        return
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

def run(fileinfo, compatible_modules, args):
    results = {}
    for r in compatible_modules.keys():
        if args.allmodules or (args.module and r in [m.split("/")[0] for m in args.module]):
            for module in modules[r]:
                if args.allmodules or (args.module and r in args.module or f"{r}/{module.__name__}" in args.module):
                    v = module.run(fileinfo.path)
                    if v != None:
                        if r not in results:
                            results[r] = {}
                        results[r][module.__name__] = v
    return results
