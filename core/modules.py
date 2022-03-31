import os.path
import sys

def add_args(parser):
    parser.add_argument("-M", "--allmodules", default=False, action="store_true", help="run all supported modules")
    parser.add_argument("-m", "--module", help="module to run")
    return parser

def import_modules(rulename):
    path = os.path.dirname(__file__) + "/../modules/" + rulename
    if os.path.isdir(path):
        for d in os.listdir(path):
            if os.path.isdir(path + "/" + d):
                sys.path.append(os.path.abspath(path + "/" + d))
                yield __import__(d)

def get_modules(rulenames):
    modules = []
    for rulename in rulenames:
        path = os.path.dirname(__file__) + "/../modules/" + rulename
        if os.path.isdir(path):
            modules.append(rulename)
    return modules

def run(r, args):
    if type(r["matches"]) is dict:
        for m in [str(v) for l in r["matches"].values() for v in l]:
            if args.allmodules or (args.module and args.module.split("/")[0] == m):
                for module in import_modules(str(m)):
                    if args.allmodules or not "/" in args.module or args.module.split("/")[1] == module.__name__:
                        result = module.run(r["fileinfo"].filename)
                        print("  -> {} module: {}".format(module.__name__, result))
