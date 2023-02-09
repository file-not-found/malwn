import datetime
import core.loader as loader

formats = []

def init_formats(path):
    global formats
    formats = loader.import_all(path)

def add_args(parser):
    global formats
    parser.add_argument("-o", "--output", default='', choices=[x.__name__ for x in formats], help="output format")
    parser.add_argument("-l", "--long", default=False, action="store_true", help="long output (uses default output from config)")
    parser.add_argument("--debug", default=False, action="store_true", help="print debug messages")
    parser.add_argument("--onlyhits", default=False, action="store_true", help="only print files with yara matches in short output")
    parser.add_argument("--nohits", default=False, action="store_true", help="only print files with no yara matches in short output")
    parser.add_argument("-y", "--yara_rule", help="filter on single rule")
    return parser

def single_print(path, result):
    res = result["Banner"] + "  " + path
    if "Fileinfo" in result and "Yara" in result["Fileinfo"] and result["Fileinfo"]["Yara"]:
        res += "  " + " ".join(result["Fileinfo"]["Yara"])
    print(res)

def print_results(results, default_output, args):
    if args.output == '':
        args.output = default_output
    else:
        args.long = True
    if args.long:
        global formats
        for f in formats:
            if f.__name__ == args.output:
                print_func = f.print_result
    else:
        print_func = single_print
    for path, result in results.items():
        if "Fileinfo" in result and "Yara" in result["Fileinfo"] and result["Fileinfo"]["Yara"]:
            if args.nohits:
                continue
            elif args.yara_rule and args.yara_rule not in result["Fileinfo"]["Yara"]:
                continue
        elif args.onlyhits or args.yara_rule:
            continue
        print_func(path, result)

def debug_print(message, args):
    if args.debug:
        print("{} {}".format(datetime.datetime.now(), message))
