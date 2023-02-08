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
    #TODO: parser.add_argument("--onlyhits", default=False, action="store_true", help="only print files with yara matches")
    return parser

def print_results(results, default_output, args):
    if args.long:
        if args.output == '':
            args.output = default_output
        global formats
        for f in formats:
            if f.__name__ == args.output:
                f.print_results(results)
    else:
        for f in results:
            print(results[f]["banner"] + "  " + f + "  " + " ".join([str(m) for matches in results[f]["yaramatches"].values() for m in matches]))

def debug_print(message, args):
    if args.debug:
        print("{} {}".format(datetime.datetime.now(), message))
