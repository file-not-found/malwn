import datetime

def add_args(parser):
   parser.add_argument("-c", "--csv", default=False, action="store_true", help="csv output")
   parser.add_argument("-l", "--long", default=False, action="store_true", help="long output")
   parser.add_argument("--debug", default=False, action="store_true", help="print debug messages")
   #TODO: parser.add_argument("--onlyhits", default=False, action="store_true", help="only print files with yara matches")
   return parser

def dict_to_str(d, csv, keys=True):
    if keys:
        t = ""
        for k, v in d.items():
            s = to_str(v, csv, keys)
            t += "{:20}{}\n".format(k, s)
        return t.rstrip("\n")
    else:
        if csv:
            return ",".join(to_str(d[e], csv, keys).strip(" ") for e in d)
        else:
            return " ".join(to_str(d[e], csv, keys) for e in d)

def list_to_str(l, csv=False, keys=False):
    if csv:
        return ",".join(to_str(x, csv, keys).strip(" ") for x in l)
    else:
        return " ".join(to_str(x, csv, keys) for x in l)

def to_str(x, csv=False, keys=True):
    if not x:
        return ""
    elif type(x) is dict:
        return dict_to_str(x, csv, keys)
    elif type(x) is list:
        return list_to_str(x, csv, keys)
    else:
        return str(x)

def print_result(result, args):
    if args.long:
        print(to_str(result["fileinfo"].get_info(), keys=True))
        if result["matches"]:
            print(to_str(result["matches"], keys=True))
        print()
    else:
        values = [result["fileinfo"].get_banner(), result["matches"]]
        print(to_str(values, args.csv, keys=False))

def debug_print(message, args):
    if args.debug:
        print("{} {}".format(datetime.datetime.now(), message))

