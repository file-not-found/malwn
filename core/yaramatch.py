#!/usr/bin/env python3
import os.path
import os
import core.dirwalker as dirwalker

quality = { "high" : 1,
            "medium" : 0,
            "low" : -1 }

compiled_rules = {}

try:
    import yara
except ImportError:
    print("yara is needed (pip3 install yara)")
    exit(-1)

def get_rulepath(fileformat, args):
    if args.yara and os.path.exists(args.yara):
        return args.yara
    else:
        path = os.path.dirname(__file__) + "/../yara-rules/" + fileformat
        if os.path.isdir(path):
            return path
    return None

def get_yaramatches(fileinfo, args):
    #if not args.yara and not args.Yara:
    #    return None
    rulepath = get_rulepath(fileinfo.fileformat, args)
    if rulepath == None:
        return None
    matchgroups = yaramatches(fileinfo.filename, rulepath)
    matches_high = []
    matches_medium = []
    matches_low = []
    
    if args.quality in quality:
        filter_quality = quality[args.quality]
    else:
        filter_quality = quality["medium"]

    for matches in matchgroups:
        for x in matches:
            if "quality" in x.meta and x.meta["quality"] in quality:
                match_quality = quality[x.meta["quality"]]
            else:
                match_quality = quality["medium"]
            if match_quality >= quality["high"] and filter_quality <= quality["high"]:
                matches_high.append(x)
            elif match_quality <= quality["low"] and filter_quality <= quality["low"]:
                matches_low.append(x)
            elif match_quality == quality["medium"] and filter_quality <= quality["medium"]:
                matches_medium.append(x)
    return {"Yara (high)": matches_high, "Yara (medium)": matches_medium, "Yara (low)": matches_low}

def yaramatches(filename, rulepath):
    for file in dirwalker.get_files([rulepath]):
        try:
            if file not in compiled_rules:
                compiled_rules[file] = yara.compile(file)
        except:
            print("Error compiling yara rules file {}".format(file))
            pass
    matchgroups = []
    for ruleset in compiled_rules.values():
        try:
            matchgroups.append(ruleset.match(filename))
        except:
            pass
    return matchgroups

def add_args(parser):
    parser.add_argument("-q", "--quality", default='medium', choices=['high', 'medium', 'low'], help="minimum rule quality")
    parser.add_argument("-y", "--yara", help="yara rules file")
    #parser.add_argument("-Y", "--Yara", default=False, action="store_true", help="use default yara rules")
    return parser
