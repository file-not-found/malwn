#!/usr/bin/env python3
import os.path
import os
import sys
import core.dirwalker as dirwalker

import_error = False
try:
    import yara
except ImportError as e:
    print(f"ImportError: {__file__}: {e} (pip3 install yara-python)", file=sys.stderr)
    import_error = True
if import_error:
    exit(-1)

quality = { "high" : 1,
            "medium" : 0,
            "low" : -1 }

compiled_rules = {}


def get_yaramatches(fileinfo, args):
    matchgroups = yaramatches(fileinfo.filename)
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

def compile_rules(folder, args):
    global compiled_rules
    if args.Yara:
        return
    if args.yara:
        rulepath = args.yara
    else:
        rulepath = folder
    if not os.path.exists(rulepath):
        print("Invalid path to yara rules {}".format(rulepath), file=sys.stderr)
        return

    for yarafile in dirwalker.get_files([rulepath], extensions=[".yar", ".yara"], recursive=True):
        try:
            if yarafile not in compiled_rules:
                binfile = yarafile.replace(".yara", ".yar") + "bin"
                if os.path.exists(binfile) and os.stat(yarafile).st_mtime == os.stat(binfile).st_mtime:
                    compiled_rules[yarafile] = yara.load(binfile)
                else:
                    st = os.stat(yarafile)
                    atime = st.st_atime
                    mtime = st.st_mtime
                    compiled_rules[yarafile] = yara.compile(yarafile)
                    compiled_rules[yarafile].save(binfile)
                    os.utime(binfile, (st.st_atime, st.st_mtime))
        except Exception as e:
            print(f"Error compiling yara rules file: {e}", file=sys.stderr)
            pass

def yaramatches(filename):
    matchgroups = []
    for ruleset in compiled_rules.values():
        try:
            m = ruleset.match(filename)
            matchgroups.append(m)
        except:
            pass
    return matchgroups

def add_args(parser):
    parser.add_argument("-q", "--quality", default='medium', choices=['high', 'medium', 'low'], help="minimum rule quality")
    parser.add_argument("-y", "--yara", help="path to yara rules")
    parser.add_argument("-Y", "--Yara", default=False, action="store_true", help="disable yara")
    return parser
