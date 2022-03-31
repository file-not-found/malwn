#!/usr/bin/env python3
import os.path
import os
from argparse import ArgumentParser

import core.dirwalker as dirwalker
import core.yaramatch as yaramatch
import core.fileinfo as fileinfo
import core.cli as cli
import core.modules as modules


def add_args(parser):
    parser.add_argument("-s", "--sort", action="store_true", default=False, help="sort results by timestamp")
    return parser

if __name__ == '__main__':
    parser = ArgumentParser()
    parser = dirwalker.add_args(parser)
    parser = fileinfo.add_args(parser)
    parser = yaramatch.add_args(parser)
    parser = cli.add_args(parser)
    parser = modules.add_args(parser)

    parser = add_args(parser)
    args = parser.parse_args()

    results = []
    for file in dirwalker.get_all_files(args):
        if not os.path.isfile(file):
            continue
        cli.debug_print("processing file {}".format(file), args)

        info = fileinfo.get_fileinfo(file, args)
        if info == None:
            continue
        cli.debug_print("got fileformat", args)

        matches = yaramatch.get_yaramatches(info, args)
        rulenames = [str(item) for e in matches for item in matches[e]]
        _modules = modules.get_modules(rulenames)
        cli.debug_print("got matches", args)

        r = {}
        r["fileinfo"] = info
        r["matches"] = matches
        #r["modules"] = _modules #TODO: mark matches if module is available (e.g. *richheader)
        results.append(r)
    if args.sort:
        results = sorted(results, key=lambda x: x["fileinfo"].time)
    for r in results:
        cli.print_result(r, args)
        modules.run(r, args)
