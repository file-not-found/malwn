#!/usr/bin/env python3
import os.path
import os
from argparse import ArgumentParser

import threading
import queue

import core.dirwalker as dirwalker
import core.yaramatch as yaramatch
import core.fileinfo as fileinfo
import core.vtinfo as vtinfo
import core.cli as cli
import core.modules as modules

from configparser import ConfigParser

MALWN_PATH = os.path.dirname(os.path.realpath(__file__))
CONFIG =  MALWN_PATH + '/config.ini'
malwn_conf = {}

def init_config(reset=False):
    global malwn_conf
    config = ConfigParser()
    config.read(CONFIG)
    if reset or not 'malwn' in config:
        config['malwn'] = {}
    if not 'yara_path' in config['malwn']:
        default = MALWN_PATH + "/yara-rules/"
        p = input(f'please enter path to yara rules [{default}]: ')
        if p == "":
            p = default
        yara_path = os.path.abspath(os.path.expanduser(p))
        config['malwn']['yara_path'] = yara_path
        reset = True
    if not 'module_path' in config['malwn']:
        default = MALWN_PATH + "/modules/"
        p = input(f'please enter path to malwn modules [{default}]: ')
        if p == "":
            p = default
        module_path = os.path.abspath(os.path.expanduser(p))
        config['malwn']['module_path'] = module_path
        reset = True
    if not 'default_output' in config['malwn']:
        p = input(f'please enter default output format: ')
        config['malwn']['default_output'] = p
        reset = True
    if not 'vt_api_key' in config['malwn']:
        p = input(f'please enter the virustotal api key: ')
        config['malwn']['vt_api_key'] = p
        reset = True
    if reset:
        with open(CONFIG, 'w') as configfile:
            config.write(configfile)
    malwn_conf = config['malwn']

def fileworker():
    while True:
        file = filequeue.get()
        if not file:
            filequeue.task_done()
            break;
        cli.debug_print("processing file {}".format(file), args)

        info = fileinfo.get_fileinfo(file, args)
        if info == None:
            filequeue.task_done()
            continue
        cli.debug_print("got fileformat", args)

        vt = vtinfo.get_vtinfo(info, args)
        cli.debug_print("got vt info", args)

        matches = yaramatch.get_yaramatches(info, args)
        cli.debug_print("got matches", args)
        rulenames = [str(item) for e in matches for item in matches[e]]

        compatible_modules = modules.get_compatible_modules(rulenames)
        modinfo = modules.run(info, compatible_modules, args)
        results[file] = {}
        results[file]["banner"] = info.get_banner()
        results[file]["fileinfo"] = info.get_info()
        results[file]["vtinfo"] = vt
        results[file]["yaramatches"] = matches
        results[file]["modules"] = modinfo
        filequeue.task_done()

def add_args(parser):
    parser.add_argument("-s", "--sort", action="store_true", default=False, help="sort results by timestamp")
    parser.add_argument("-t", "--threads", type=int, default=10, help="number of concurrent threads")
    parser.add_argument("--reset", action="store_true", default=False, help="reset config file")
    return parser

if __name__ == '__main__':

    fileinfo.init_formats(MALWN_PATH + "/formats/")
    cli.init_formats(MALWN_PATH + "/output/")

    parser = ArgumentParser()
    parser = dirwalker.add_args(parser)
    parser = fileinfo.add_args(parser)
    parser = vtinfo.add_args(parser)
    parser = yaramatch.add_args(parser)
    parser = cli.add_args(parser)
    parser = modules.add_args(parser)

    parser = add_args(parser)
    args = parser.parse_args()

    init_config(args.reset)

    cli.debug_print("compiling yara rules", args)
    vtinfo.init_api(malwn_conf["vt_api_key"])
    yaramatch.init_rules(malwn_conf["yara_path"], args)
    modules.init_modules(malwn_conf["module_path"])

    filequeue = queue.Queue()

    for file in dirwalker.get_all_files(args):
        if not os.path.isfile(file):
            continue
        filequeue.put(file)

    cli.debug_print("starting threads", args)
    threads = []
    results = {}
    for i in range(args.threads):
        t = threading.Thread(target=fileworker)
        t.start()
        threads.append(t)

    filequeue.join()
    cli.debug_print("filequeue finished", args)
    for i in threads:
        filequeue.put(None)
    for t in threads:
        t.join()
    cli.debug_print("threads stopped", args)

    if args.sort:
        results = dict(sorted(results.items(), key=lambda x: x[1]["banner"][25:]))
    cli.print_results(results, malwn_conf["default_output"], args)
