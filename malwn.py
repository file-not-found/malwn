#!/usr/bin/env python3
import os
import sys
from argparse import ArgumentParser

import threading
import queue

import core.dirwalker as m_dirwalker
import core.fileinfo as m_fileinfo
import core.output as m_output
import core.modules as m_modules
import core.yara as m_yara
import core.vt as m_vt

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
        try:
            tid = threading.get_native_id()
            m_output.debug_print("(TID {}) processing file {}".format(tid, file), args)

            fileinfo = m_fileinfo.get_fileinfo(file, args)
            if fileinfo == None:
                filequeue.task_done()
                continue
            m_output.debug_print("(TID {}) got fileformat".format(tid), args)

            vtinfo = m_vt.get_vtinfo(fileinfo, args)
            m_output.debug_print("(TID {}) got vt info".format(tid), args)

            yaramatches = m_yara.get_yaramatches(fileinfo, args)
            m_output.debug_print("(TID {}) got yara matches".format(tid), args)
            rulenames = yaramatches

            # dirty access to arguments from other modules to improve speed
            results[file] = {}
            results[file]["Banner"] = fileinfo.get_banner()
            m_output.debug_print("(TID {}) got banner".format(tid), args)
            results[file]["Fileinfo"] = {}
            if 'long' in args and args.long == True:
                results[file]["Fileinfo"] = fileinfo.get_info()
                m_output.debug_print("(TID {}) got verbose info".format(tid), args)
                results[file]["Fileinfo"]["VirusTotal"] = vtinfo
            results[file]["Fileinfo"]["Yara"] = yaramatches
            if ('module' in args and args.module != None) or ('allmodules' in args and args.allmodules == True):
                compatible_modules = m_modules.get_compatible_modules(rulenames)
                m_output.debug_print("(TID {}) got compatible modules".format(tid), args)
                modinfo = m_modules.run(fileinfo, compatible_modules, args)
                m_output.debug_print("(TID {}) ran compatible modules".format(tid), args)
                results[file]["Fileinfo"]["Modules"] = modinfo
        except Exception as e:
            print(f"Error processing {file}: {e}", file=sys.stderr)
        m_output.debug_print("(TID {}) file {} done".format(tid, file), args)
        filequeue.task_done()

def add_args(parser):
    parser.add_argument("-s", "--sort", action="store_true", default=False, help="sort results by timestamp")
    parser.add_argument("-t", "--threads", type=int, default=10, help="number of concurrent threads")
    parser.add_argument("--reset", action="store_true", default=False, help="reset config file")
    return parser

if __name__ == '__main__':

    m_fileinfo.init_formats(MALWN_PATH + "/formats/")
    m_output.init_formats(MALWN_PATH + "/output/")

    parser = ArgumentParser()
    parser = m_dirwalker.add_args(parser)
    parser = m_fileinfo.add_args(parser)
    parser = m_vt.add_args(parser)
    parser = m_yara.add_args(parser)
    parser = m_output.add_args(parser)
    parser = m_modules.add_args(parser)

    parser = add_args(parser)
    args = parser.parse_args()

    init_config(args.reset)

    m_output.debug_print("loading yara rules", args)
    m_yara.init_rules(malwn_conf["yara_path"], args)
    m_output.debug_print("yara rules loaded", args)

    m_modules.init_modules(malwn_conf["module_path"])
    m_vt.init_api(malwn_conf["vt_api_key"])

    filequeue = queue.Queue()

    for file in m_dirwalker.get_all_files(args):
        if not os.path.isfile(file):
            continue
        filequeue.put(file)

    m_output.debug_print("starting threads", args)
    threads = []
    results = {}
    for i in range(args.threads):
        t = threading.Thread(target=fileworker)
        t.start()
        threads.append(t)

    filequeue.join()
    m_output.debug_print("filequeue finished", args)
    for i in threads:
        filequeue.put(None)
    for t in threads:
        t.join()
    m_output.debug_print("threads stopped", args)

    if args.sort:
        results = dict(sorted(results.items(), key=lambda x: x[1]["Banner"][25:]))
    else:
        results = dict(sorted(results.items()))
    m_output.print_results(results, malwn_conf["default_output"], args)
