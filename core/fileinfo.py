#!/usr/bin/env python3
import os.path
import sys

import collections
import math
import os

import core.loader as loader

import_error = False
try:
    import magic
except ImportError as e:
    print(f"ImportError: {__file__}: {e} (pip3 install python-magic)", file=sys.stderr)
    import_error = True
if import_error:
    exit(-1)

formats = []

def add_args(parser):
   parser.add_argument("-a", "--all", default=False, action="store_true", help="analyze all files")
   return parser


class FileInfo:
    filename = None
    size = None

    fileformat = ""
    filetype = None
    magic = None
    time = ""

    info = {}

    def __init__(self, filename):
        self.filename = filename
        self.size = os.stat(self.filename).st_size
        self.magic = magic.from_file(self.filename)

    def calc_entropy(self):
        with open(self.filename, "rb") as infile:
            data = infile.read()
        l = len(data)
        if l == 0:
            return 0
        e = 0
        counter = collections.Counter(data)
        for count in counter.values():
            # count is always > 0
            p_x = count / l
            e += - p_x * math.log2(p_x)
        return e

    def get_banner(self):
        banner = []
        banner.append("{:5}".format(self.fileformat))
        if self.time and self.filetype:
            banner.append("{:18}".format(self.filetype[:18]))
            banner.append("{:24}".format(self.time))
        else:
            banner.append("{:42}".format(self.magic.split(",")[0][:42]))
            banner.append("")
        banner.append("{:8} ".format(self.size))
        banner.append(self.filename)
        return banner

    def set_info(self):
        import hashlib
        self.info = {}
        self.info["Filename"] = os.path.basename(self.filename)
        with open(self.filename, "rb") as infile:
            data = infile.read()
        self.info["MD5"] = hashlib.md5(data).hexdigest()
        self.info["SHA1"] = hashlib.sha1(data).hexdigest()
        self.info["SHA256"] = hashlib.sha256(data).hexdigest()
        self.info["Filesize (Bytes)"] = self.size
        self.info["Filetype"] = self.magic
        #self.info["Entropy"] = self.calc_entropy()

    def get_info(self):
        self.set_info()
        return self.info

def init_formats(path):
    global formats
    if formats == []:
        formats = loader.import_all(path)

def get_fileinfo(filename, args):
    global formats
    for f in formats:
        fileinfo = f.FileInfo(filename)
        if fileinfo.fileformat:
            return fileinfo
    if args.all:
        return FileInfo(filename)
    return None
