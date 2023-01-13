#!/usr/bin/env python3
import os.path
import sys

import collections
import math
import os

imports_ok = True
# 
try:
    import exiftool
except ImportError:
    imports_ok = False
    print("pyexiftool is needed for docx files (pip3 install pyexiftool)")

try:
    import magic
except ImportError:
    imports_ok = False
    print("python-magic is needed (pip3 install python-magic)")

if not imports_ok:
    exit(-1)

formats = {}

def add_args(parser):
   parser.add_argument("-a", "--all", default=False, action="store_true", help="analyze all files")
   return parser


class FileInfo:
    filename = None
    size = None

    fileformat = None
    filetype = None
    time = ""

    def __init__(self, filename):
        self.filename = filename
        self.size = os.stat(self.filename).st_size
        if self.filetype == None:
            self.filetype = magic.from_file(self.filename)
        if self.fileformat == None:
            self.fileformat = 'other'

    def entropy(self):
        with open(self.filename, "rb") as infile:
            data = infile.read()
            e = 0

            counter = collections.Counter(data)
            l = len(data)
            for count in counter.values():
                # count is always > 0
                p_x = count / l
                e += - p_x * math.log2(p_x)

            return e

    def get_banner(self):
        banner = []
        banner.append(" " * 5)
        m = self.filetype.split(",")[0]
        if len(m) > 41:
            m = m[:38] + "..."
        banner.append("{:41}".format(m))
        banner.append("")
        banner.append("{:9} ".format(self.size))
        banner.append(self.filename)
        return banner

    def get_info(self):
        import hashlib
        info = {}
        info["Filename"] = self.filename
        with open(self.filename, "rb") as infile:
            data = infile.read()
            info["MD5"] = hashlib.md5(data).hexdigest()
            info["SHA1"] = hashlib.sha1(data).hexdigest()
            info["SHA256"] = hashlib.sha256(data).hexdigest()
        info["Filesize (Bytes)"] = self.size
        info["Filetype"] = self.filetype
        #info["Entropy"] = self.entropy()
        return info

def load_modules(path, modules):
    for d in os.listdir(path):
        if os.path.isdir(path + "/" + d):
            sys.path.append(os.path.abspath(path + "/" + d))
            modules[d] = __import__(d)

def get_fileinfo(filename, args):
    global formats
    if formats == {}:
        path = os.path.dirname(__file__) + "/../formats/"
        load_modules(path, formats)
    for f in formats:
        m = formats[f]
        fileinfo = m.FileInfo(filename)
        if fileinfo.fileformat:
            return fileinfo
    if args.all:
        return FileInfo(filename)
    return None
