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

def is_hash(s):
    hexchars = "1234567890ABCDEFabcdef"
    splitchars = "."
    if '.' in s:
        s = s.split('.')[0]
    if len(s) == 64 or len(s) == 40 or len(s) == 32:
        if all(c in hexchars for c in s):
            return True
    return False

class FileInfo:
    filename = None
    size = None

    fileformat = ""
    filetype = None
    magic = None
    time = ""
    filenames = []

    info = {}

    def __init__(self, filename):
        self.filename = filename
        self.size = os.stat(self.filename).st_size
        self.magic = magic.from_file(self.filename)
        self.filenames = []
        self.add_filename(os.path.basename(filename))

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

    def add_filename(self, name):
        if is_hash(name):
            return
        self.filenames.append(name)

    def get_banner(self):
        if self.time and self.filetype:
            banner = "{:6}".format(self.fileformat)
            banner += "{:19}".format(self.filetype)
            banner += "{:24}".format(self.time)
        else:
            banner = "      {:43}".format(self.magic.split(",")[0][:42])
        banner += "{:9}".format(self.size)
        return banner

    def set_info(self):
        import hashlib
        self.info = {}
        #self.info["Filename"] = os.path.basename(self.filename)
        with open(self.filename, "rb") as infile:
            data = infile.read()
        self.info["MD5"] = hashlib.md5(data).hexdigest()
        self.info["SHA1"] = hashlib.sha1(data).hexdigest()
        self.info["SHA256"] = hashlib.sha256(data).hexdigest()
        self.info["Filesize"] = str(self.size)+" bytes"
        self.info["Filetype"] = self.magic
        self.info["Filenames"] = self.filenames
        #self.info["Entropy"] = self.calc_entropy()

    def get_info(self):
        self.set_info()
        return self.info
