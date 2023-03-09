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

def get_fileinfo(path, args):
    global formats
    for f in formats:
        fileinfo = f.FileInfo(path)
        if hasattr(fileinfo, 'fileformat'):
            return fileinfo
    if args.all:
        return FileInfo(path)
    return None

def contains_hash(s):
    hexchars = "1234567890ABCDEFabcdef"
    splitchars = "."
    if '.' in s:
        s_list = s.split('.')
    elif '_' in s:
        s_list = s.split('_')
    else:
        s_list = [s, ]
    for s in s_list:
        if len(s) == 64 or len(s) == 40 or len(s) == 32:
            if all(c in hexchars for c in s):
                return True
    return False

class FileInfo:

    def __init__(self, path):
        self.path = path
        self.fileformat = ""
        self.filetype = None
        self.size = os.stat(self.path).st_size
        self.time = ""
        self.magic = magic.from_file(self.path)
        self.filenames = []
        self.info = {}

    def calc_entropy(self):
        with open(self.path, "rb") as infile:
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
        if name in self.filenames or contains_hash(name):
            return
        self.filenames.append(name)

    def get_banner(self):
        if self.filetype:
            banner = "{:6}".format(self.fileformat[:5])
            if len(self.filetype) > 18:
                banner += "{:19}".format(self.filetype[:15] + "...")
            else:
                banner += "{:19}".format(self.filetype[:18])
            banner += "{:24}".format(self.time)
        else:
            banner = "      {:43}".format(self.magic.split(",")[0][:42])
        banner += "{:9}".format(self.size)
        return banner

    def set_info(self):
        import hashlib
        with open(self.path, "rb") as infile:
            data = infile.read()
        self.add_filename(os.path.basename(self.path))
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
