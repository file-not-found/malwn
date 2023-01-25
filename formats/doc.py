import os
import re
import sys
import datetime
import time
import core.fileinfo as fileinfo

import_error = False
try:
    import exiftool
except ImportError as e:
    print(f"ImportError: {__file__}: {e} (pip3 install pyexiftool)", file=sys.stderr)
    import_error = True
if import_error:
    exit(-1)

class FileInfo(fileinfo.FileInfo):
    metadata = {}

    def __init__(self, filename):
        try:
            header = b''
            with open(filename, "rb") as infile:
                header = infile.read(4)
            if header == b"\xd0\xcf\x11\xe0":
                super().__init__(filename)
                self.magic = self.magic.split(',')[0]
                with exiftool.ExifToolHelper() as et:
                    self.metadata = et.get_metadata(filename)[0]

                self.set_modification_date()
                self.set_fileformat()
                self.set_filetype()
        except FileNotFoundError as e:
            print(e, file=sys.stderr)
            pass

    def set_fileformat(self):
        if 'File:FileType' in self.metadata:
            self.fileformat = self.metadata['File:FileType']

    def set_filetype(self):
        if 'FlashPix:CompObjUserType' in self.metadata and self.metadata['FlashPix:CompObjUserType'] != '':
            self.filetype = self.metadata['FlashPix:CompObjUserType'].replace("Microsoft Word", "MS Word").replace(" Document", "")
        else:
            self.filetype = self.magic

    def set_modification_date(self):
        if 'FlashPix:ModifyDate' in self.metadata:
            self.time = self.format_datetime(self.metadata['FlashPix:ModifyDate'])

    def format_datetime(self, t):
        if "+" in t:
            offset = t.split("+")[1].replace(":", "")
            t = t.split("+")[0] + "+" + offset
            ts = datetime.datetime.strptime(t, "%Y:%m:%d %H:%M:%S%z")
            t = time.strftime("%Y-%m-%d %H:%M:%S UTC",ts.utctimetuple())
        else:
            ts = datetime.datetime.strptime(t, "%Y:%m:%d %H:%M:%S")
            t = time.strftime("%Y-%m-%d %H:%M:%S",ts.utctimetuple())
        return t

    def set_info(self):
        super().set_info()
        if 'FlashPix:Author' in self.metadata:
            self.info["Author"] = self.metadata['FlashPix:Author']
        if 'FlashPix:CreateDate' in self.metadata:
            self.info["Create Date"] = self.format_datetime(self.metadata['FlashPix:CreateDate'])
        if 'FlashPix:LastModifiedBy' in self.metadata:
            self.info["Last Modified By"] = self.metadata['FlashPix:LastModifiedBy']
        self.info["Modify Date"] = self.time
        if 'FlashPix:Template' in self.metadata:
            self.info["Template"] = self.metadata['FlashPix:Template']
        if 'FlashPix:LanguageCode' in self.metadata:
            self.info["LanguageCode"] = hex(int(self.metadata['FlashPix:LanguageCode']))
        if 'FlashPix:TotalEditTime' in self.metadata:
            self.info["Total Edit Time"] = self.metadata['FlashPix:TotalEditTime']
