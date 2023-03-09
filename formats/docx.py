import os
import re
import sys
import zipfile

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

    def __init__(self, path):
        try:
            with open(path, "rb") as infile:
                header = infile.read(4)
            if header == b"\x50\x4b\x03\x04":
                self.zipfile = zipfile.ZipFile(path)
                if "[Content_Types].xml" in self.zipfile.namelist() and "docProps/app.xml" in self.zipfile.namelist() and "docProps/core.xml" in self.zipfile.namelist():
                    self.fileformat = __name__
                    super().__init__(path)
                    self.time = self.get_modification_date()
                self.set_fileformat()
                self.set_filetype()
        except:
            pass

    def set_fileformat(self):
        with self.zipfile.open("[Content_Types].xml") as xmlfile:
            data = xmlfile.read()
        if b"document.macroEnabled.main+xml" in data:
            self.fileformat = "DOCM"
        elif b"document.main+xml" in data:
            self.fileformat = "DOCX"
        elif b"template.macroEnabledTemplate.main+xml" in data:
            self.fileformat = "DOTM"
        elif b"template.main+xml" in data:
            self.fileformat = "DOTX"
        elif b"application/vnd.openxmlformats-officedocument.spreadsheetml" in data:
            self.fileformat = "XLSX"
        elif b"application/vnd.ms-excel.sheet.macroEnabled" in data:
            self.fileformat = "XLSM"
        else:
            self.fileformat = "UNKN"

    def set_filetype(self):
        with self.zipfile.open("docProps/app.xml") as xmlfile:
            data = xmlfile.read()
        m = re.search(b"<Application>(.*)</Application>", data)
        if m:
            self.filetype = m.group(1).decode("utf-8")
        else:
            self.filetype = "unknown word"
        self.filetype = self.filetype.replace("Microsoft", "MS")
        self.filetype = self.filetype.replace(" Office", "")
        m = re.search(b"<AppVersion>(.*)</AppVersion>", data)
        if m:
            self.filetype += " (v{})".format(m.group(1).decode("utf-8").split(".")[0])

    def get_modification_date(self):
        with self.zipfile.open("docProps/core.xml") as xmlfile:
            data = xmlfile.read()
        m = re.search(b"<dcterms:modified .*>(.*)</dcterms:modified>", data)
        if m:
            return m.group(1).decode("utf-8").replace("T", " ").replace("Z", " UTC")
        else:
            return ""

    def set_info(self):
        super().set_info()
        self.time = self.get_modification_date()
        with exiftool.ExifToolHelper() as et:
            meta = et.get_metadata(self.path)
            self.info["DOCinfo"] = {}
            if "File:FileType" in meta:
                self.info["DOCinfo"]["Type"] = meta["File:FileType"]
            if "XML:Application" in meta:
                self.info["DOCinfo"]["Application"] = meta["XML:Application"]
                if "XML:AppVersion" in meta:
                    self.info["DOCinfo"]["Application"] += " (v{})".format(meta["XML:AppVersion"])
            if "XMP:Creator" in meta:
                self.info["DOCinfo"]["Creator"] = meta["XMP:Creator"]
            if "XML:CreateDate" in meta:
                self.info["DOCinfo"]["Create Date"] = meta["XML:CreateDate"]
            if "XML:LastModifiedBy" in meta:
                self.info["DOCinfo"]["Last Modified By"] = meta["XML:LastModifiedBy"]
            self.info["DOCinfo"]["Modify Date"] = self.time
            if "XML:Template" in meta:
                self.info["DOCinfo"]["Template"] = meta["XML:Template"]
            if "XML:TotalEditTime" in meta:
                self.info["DOCinfo"]["Total Edit Time"] = meta["XML:TotalEditTime"]
            if "XML:Pages" in meta:
                self.info["DOCinfo"]["Pages"] = meta["XML:Pages"]
            if "XML:Words" in meta:
                self.info["DOCinfo"]["Words"] = meta["XML:Words"]
            if "XML:Characters" in meta:
                self.info["DOCinfo"]["Characters"] = meta["XML:Characters"]
