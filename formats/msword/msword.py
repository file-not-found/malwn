import os
import core.fileinfo as fileinfo
import re

try:
    import exiftool
except ImportError:
    print("pyexiftool is needed for docx files (pip3 install pyexiftool)")
    exit(-1)

try:
    import zipfile
except ImportError:
    print("zipfile is needed for docx files (pip3 install pyexiftool)")
    exit(-1)

class FileInfo(fileinfo.FileInfo):
    zipfile = None

    def __init__(self, filename):
        try:
            self.zipfile = zipfile.ZipFile(filename)
            if "[Content_Types].xml" in self.zipfile.namelist() and "docProps/app.xml" in self.zipfile.namelist() and "docProps/core.xml" in self.zipfile.namelist():
                self.fileformat = __name__
                self.time = self.get_modification_date()
                super().__init__(filename)
        except:
            pass

    def get_type(self):
        with self.zipfile.open("[Content_Types].xml") as xmlfile:
            data = xmlfile.read()
        if b"document.macroEnabled.main+xml" in data:
            return "DOCM"
        elif b"document.main+xml" in data:
            return "DOCX"
        elif b"template.macroEnabledTemplate.main+xml" in data:
            return "DOTM"
        elif b"template.main+xml" in data:
            return "DOTX"
        else:
            return "dunno"

    def get_application(self):
        with self.zipfile.open("docProps/app.xml") as xmlfile:
            data = xmlfile.read()
        m = re.search(b"<Application>(.*)</Application>", data)
        if m:
            application = m.group(1).decode("utf-8").replace("Microsoft Office", "MS")
        else:
            application = "unknown word"
        m = re.search(b"<AppVersion>(.*)</AppVersion>", data)
        if m:
            application += " (v{})".format(m.group(1).decode("utf-8").replace("0000", "0"))
        return application

    def get_modification_date(self):
        with self.zipfile.open("docProps/core.xml") as xmlfile:
            data = xmlfile.read()
        m = re.search(b"<dcterms:modified .*>(.*)</dcterms:modified>", data)
        if m:
            return m.group(1).decode("utf-8").replace("T", " ").replace("Z", " UTC")
        else:
            return ""

    def get_banner(self):
        banner = []
        banner.append("{:5}".format(self.get_type()))
        banner.append("{:18}".format(self.get_application()))
        banner.append("{:24}".format(self.time))
        banner.append("{:8} ".format(self.size))
        banner.append(self.filename)
        return banner

    def get_info(self):
        filename = self.filename
        self.time = self.get_modification_date()
        with exiftool.ExifToolHelper() as et:
            meta = et.get_metadata(filename)
            info = super().get_info()
            if "File:FileType" in meta:
                info["Type"] = meta["File:FileType"]
            if "XML:Application" in meta:
                info["Application"] = meta["XML:Application"]
                if "XML:AppVersion" in meta:
                    info["Application"] += " (v{})".format(meta["XML:AppVersion"])
            if "XMP:Creator" in meta:
                info["Creator"] = meta["XMP:Creator"]
            if "XML:CreateDate" in meta:
                info["Create Date"] = meta["XML:CreateDate"]
            if "XML:LastModifiedBy" in meta:
                info["Last Modified By"] = meta["XML:LastModifiedBy"]
            info["Modify Date"] = self.time
            if "XML:Template" in meta:
                info["Template"] = meta["XML:Template"]
            if "XML:TotalEditTime" in meta:
                info["Total Edit Time"] = meta["XML:TotalEditTime"]
            if "XML:Pages" in meta:
                info["Pages"] = meta["XML:Pages"]
            if "XML:Words" in meta:
                info["Words"] = meta["XML:Words"]
            if "XML:Characters" in meta:
                info["Characters"] = meta["XML:Characters"]
            return info
