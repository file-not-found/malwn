import os
import time
import core.fileinfo as fileinfo

try:
    import pefile
except ImportError:
    print("pefile is needed for PE32 files (pip3 install pefile)")
    exit(-1)

class FileInfo(fileinfo.FileInfo):
    pe = None

    def __init__(self, filename):
        try:
            self.pe = pefile.PE(filename, fast_load=True)
            self.fileformat = __name__
            #self.time = self.get_latest_time()
            self.time = self.format_time(self.get_compile_time(), ' ')
            super().__init__(filename)
        except pefile.PEFormatError:
            return None

    def get_export_time(self):
        s = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size
        if s > 0:
            export_data = self.pe.parse_export_directory(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress, s)
            if hasattr(export_data, 'struct') and hasattr(export_data.struct, 'TimeDateStamp'):
                return export_data.struct.TimeDateStamp
        return 0

    def get_resource_time(self):
        s = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size
        if s > 0:
            resource_data = self.pe.parse_resources_directory(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress, s)
            if hasattr(resource_data, 'struct') and hasattr(resource_data.struct, 'TimeDateStamp'):
                return resource_data.struct.TimeDateStamp
        return 0

    def get_arch_string(self):
        m = self.pe.FILE_HEADER.Machine
        if m == 0x14c:
            return "PE32"
        elif m == 0x8664:
            return "PE32+"
        else:
            return "PE"

    def get_type_string(self):
        c = self.pe.FILE_HEADER.Characteristics
        typ = "???"
        if c & 0x2000:
            typ = "dll"
        elif c & 0x2:
            typ= "exe"
        s = self.pe.OPTIONAL_HEADER.Subsystem
        sub = "unknown"
        if s == 1 or s == 8:
            sub = "native"
        elif s == 2:
            sub = "gui"
        elif s == 3:
            sub = "console"
        return "{} ({})".format(typ,sub)

    def get_compile_time(self):
        return self.pe.FILE_HEADER.TimeDateStamp

    def get_latest_time(self):
        ct = self.get_compile_time()
        et = self.get_export_time()
        #rt = get_resource_time(self.pe)
        if et == 0xffffffff:
            et = 0
        rt = 0
        if et > ct or rt > ct:
            ts = max(ct, et, rt)
            mark = '*'
        else:
            ts = ct
            mark = ' '
        return self.format_time(ts, mark)

    def format_time(self, ts, mark):
        return '{} UTC{}'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)), mark)

    def get_diec_output(self):
        import subprocess
        import json
        try:
            comp = subprocess.run(["diec", "-j", self.filename], capture_output=True)
            res = json.loads(comp.stdout)
            return ", ".join([x["string"] for x in res["detects"]])
        except FileNotFoundError:
            return None

    def get_banner(self):
        banner = []
        banner.append("{:5}".format(self.get_arch_string()))
        banner.append("{:18}".format(self.get_type_string()))
        banner.append("{:24}".format(self.time))
        banner.append("{:8} ".format(self.size))
        banner.append(self.filename)
        return banner

    def get_info(self):
        info = super().get_info()
        info["Compile Timestamp"] = self.format_time(self.get_compile_time(), "")
        info["Export Timestamp"] = self.format_time(self.get_export_time(), "")
        info["Resource Timestamp"] = self.format_time(self.get_resource_time(), "")
        diec = self.get_diec_output()
        if diec != None:
            info["Compiler Info"] = diec
        return info
