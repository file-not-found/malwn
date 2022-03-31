import os
import time
import core.fileinfo as fileinfo

try:
    import pefile
except ImportError:
    print("pefile is needed for PE32 files (pip3 install pefile)")
    exit(-1)

class FileInfo(fileinfo.FileInfo):
    arch_string = ""
    type_string = ""
    dot_net = False
    compile_time = 0
    export_time = 0
    resource_time = 0

    def __init__(self, filename):
        try:
            pe = pefile.PE(filename, fast_load=True)
            self.fileformat = __name__
            self.set_arch_string(pe)
            self.set_compile_time(pe)
            self.set_export_time(pe)
            self.set_resource_time(pe)
            self.check_dot_net(pe)
            self.set_type_string(pe)
            #self.time = self.get_latest_time()
            self.time = self.format_time(self.get_compile_time(), ' ')
            super().__init__(filename)
        except pefile.PEFormatError:
            return None

    def set_export_time(self, pe):
        s = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size
        if s > 0:
            export_data = pe.parse_export_directory(pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress, s)
            if hasattr(export_data, 'struct') and hasattr(export_data.struct, 'TimeDateStamp'):
                self.export_time = export_data.struct.TimeDateStamp

    def get_export_time(self):
        return self.export_time

    def set_resource_time(self, pe):
        s = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size
        if s > 0:
            resource_data = pe.parse_resources_directory(pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress, s)
            if hasattr(resource_data, 'struct') and hasattr(resource_data.struct, 'TimeDateStamp'):
                self.resource_time = resource_data.struct.TimeDateStamp

    def get_resource_time(self):
        return self.resource_time

    def set_arch_string(self, pe):
        m = pe.FILE_HEADER.Machine
        if m == 0x14c:
            self.arch_string = "PE32"
        elif m == 0x8664:
            self.arch_string = "PE32+"
        else:
            self.arch_string = "PE"

    def get_arch_string(self):
        return self.arch_string

    def check_dot_net(self, pe):
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size > 0 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0:
            self.dot_net = True

    def is_dot_net(self):
        return self.dot_net

    def set_type_string(self, pe):
        c = pe.FILE_HEADER.Characteristics
        typ = "???"
        if c & 0x2000:
            typ = "dll"
        elif c & 0x2:
            typ= "exe"
        sub = "unknown"
        if self.is_dot_net():
            sub = ".NET"
        else:
            s = pe.OPTIONAL_HEADER.Subsystem
            if s == 1 or s == 8:
                sub = "native"
            elif s == 2:
                sub = "gui"
            elif s == 3:
                sub = "console"
        self.type_string = "{} ({})".format(typ,sub)

    def get_type_string(self):
        return self.type_string

    def set_compile_time(self, pe):
        self.compile_time = pe.FILE_HEADER.TimeDateStamp

    def get_compile_time(self):
        return self.compile_time

    def get_latest_time(self):
        ct = self.get_compile_time()
        et = self.get_export_time()
        #rt = self.get_resource_time()
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
        except json.decoder.JSONDecodeError:
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
        export_time = self.get_export_time()
        if export_time != 0:
            info["Export Timestamp"] = self.format_time(export_time, "")
        resource_time = self.get_resource_time()
        if resource_time != 0:
            info["Resource Timestamp"] = self.format_time(resource_time, "")
        diec = self.get_diec_output()
        if diec != None:
            info["Compiler Info"] = diec
        return info
