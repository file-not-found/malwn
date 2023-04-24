import os
import re
import sys
import time
import core.fileinfo as fileinfo

import_error = False
try:
    import pefile
except ImportError as e:
    print(f"ImportError: {__file__}: {e} (pip3 install pefile)", file=sys.stderr)
    import_error = True
try:
    import dotnetfile
except ImportError as e:
    print(f"ImportError: {__file__}: {e} (install dotnetfile from https://github.com/pan-unit42/dotnetfile)", file=sys.stderr)
    import_error = True
if import_error:
    exit(-1)


class FileInfo(fileinfo.FileInfo):
    dot_net = False
    compile_time = 0
    export_time = 0
    resource_time = 0
    export_name = None
    pdb_filename = None
    module_name = None
    assembly_info = {}
    guids = []

    def __init__(self, path):
        try:
            try:
                pe = dotnetfile.DotNetPE(path)
                self.dot_net = True
            except dotnetfile.parser.CLRFormatError:
                pe = pefile.PE(path, fast_load=True)
        except pefile.PEFormatError:
            return None
        try:
            super().__init__(path)
            self.fileformat = __name__
            self.set_fileformat(pe)
            self.set_compile_time(pe)
            self.set_export_time(pe)
            self.set_resource_time(pe)
            self.set_filetype(pe)
            self.set_export_name(pe)
            #self.time = self.get_latest_time()
            self.time = self.format_time(self.compile_time, ' ')
            self.set_pdb_filename(pe)
            if self.dot_net:
                self.set_module_name(pe)
                self.set_assembly_info(pe)
                self.set_guids(pe)
            del pe
        except Exception as e:
            print(e, file=sys.stderr)
            return None

    def get_data_directory_offset(self, pe, index):
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(dd) > index and hasattr(dd[index], 'Size') and hasattr(dd[index], 'VirtualAddress'):
            return dd[index].VirtualAddress, dd[index].Size
        return 0, 0

    def set_export_time(self, pe):
        va, s = self.get_data_directory_offset(pe, 0)
        if s > 0 and va > 0:
            export_data = pe.parse_export_directory(va, s)
            if hasattr(export_data, 'struct') and hasattr(export_data.struct, 'TimeDateStamp'):
                self.export_time = export_data.struct.TimeDateStamp

    def get_export_time(self):
        return self.export_time

    def set_export_name(self, pe):
        va, s = self.get_data_directory_offset(pe, 0)
        if s > 0 and va > 0:
            export_data = pe.parse_export_directory(va, s)
            if hasattr(export_data, 'name'):
                try:
                    self.export_name = export_data.name.decode("UTF-8")
                except:
                    return

    def set_resource_time(self, pe):
        va, s = self.get_data_directory_offset(pe, 2)
        if s > 0 and va > 0:
            resource_data = pe.parse_resources_directory(va, s)
            if hasattr(resource_data, 'struct') and hasattr(resource_data.struct, 'TimeDateStamp'):
                self.resource_time = resource_data.struct.TimeDateStamp

    def get_resource_time(self):
        return self.resource_time

    def set_fileformat(self, pe):
        m = pe.FILE_HEADER.Machine
        if m == 0x14c:
            self.fileformat = "PE32"
        elif m == 0x8664:
            self.fileformat = "PE32+"
        else:
            self.fileformat = "PE"

    def is_dot_net(self):
        return self.dot_net

    def set_filetype(self, pe):
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
        self.filetype = "{} ({})".format(typ,sub)

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

    def set_pdb_filename(self, pe):
        va, s = self.get_data_directory_offset(pe, 6)
        if s > 0 and va > 0:
            dbg_data = pe.parse_debug_directory(va, s)
            if dbg_data != None and len(dbg_data) > 0 and hasattr(dbg_data[0], 'entry') and hasattr(dbg_data[0].entry, 'PdbFileName'):
                try:
                    self.pdb_filename = dbg_data[0].entry.PdbFileName.strip(b"\0").decode("UTF-8")
                except:
                    self.pdb_filename = None

    def set_module_name(self, dotnetpe):
        if dotnetpe.metadata_table_exists('Module'):
            self.module_name = dotnetpe.Module.get_module_name()

    def set_assembly_info(self, dotnetpe):
        self.assembly_info = {}
        if dotnetpe.metadata_table_exists('Assembly'):
            self.assembly_info["Name"] = dotnetpe.Assembly.get_assembly_name()
            assembly_version_info = dotnetpe.Assembly.get_assembly_version_information()

            self.assembly_info["BuildNumber"] = str(assembly_version_info.BuildNumber)  
            self.assembly_info["MajorVersion"] = str(assembly_version_info.MajorVersion)
            self.assembly_info["MinorVersion"] = str(assembly_version_info.MinorVersion)
            self.assembly_info["RevisionNumber"] = str(assembly_version_info.RevisionNumber)

    def set_guids(self, dotnetpe):
        self.guids = []
        # Suchmuster für GUIDs
        guid_pattern = re.compile(
            rb'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}'
        )

        # Extrahiere GUIDs aus der Binärdaten
        guids = re.findall(guid_pattern, dotnetpe.__data__)

        # Dekodiere die GUIDs in Unicode-Zeichen
        self.guids = [guid.decode('utf-8') for guid in guids]
           
    def get_diec_output(self):
        import subprocess
        import json
        try:
            comp = subprocess.run(["diec", "-j", self.path], capture_output=True)
            res = json.loads(comp.stdout)
            if "detects" in res:
                if all("values" in x for x in res["detects"]):
                    l = res["detects"][0]["values"]
                else:
                    l = res["detects"]
                if all("string" in x for x in l):
                    return ", ".join([x["string"] for x in l])
            return None
        except FileNotFoundError:
            return None
        except json.decoder.JSONDecodeError:
            return None

    def set_peinfo(self):
        peinfo = {}
        peinfo["CompileTimestamp"] = self.format_time(self.get_compile_time(), "")
        diec = self.get_diec_output()
        if diec != None:
            peinfo["CompilerInfo"] = diec
        if self.pdb_filename != None:
            peinfo["PDB"] = self.pdb_filename
        if self.export_time != 0:
            peinfo["ExportTimestamp"] = self.format_time(self.export_time, "")
        if self.export_name != None:
            peinfo["ExportDLLName"] = self.export_name
            self.add_filename(self.export_name)
        if self.resource_time != 0:
            peinfo["ResourceTimestamp"] = self.format_time(self.resource_time, "")
        if self.module_name != None:
            peinfo["ModuleName"] = self.module_name
            self.add_filename(self.module_name)
        if self.assembly_info != {}:
            peinfo["AssemblyInfo"] = self.assembly_info
        if self.guids != []:
            peinfo["GUIDs"] = self.guids

        return peinfo

    def set_info(self):
        super().set_info()
        self.info["PEinfo"] = self.set_peinfo()
