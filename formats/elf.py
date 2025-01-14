import os
import sys
import time
import re
import core.fileinfo as fileinfo

import_error = False
try:
    from elftools.elf.elffile import ELFFile
except ImportError as e:
    print(f"ImportError: {__file__}: {e} (pip3 install pyelftools)", file=sys.stderr)
    import_error = True
if import_error:
    exit(-1)



class FileInfo(fileinfo.FileInfo):
    buildid = None
    comment = None

    def __init__(self, path):
        with open(path, "rb") as infile:
            header = infile.read(4)
        if header == b"\x7fELF":
            infile = open(path, "rb")
            elf = ELFFile(infile)
            try:
                super().__init__(path)
                self.fileformat = __name__
                self.set_fileformat(elf)
                self.set_filetype(elf)
                self.set_buildid(elf)
                self.set_comment(elf)
            except Exception as e:
                print(e, file=sys.stderr)
                return None
            finally:
                infile.close()


    def set_fileformat(self, elf):
        if elf.elfclass == 32:
            self.fileformat = "ELF32"
        elif elf.elfclass == 64:
            self.fileformat = "ELF64"

    def set_filetype(self, elf):
        typ = elf.header.e_type[3:]
        machine = elf.header.e_machine[3:]
        self.filetype = "{} ({})".format(typ,machine)

    def get_type_string(self):
        return self.type_string

    def set_buildid(self, elf):
        s = elf.get_section_by_name('.note.gnu.build-id')
        if s != None:
            raw = s.data()
            self.buildid = raw[0x10:].hex()

    def set_comment(self, elf):
        s = elf.get_section_by_name('.comment')
        if s != None:
            raw = s.data()
            self.comment = raw.decode("utf-8")

    def format_time(self, ts, mark):
        return '{} UTC{}'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)), mark)


    def set_elfinfo(self):
        elfinfo = {}
        if self.buildid != None:
            elfinfo["BuildID"] = self.buildid
        if self.comment != None:
            elfinfo["Comment"] = self.comment

        return elfinfo

    def set_info(self):
        super().set_info()
        self.info["ELFinfo"] = self.set_elfinfo()
