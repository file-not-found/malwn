rule python_pe{
strings:
    $ = "PyImport"
    $ = "Py_Initialize"
    $ = "PyType"
    $ = "LoadLibraryEx"
    $ = "Python 3"
    $ = "Python 2"
condition:
    (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and
    5 of them
}
rule upx {
    strings:
        $mz = "MZ"
        $upx1 = {55505830000000}
        $upx2 = {55505831000000}
        $upx_sig = "UPX!"

    condition:
        $mz at 0 and $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024)
}

rule vbaProject {
strings:
    $ = "word/vbaProject.bin"
condition:
    1 of them
}

rule richheader {
strings:
    $mz = "MZ"
    $rich = "Rich"
condition:
    $mz at 0 and
    $rich in (128..256)
}

rule mingw_w64{
strings:
    $ = "Mingw-w64 runtime failure:"
condition:
    all of them
}

rule cobaltstrike_config{
strings:
    $ = "\x00\x00\x00\x1a\x00\x03\x00\x10GET\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1b\x00\x03\x00\x10POST\x00\x00" xor
condition:
    1 of them
}
