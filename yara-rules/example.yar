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

rule cs_config_data{
strings:
    $ = { 2e 2f 2e 2f 2e 2c }
    $ = { 69 6b 7a }
    $ = { 7e 61 7d 7a }
    $ = { 2e 26 2e 2d 2f 2e }
condition:
    all of them
}
