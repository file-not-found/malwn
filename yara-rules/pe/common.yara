rule rarSFX{
strings:
    $ = { 50 4b 01 02 }
    $ = { 50 4b 03 04 }
    $ = "WinRAR SFX"
    $ = "sfxcmd" wide
    $ = "winrarsfxmappingfile.tmp" wide
condition:
    all of them
}
rule richheader{
strings:
    $rich = "Rich"
condition:
    $rich in (128..256)
}
