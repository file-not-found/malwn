rule udf_iso_with_lnk{
strings:
    $ = "ImgBurn v2.5.8.0"
    $ = "UDF Compliant"
    $ = "This program cannot be run in DOS mode"
    $ = ".LNK;1"
condition:
    4 of them
}
