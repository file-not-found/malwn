rule vbaProject {
strings:
    $ = "word/vbaProject.bin"
condition:
    1 of them
}
