# malwn - malware information tool

Commandline tool to display file information for malware supporting yara rules.

Supports
- PE files
- MS word files (doc, docx)

## usage

    malwn                   print short info for all malware files in current folder
    malwn -r                print short info for all malware files in current folder and its subfolders
    malwn -l <filename>     print long info for malware file
    malwn -M <filename>     run all matching modules
    malwn -h                show help

## extend malwn

### yara rules

Upon first execution you can configure a path where `malwn` will look for all
`.yar` and `.yara` file recursively.

### modules

`malwn` can automatically execute modules if certain yara rules match.
The module folder can be configured upon first execution.
A subfolder with the same name as the corresponding yara rule has to be created there.
Any number of modules can be put inside this folder.
These modules must have a `run` function which expects the filename as input parameter and which should return the result as a string.
