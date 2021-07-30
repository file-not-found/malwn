# malwn - malware information tool

Commandline tool to display file information for malware supporting yara rules.

Supports
- PE files
- MS word files

## usage

    malwn                   print short info for all malware files in current folder
    malwn -r                print short info for all malware files in current folder and its subfolders
    malwn -l <filename>     print long info for malware file
    malwn -M <filename>     run all matching modules
    malwn -h                show help

## extend malwn

### yara rules

Yara rules should be placed in the folder `yara-rules/` for the related file type.
Filename and rule names can be chosen freely.

### modules

`malwn` can automatically execute modules if certain yara rules match. New modules
can be created by creating a folder `modules/<yara_rule_name>/`. Here any number
of modules can be created as `<module_name>/<module_name>.py`. These modules
must have a `run` function which takes a filename as parameter and returns a string.
