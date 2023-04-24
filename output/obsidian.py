OBSIDIAN_REFS = ['MD5', 'SHA1', 'SHA256', 'SubmitterID', 'GUID']

indent = '    '

def obsidian_format(d, level=0):
    for k, v in d.items():
        if not v:
            continue
        elif type(v) == dict:
            print(indent * level + f"- {k}:")
            obsidian_format(v, level=level+1)
        elif type(v) == list:
            print(indent * level + f"- {k}:")
            for e in v:
                print(indent * (level + 1) + f"- `{e}`")
        elif type(v) == str:
            if k in OBSIDIAN_REFS:
                print(indent * level + f"- {k}: [[{v}]]")
            else:
                print(indent * level + f"- {k}: `{v}`")
            

def print_result(file, info):
    filenames = []
   
    fileinfo = info.get("Fileinfo")
    if fileinfo:
        label = fileinfo.get("SHA256")
        print(indent + f"- {label}:")
        obsidian_format(fileinfo, level=2)
