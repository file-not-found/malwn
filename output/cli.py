indent = ' '

def obsidian_format(d, level=0):
    for k, v in d.items():
        if not v:
            continue
        elif type(v) == dict:
            print(indent * level + f"{k:20}")
            obsidian_format(v, level=level+1)
        elif type(v) == list:
            l = " ".join(v)
            print(indent * level + f"{k:20}{l}")
            #for e in v:
            #    print(indent * (level + 1) + f"{e:20}")
        elif type(v) == str:
            print(indent * level + f"{k:20}{v}")
            

def print_result(file, info):
    filenames = []
   
    finfo = info.get("Fileinfo")
    if finfo:
        print(f"{file}")
        obsidian_format(finfo, level=1)
