
obsidian_refs = ['MD5', 'SHA1', 'SHA256']
#obsidian_code = ['Filename', 'Filetype', 'Compiler Info', 'PDB Filename', 'Export DLL Name']

def dict_to_str(d, csv, keys=True):
    if keys:
        t = ""
        for k, v in d.items():
            s = to_str(v, csv, keys)
            # skip empty values
            if s != "":
                if k in obsidian_refs:
                    s = '[[' + s + ']]'
                #if k in obsidian_code:
                else:
                    s = '`' + s + '`'
                t += "{:20}{}\n".format(k, s)
        return t.rstrip("\n")
    else:
        if csv:
            return ",".join(to_str(d[e], csv, keys).strip(" ") for e in d)
        else:
            return " ".join(to_str(d[e], csv, keys) for e in d)

def list_to_str(l, csv=False, keys=False):
    if csv:
        return ",".join(to_str(x, csv, keys).strip(" ") for x in l)
    else:
        return " ".join(to_str(x, csv, keys) for x in l)

def to_str(x, csv=False, keys=True):
    if not x:
        return ""
    elif type(x) is dict:
        return dict_to_str(x, csv, keys)
    elif type(x) is list:
        return list_to_str(x, csv, keys)
    else:
        return str(x)

def print_result(result):
    print(result["fileinfo"].filename)
    print(to_str(result["fileinfo"].get_info(), keys=True))
    if result["matches"]:
        m = to_str(result["matches"], keys=True)
        if m != "":
            print(to_str(result["matches"], keys=True))
    print()
