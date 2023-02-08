
obsidian_refs = ['MD5', 'SHA1', 'SHA256', 'Source']
#obsidian_code = ['Filename', 'Filetype', 'Compiler Info', 'PDB Filename', 'Export DLL Name']

def dict_to_str(d, keys=True):
    if keys:
        t = ""
        for k, v in d.items():
            s = to_str(v, keys)
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
        return " ".join(to_str(d[e], keys) for e in d)

def list_to_str(l, keys=False):
    return " ".join(to_str(x, keys) for x in l)

def to_str(x, keys=True):
    if not x:
        return ""
    elif type(x) is dict:
        return dict_to_str(x, keys)
    elif type(x) is list:
        return list_to_str(x, keys)
    else:
        return str(x)

def print_results(results):
    for f in results:
        print(f)
        print(to_str(results[f]["fileinfo"], keys=True))
        if results[f]["yaramatches"]:
            m = to_str(results[f]["yaramatches"], keys=True)
            if m != "":
                print(m)
        if results[f]["modules"]:
            for rule in results[f]["modules"]:
                for mod in results[f]["modules"][rule]:
                    m = to_str(results[f]["modules"][rule][mod], keys=True)
                    if m != "":
                        #print(f"**{rule}.{mod}**")
                        print(m)
        print("## vt")
        print(to_str(results[f]["vtinfo"], keys=True))
        print()
