def dict_to_str(d, keys=True):
    if keys:
        t = ""
        for k, v in d.items():
            s = to_str(v, keys)
            # skip empty values
            if s != "":
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

def print_result(result):
    print(result["fileinfo"].filename)
    print(to_str(result["fileinfo"].get_info(), keys=True))
    if result["matches"]:
        m = to_str(result["matches"], keys=True)
        if m != "":
            print(to_str(result["matches"], keys=True))
    print()
