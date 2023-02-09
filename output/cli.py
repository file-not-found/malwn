noprint = ['Banner']

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

def print_results(results):
    for f in results:
        print(f"{f}")
        for i in results[f]:
            if i not in noprint and results[f][i]:
                print(f"### {i}")
                print(to_str(results[f][i], keys=True))
                #if results[f]["modules"]:
                #    for rule in results[f]["modules"]:
                #        for mod in results[f]["modules"][rule]:
                #            m = to_str(results[f]["modules"][rule][mod], keys=True)
                #            if m != "":
                #                #print(f"**{rule}.{mod}**")
                #                print(m)
        print()
