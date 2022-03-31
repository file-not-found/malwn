def get_url(data):
    m = data.find(b'.&.-/.')
    url = b''
    if m >= 0:
        pos = m + 6
        while pos < len(data) and data[pos] != 0x2e:
            url += bytes([data[pos] ^ 0x2e, ])
            pos += 1
    return url

def get_port(data):
    m = data.find(b'.,./.,')
    port = 0
    if m >= 0:
        pos = m + 6

        if pos + 1 < len(data):
            port = (data[pos] ^ 0x2e )* 0x100 + (data[pos + 1] ^ 0x2e)
    return port


def run(filename):
    with open(filename, "rb") as infile:
        data = infile.read()
    start = data.find(b'././.,')
    if start < 0:
        return None
    url = get_url(data[start + 6:]).decode("utf-8")
    port = get_port(data[start + 6:])
    return "\nURL:    {}\nPORT:   {}\n".format(url, port)
