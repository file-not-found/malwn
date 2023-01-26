from binascii import hexlify
config_mark =   b'\x00\x01\x00\x01\x00\x02'
url_mark =      b'\x00\x08\x00\x03\x01\x00'
port_mark =     b'\x00\x02\x00\x01\x00\x02'
pubkey_mark =   b'\x00\x07\x00\x03\x01\x00'

def get_url(data, key):
    m = data.find(xor(url_mark, key))
    if m >= 0:
        url = b''
        pos = m + 6
        while pos < len(data) and data[pos] != key:
            url += bytes([data[pos] ^ key, ])
            pos += 1
        return url
    return None

def get_port(data, key):
    m = data.find(xor(port_mark, key))
    if m >= 0:
        pos = m + 6
        if pos + 1 < len(data):
            port = (data[pos] ^ key)* 0x100 + (data[pos + 1] ^ key)
        return port
    return None

def get_pubkey(data, key):
    m = data.find(xor(pubkey_mark, key))
    if m >= 0:
        pubkey = b''
        pos = m + 6
        while pos < len(data) and len(pubkey) < 256:
            pubkey += bytes([data[pos] ^ key, ])
            pos += 1
        return pubkey
    return None

def xor(data, key):
    result = b''
    for c in data:
        result += bytes([c ^ key, ])
    return result

def run(filename):
    with open(filename, "rb") as infile:
        data = infile.read()
    for key in range(256):
        start = data.find(xor(config_mark, key))
        if start < 0:
            continue
        url = get_url(data[start + 6:], key).decode("utf-8")
        port = get_port(data[start + 6:], key)
        pubkey = hexlify(get_pubkey(data[start + 6:], key)).decode("utf-8")
        if url and port and pubkey:
            #return "\nURL:    {}\nPORT:   {}\nPUBKEY: {}\n".format(url, port, pubkey)
            return {"C2 URL":url, "C2 Port": port, "C2 Public Key": pubkey}
