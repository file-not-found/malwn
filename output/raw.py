import json

def print_result(path, result):
    print(json.dumps({path: result}, indent=2))
