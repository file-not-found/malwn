#!/usr/bin/env python3
import os.path
import os

def get_files(paths, extensions=["",], recursive=False):
    for path in paths:
        if path.startswith('/'):
            to_path = os.path.abspath
        else:
            to_path = os.path.relpath
        if os.path.isdir(path):
            if recursive:
                for r, d, f in os.walk(path):
                    for filename in f:
                        for extension in extensions:
                            if filename.endswith(extension):
                                yield to_path(os.path.join(r, filename))
            else:
                for filename in os.listdir(path):
                    for extension in extensions:
                        if filename.endswith(extension):
                            yield to_path(os.path.join(path, filename))
        elif os.path.isfile(path):
            for extension in extensions:
                if path.endswith(extension):
                    yield to_path(path)

def get_all_files(args):
    return get_files(args.file, recursive=args.recursive)

def add_args(parser):
    parser.add_argument("file", nargs='*', default='.')
    parser.add_argument("-r", "--recursive", default=False, action="store_true", help="open directories recursively")
    return parser

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser = add_args(parser)

    args = parser.parse_args()

    for f in get_all_files(args):
        print(f)
