#!/bin/python3

import argparse
import base64
import getpass
import hashlib
import os
import pathlib
import subprocess
import sys
import time


SCRYPT_MAX_LENGTH=512
PASSLE_HOME = "PASSLE_HOME"
PASSLE_SITES_DIRECTORY_NAME = "sites"
PASSLE_ENDIANNESS = 'big'
AVAILABLE_ENCODINGS = {"base32": base64.b32encode, "base64": base64.b64encode,
                       "base85": base64.b85encode,
                       "decimal": lambda b: str(int.from_bytes(b, endianness=PASSLE_ENDIANNESS)),
                       "hexadecimal": lambda b: base64.b16encode}
VERBOSITY = None

def printinfo(*args, **kwargs):
    print(*args, *kwargs, file=sys.stderr)

def derive_pass(master, key, encode=None, length=None):
    n = 16384 # n — CPU/memory cost factor
    r = 32 # r — block size
    p = 1 # p — paralellization factor
    maxmem = 128 * r * (n + p + 2)
    length = length or 512
    encode = encode or base64.b64encode
    result = hashlib.scrypt(master.encode('utf-8'),
                            salt=key.encode('utf-8'),
                            n=n, r=r, p=p, maxmem=maxmem,
                            dklen=SCRYPT_MAX_LENGTH)
    encoded_result = encode(result).decode('utf-8')
    if SCRYPT_MAX_LENGTH >= length:
        return encoded_result[:length]
    else:
        raise Exception("Password can't have length {}".format(length))


def store_directory(store_directory=None):
    store_directory = store_directory or os.environ.get(PASSLE_HOME) or os.path.join(pathlib.Path.home(), ".passle")
    return valid_store_directory(store_directory)


def valid_store_directory(prospective_dir, writable=False):
    if os.path.isfile(prospective_dir):
        raise FileExistsError("{0} is a file, not a directory".format(prospective_dir))
    elif not os.path.isdir(prospective_dir):
        os.makedirs(os.path.join(prospective_dir, PASSLE_SITES_DIRECTORY_NAME))
    # is directory, now check permissions
    if not os.access(prospective_dir, os.R_OK):
        raise PermissionError("Need read permission on {}".format(prospective_dir))
    if writable and not os.access(prospective_dir, os.W_OK):
        raise PermissionError("Need write permission on {}".format(prospective_dir))
    return prospective_dir


def list_site_files(store_dir):
    site_files_dir = os.path.join(store_dir, PASSLE_SITES_DIRECTORY_NAME)
    for root, _, files in os.walk(site_files_dir, topdown=True):
        for f in files:
            yield (root, f)


def find_site_file(name, store_dir):
    for d, f in list_site_files(store_dir):
        if f == name:
            return os.path.join(d, f)
    raise Exception("Could not find site file for {}".format(name))


def parse_site_file(name, store_dir=None):
    store_dir = store_directory(store_dir)
    path = find_site_file(name, store_dir)
    if VERBOSITY:
        printinfo("Reading site file for {} at {}".format(name, path))
    with open(path, 'r') as f:
        key = f.readline().strip()
        if key:
            parse_result = {'key': key}
            for line in map(lambda s: s.strip(), f.readlines()):
                if line:
                    if line[0] == "#":
                        continue
                    key, value = line.split(sep=':', maxsplit=1)
                    key = key.rstrip()
                    value = value.lstrip()
                    if not parse_result.get(key):
                        if VERBOSITY:
                            printinfo("read {} for {}".format(value, key))
                        parse_result[key] = value
                    else:
                        raise Exception("Duplicate key {} for {}".format(key, name))
            return parse_result
        else:
            raise Exception("Key for {} may not empty".format(name))


##
# copy-paste functionality
def copy_nix(string):
    _cmd = ["xclip", "-selection", "clipboard"]
    def clear_clipboard():
        subprocess.run(_cmd, check=True, input="".encode('ascii'))
        return None
    subprocess.run(_cmd, check=True, input=string.encode('utf-8'))
    return clear_clipboard



##
# CLI

parser = argparse.ArgumentParser(description="Create a password.")
parser.add_argument('-k', '--as-key', action='store_true',
                    help="treat TARGET as key, not as a site name")
parser.add_argument('-c', '--clip', nargs='?', type=int, metavar="TIMEOUT",
                    const=30,
                    help="copy password to clipboard instead of printing it\nclear clipboard and return after TIMEOUT (default: 30 seconds)")
parser.add_argument('-s', '--store', metavar="STORE_DIR",
                    help="path to password store directory")
parser.add_argument('-l', '--length', type=int,
                    metavar="PASSWORD_LENGTH",
                    help="length of password to produce")
parser.add_argument('-e', '--encoding', metavar="ENCODING",
                    choices=AVAILABLE_ENCODINGS.keys(),
                    help="password encoding")
parser.add_argument('-v', '--verbose', action='store_true')
parser.add_argument('target', metavar="TARGET",
                    help="target to produce password to")


if __name__ == '__main__':
    args = parser.parse_args()
    VERBOSITY = args.verbose
    if VERBOSITY:
        printinfo("CLI options:", args)
    master = getpass.getpass(prompt="Master passphrase: ")
    if args.as_key:
        parse_result = {"key": args.target}
    else:
        parse_result = parse_site_file(args.target, store_dir=args.store)
    key = parse_result.get('key')
    length = args.length or int(parse_result.get('length'))
    encode_name = args.encoding or parse_result.get('encoding')
    encode = AVAILABLE_ENCODINGS.get(encode_name)
    if not encode:
        raise Exception("Could not find encoding for {}".format(encode_name))
    password = derive_pass(master, key, length=length, encode=encode)
    if not args.clip:
        print(password)
    else:
        clear = lambda: None
        # platform-dependent copy and clearing code
        if sys.platform == 'win32':
            raise NotImplementedError("Copy to and clear clipboard not implemented for Windows. Patches welcome")
        elif sys.platform == 'darwin':
            raise NotImplementedError("Copy to and clear clipboard not implemented for MacOSX. Patches welcome")
        else:
            clear = copy_nix(password)
        # clear clipboard after time
        try:
            time.sleep(args.clip or 30)
        finally:
            clear()


# Local Variables:
# coding: utf-8-unix
# python-shell-interpreter: "python3"
# End:
