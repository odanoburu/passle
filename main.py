#!/bin/python3

import argparse
import base64
import getpass
import hashlib
import os


def derive_pass(master, key):
    n = 16384 # n — CPU/memory cost factor
    r = 32 # r — block size
    p = 1 # p — paralellization factor
    maxmem = 128 * r * (n + p + 2)
    dklen = 64
    result = hashlib.scrypt(master.encode('utf-8'),
                            salt=key.encode('utf-8'),
                            n=n, r=r, p=p, maxmem=maxmem,
                            dklen=dklen)
    return base64.b64encode(result).decode('utf-8')


def store_directory():
    # default, environment variable, etc.
    pass


def list_site_files(store_dir):
    site_files_dir = os.path.join(store_dir, "sites")
    for root, _, files in os.walk(site_files_dir, topdown=True):
        for f in files:
            yield (root, f)


def find_site_file(name, store_dir):
    for d, f in list_site_files(store_dir):
        if f == name:
            return os.path.join(d, f)
    raise Exception("Could not find site file for {}".format(name))


def parse_site_file(name, store_dir=None):
    store_dir = store_dir or store_directory()
    path = find_site_file(name, store_dir)
    with open(path, 'r') as f:
        key = f.readline().strip()
        if key:
            return {'key': key}
        else:
            raise Exception("Key for {} may not empty".format(name))


def directory(prospective_dir, writable=False):
    if os.path.isfile(prospective_dir):
        raise argparse.ArgumentTypeError("{0} is a file, not a directory".format(prospective_dir))
    elif not os.path.isdir(prospective_dir):
        raise argparse.ArgumentTypeError("{0} is not a directory".format(prospective_dir))
    else: # is directory, now check permissions
        if os.access(prospective_dir, os.R_OK) and not (writable and os.access(prospective_dir, os.W_OK)):
            return prospective_dir
        else:
            raise argparse.ArgumentTypeError("{0} does not have the necessary permissions".format(prospective_dir))



##
# CLI

parser = argparse.ArgumentParser(description="Create a password.")
parser.add_argument('-k', '--as-key', action='store_true',
                    help="treat TARGET as key, not as a site name")
parser.add_argument('-c', '--clip', action='store_true',
                    help="copy password to clipboard instead of printing it")
parser.add_argument('-s', '--store', type=directory,
                    metavar="STORE_DIR",
                    help="path to password store directory")
parser.add_argument('target', metavar="TARGET",
                    help="target to produce password to")


if __name__ == '__main__':
    args = parser.parse_args()
    print(args)
    master = getpass.getpass(prompt="Master passphrase: ")
    if args.as_key:
        key = args.target
    else:
        # FIXME: this should also get configuration
        key = parse_site_file(args.target, store_dir=args.store).get('key')
    password = derive_pass(master, key)
    if not args.clip:
        print(password)
    else:
        pass


# Local Variables:
# coding: utf-8-unix
# python-shell-interpreter: "python3"
# End:
