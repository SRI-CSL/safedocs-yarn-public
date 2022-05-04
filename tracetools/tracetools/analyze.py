# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import argparse


def parse_args():
    parser = argparse.ArgumentParser(description='mem trace log analysis tool')
    parser.add_argument('--infile', '-i',  type=argparse.FileType('rb', 0),
                        required=True)
    parser.add_argument('--decompress', '-x',  action='store_true',
                        help="bunzip2 input file")
    parser.add_argument('--callstack', '-c', action='store_true',
                        help='enable call stack tracking')
    p = parser.parse_args()
    if p.decompress:
        path = p.infile.name
        p.infile.close()
        p.infile = bz2.open(path, 'rb')
    return p




def run(args):
    pass

if __name__ == "__main__":
