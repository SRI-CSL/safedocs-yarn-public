#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import os
from tracetools import yarn_args


def parse_args():
    parser = yarn_args.YarnArgParser(description='import file trace to'
                                     'result directory')
    parser.add_argument('-f', '--file', action='append',
                        required=True, default=[],
                        help='path of file to import')
    p = parser.parse_args()
    return p


if __name__ == "__main__":
    args = parse_args()
    for path in args.file:
        if not os.path.exists(path):
            raise Exception(f"no file at {path}")
    res_info = args.results_obj
    for f in args.file:
        res_info.import_file(f)
