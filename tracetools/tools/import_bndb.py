#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import os
import argparse
from tracetools import results


def parse_args():
    parser = argparse.ArgumentParser(description='import bndb file into results')
    parser.add_argument('-R', '--results_file', action='append', required=True,
                        help="path to results file of results to which you"
                        " want to import bndb. It will import bndb into all "
                        "bin_* folders")
    parser.add_argument('-b', '--bndb', action='append', nargs=2,
                        required=True, default=[],
                        help='binary basename and path to bnbd to import ')
    p = parser.parse_args()
    return p


if __name__ == "__main__":
    args = parse_args()
    for (name, path) in args.bndb:
        if not os.path.exists(path):
            raise Exception(f"no file at {path}")
        for f in args.results_file:
            if not os.path.exists(path):
                raise Exception(f"no results file at {path}")
            r = results.Results(os.path.dirname(f))
            parsers = r.get_all_results()
            for p in parsers.keys():
                r.init_from_parser_name(p)
                bins_dir = os.path.join(r.results_dir, r.parser_bins_dir)
                if not os.path.exists(os.path.join(bins_dir, name)):
                    print(f"no such binary '{name}' found in cached"
                          f" binary directory {bins_dir}")
                    continue
                which = None if name == os.path.basename(r.parser) else name
                r.save_bndb(path, which, True)
