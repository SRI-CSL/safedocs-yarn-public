#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import sys
import os
from tracetools import yarn_args, results, results_data
import glob


def parse_args(args=None):
    parser = yarn_args.YarnArgParser("Manage results", require_results=False)
    parser.add_argument('-t', '--tag', action="store",
                        help="Create symlink/tag for results directory")
    parser.add_argument("-c", "--cleanup", action="store",
                        help="remove dead links and links to empty results")
    parser.add_argument("-r", "--remove", action="store_true")
    parser.add_argument("-i", "--iter-all", action="store")
    return parser.parse_args(args if args else sys.argv[1:])


def run(args=None):
    a = parse_args(args)
    if a.iter_all:
        parser_count = 0
        total_results = 0
        r = results.Results(a.iter_all)
        for p in r.iter_parsers():
            result_count = 0
            parser_count += 1
            for ri in p.results():
                result_count += 1
                total_results += 1
            print(p.orig_path, p.sha512sum,
                  "has", result_count,
                  "results")
        print("Total parser bins:", parser_count)
        print("Total # results:", total_results)

    if a.tag:
        a.results_obj.tag(a.tag)
    if a.remove:
        # also cleanup dead symbolic links
        a.cleanup = a.results_obj.r.results_root
        path = a.results_obj.result_dir
        os.system(f"rm -r {path}")

    if a.cleanup:
        def del_if_empty(path):
            if not glob.glob(os.path.join(path, "*")):
                os.system(f"rmdir {path}")
                print(f"Deleting emtpy dir {path}")
            elif not os.path.exists(os.path.join(path,
                                                 results_data.DataShelf.INFO())):
                print(f"No info dictionary exists for {path},",
                      "perhaps it is incomplete")

        for bpath in results_data.BinInfo.iter_paths(a.cleanup):
            for rpath in results_data.ResultData.iter_paths(bpath):
                del_if_empty(rpath)
            del_if_empty(bpath)
        [os.remove(f)
         for f in glob.glob(os.path.join(a.cleanup, "*"))
         if os.path.islink(f) and not os.path.exists(os.path.realpath(f))]


if __name__ == "__main__":
    run()
