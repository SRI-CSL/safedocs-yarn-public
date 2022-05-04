#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.

import sys
import platform
from tracetools import yarn_args
from tracetools.signatures.versions import VersionManager
# import tracetools.signatures.versions.VersionManager as VersionManager
from tracetools.results import Results, ResultsInfo
import os
# import importlib


def parse_args(args=None):
    parser = yarn_args.YarnArgParser("Generate bin/library metadata caches",
                                     require_results=False)
    parser.add_argument('-d', '--debug-addr-name', action="append",
                        default=[])
    parser.add_argument("-f", "--force", action="store_true",
                        help="Force overwriting of cache if "
                        "--get-bin-metadata")
    # parser.add_argument("-D", "--dir", action="store")
    return parser.parse_args(args if args else sys.argv[1:])


def run(args=None):
    if platform.python_implementation() == "PyPy":
        raise Exception("Binary ninja required to use this feature, which"
                        " isn't compatible with pypy")
    a = parse_args(args)
    # check if binaryninja is available and functional
    import binaryninja
    # this will raise an exception if there isn't a valid license
    binaryninja._init_plugins()
    if not a.results_obj:
        if not a.parse_results:
            raise Exception("Do not know which addr cache to generate")
        root_dir = a.parse_results.pop()
        if not os.path.exists(os.path.join(root_dir, "data")):
            results_obj = ResultsInfo(root_dir)
        else:
            bindir = os.path.realpath(root_dir)
            r = Results(os.path.dirname(bindir))
            r.init(bindir, True)
            results_obj = r.any_result()
    else:
        results_obj = a.results_obj
    VersionManager.do_gen_bin_metadata(results_obj, a.force,
                                       a.debug_addr_name)


if __name__ == "__main__":
    if False:
        import cProfile
        cProfile.run("run()")
    else:
        run()
