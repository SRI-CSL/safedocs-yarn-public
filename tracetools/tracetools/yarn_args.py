# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import argparse
import results
import os
import json
import logging
from tracetools import global_config
import platform


class YarnArgException(Exception):
    pass


class YarnArgParser():
    def __init__(self, description='', demangle=False,
                 out=False, skip=False, multiprocess=False,
                 threads=False, require_results=True, include_libs=True,
                 ask_binja=False):
        # don't subclass argparse.ArgumentParser, it breaks things
        self._parser = argparse.ArgumentParser(description=description)
        if include_libs:
            self.add_argument('-l', '--include_libs', action='append',
                              default=[],
                              help='track events that happen in library as well')
        self.add_argument("--start-at", action="store", type=int, default=0,
                          help="Don't start processing until this many log "
                          "entries have been parsed")
        self.process_threads = threads
        self.require_results = require_results
        if threads:
            self.add_argument("--thread", action="append", type=int,
                              default=None, help="Thread ID of log to "
                              "analyze, otherwise analyzes all")
        if skip:
            self.add_argument('-s', '--skip', action="append", default=[],
                              help='names of functions to skip during '
                              'analysis')
        if out:
            self.add_argument('-o', '--output', action="store",
                              help="file to write output")
            self.add_argument('--save-as-result', action="store_true",
                              help="save output file inside result dir"
                              " named basename of --output, can only "
                              " be used when processing single result")
            self.add_argument('--overwrite-result', action="store_true",
                              help="If using --save-as-result, overwrite "
                              "existing result instead of failing")
        self.ask_binja = ask_binja
        self.pypy = platform.python_implementation() == "PyPy"
        if ask_binja and not self.pypy:
            self.add_argument("--no-binja", action="store_true",
                              help="Don't try to use binaryninja facilities")
        self.process_demangle = demangle
        if demangle:
            self.add_argument('-d', '--demangle', action='store_true',
                              help='demangle c++ names in output')
        self._multprocess = multiprocess
        if multiprocess:
            action = "append"
        else:
            action = "store"
        self.add_argument('--parse_results', '-R', nargs=1,
                          default=None, action=action,
                          help='path to results file, results id to parse.',
                          required=require_results)
        self.add_argument("-v", "--verbose", action="store_true",
                          help="Print debugging output")

    def add_argument(self, *args, **aargs):
        self._parser.add_argument(*args, **aargs)

    def parse_args(self, args=None, namespace=None):
        a = self._parser.parse_args(args, namespace)
        multi = self._multprocess
        level = logging.DEBUG if a.verbose else logging.INFO
        logging.getLogger().setLevel(level)
        res = getattr(a, "parse_results", [] if multi else None)
        if not hasattr(a, "include_libs"):
            a.include_libs = []
        if not multi:
            res = [res] if res else []
            multi = False
        results_objects = []
        if self.ask_binja and self.pypy:
            # force no binja if using pypy
            a.no_binja = True
        [setattr(a, attr, None)
         for attr in ["skip", "output", "save_as_result", "overwrite_result",
                      "thread", "no_binja"] if not hasattr(a, attr)]
        for r in res:
            if not os.path.exists(r[0]):
                if self.require_results:
                    raise YarnArgException(f"No results directory found at {r[0]}")
            else:
                try:
                    results_objects.append(results.ResultsInfo(r[0]))
                except json.decoder.JSONDecodeError as e:
                    if self.require_results:
                        raise e
                    results_objects = []
                    break
        if a.output and a.save_as_result:
            if len(results_objects) != 1:
                raise YarnArgException("Cannot use --save-as-result when not "
                                       "processing exactly one result")
            a.output = os.path.join(results_objects[0].result_dir,
                                    os.path.basename(a.output))
            logging.info(f"Writing output to {a.output}")
            if os.path.exists(a.output) and not a.overwrite_result:
                raise YarnArgException(f"File already exists at {a.output}. "
                                       "Use --overwrite-result if you wish to "
                                       "clobber it")
        if not multi:
            results_objects = results_objects[0] if results_objects else None
        a.results_obj = results_objects
        global_config.demangle = a.demangle if self.process_demangle else None
        # global_config.track_threads = a.thread if self.process_threads else \
        return a
