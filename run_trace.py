#!/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import argparse
import dataclasses
import os
import sys
import subprocess
import shlex
from typing import Dict
from tracetools.results import Results
import test_trace
import logging
from tracetools.defn_manager import BinArgs, DefnLoader


@dataclasses.dataclass
class ScriptExec():
    root_dir: str
    __path: str
    timeout: int
    environ: Dict[str, str]
    binargs: BinArgs
    args: str = ""
    setup_script: str = ""

    def __post_init__(self):
        if not self.binargs:
            self.binargs = BinArgs("")
        self.args = self.binargs.parser_args
        self.setup_script = self.binargs.setup_script
        self._path = None

    @classmethod
    def create(cls, defn_mgr, parser, version, bin_name, timeout):
        pdef = defn_mgr.defs[parser]
        version_info = pdef.versions[version]
        if version_info.get_bin_path_info(bin_name) is None:
            raise Exception("We do not have binary/execution information on "
                            f"binary '{bin_name}' for parser '{parser}'")

        timeout = pdef.get_timeout(version, bin_name) \
            if timeout is None else timeout
        environ = pdef.get_environ(version, bin_name, "{in_file}")
        args = pdef.get_bin_args(bin_name)
        path = version_info.get_bin_path_info(bin_name).path
        return cls(version_info.root_dir, path, timeout, environ,
                   args)

    @property
    def path(self):
        if self._path is None:
            self._path = self.__path if self.__path.startswith("/") else \
                os.path.join(self.root_dir, self.__path)
        return self._path

    def _format(self, s, in_file):
        return s.format(**{"root_dir": self.root_dir,
                           "in_file": in_file})

    def get_environ(self, input_path="{in_file}"):
        return {k: self._format(val, input_path)
                for (k, val) in self.environ.items()}

    def get_args(self, input_path="{in_file}"):
        return self._format(self.args, input_path)

    def get_cmd(self, input_path="{in_file}"):
        args = self.get_args(input_path)
        return f"{self.path} {args}"


class DefnManager():
    def __init__(self, path: str, rio_root: str, build_dir: str,
                 results_dir: str):
        self.build_dir = build_dir
        self.rio_root = rio_root
        self.results_dir = results_dir
        self.defn_loader = DefnLoader(path)

    def run_version(self, parser: str, parser_version: str,
                    parser_bin: str, input_path: str,
                    do_exec: bool = True,
                    track_all: bool = False, enable_fns=None,
                    timeout=None, compress=False, pruned_log=False,
                    tag=None):
        if not os.path.exists(input_path):
            logging.error(f"Input file not found at '{input_path}', skipping")
            return
        if parser is None:
            parser = self.default_parser()
        pdef = self.defn_loader.defs[parser]
        if parser_version is None:
            parser_version = pdef.default_version()
        if parser_bin is None:
            parser_bin = pdef.get_version(parser_version).default_bin()
        pexec = ScriptExec.create(self.defn_loader, parser, parser_version,
                                  parser_bin, timeout)
        setup_process = None
        if pexec.setup_script:
            sexec = ScriptExec.create(self.defn_loader, parser, parser_version,
                                      pexec.setup_script, None)
            cmd = sexec.get_cmd(input_path)
            setup_environ = sexec.get_environ(input_path)
            if do_exec:
                setup_process = subprocess.Popen(shlex.split(cmd),
                                                 env=setup_environ)
                if not sexec.binargs.background:
                    setup_process.wait(timeout=sexec.timeout)
            else:
                print(" ".join([f"{k}='{v}'"
                                for (k, v) in
                                setup_environ.items()]),
                      cmd)
                print()

        if enable_fns:
            current = pexec.environ.get(Results.ENABLE_FN_ENVIRON, "")
            pexec.environ[Results.ENABLE_FN_ENVIRON] = current + "," + \
                ",".join(enable_fns)
        enable_fn_list = None
        disable_fn_list = None

        for (k, v) in dict(pexec.environ).items():
            if k in [Results.ENABLE_FN_ENVIRON, Results.DISABLE_FN_ENVIRON]:
                if track_all:
                    del pexec.environ[k]
                    continue
                elif k == Results.ENABLE_FN_ENVIRON:
                    enable_fn_list = v
                else:
                    disable_fn_list = v
            else:
                os.environ[k] = v
        tr = test_trace.TraceRunner(parser=pexec.path,
                                    rio_root=self.rio_root,
                                    build_dir=self.build_dir,
                                    parser_args=pexec.get_args(),
                                    timeout=pexec.timeout*60,
                                    results_dir=self.results_dir,
                                    delete=pexec.binargs.delete,
                                    compress=compress,
                                    enable=enable_fn_list,
                                    disable=disable_fn_list,
                                    no_run=not do_exec, bb=True,
                                    call=True, alloc=True,
                                    trace_socket=pexec.binargs.trace_socket,
                                    trace_file=pexec.binargs.trace_file,
                                    print_results_path=True,
                                    inputs=[input_path],
                                    pruned_log=pruned_log,
                                    track_writes=True,
                                    copy=pexec.binargs.copy,
                                    parser_root_dir=pexec.root_dir)
        tr.merge_environ(pexec.environ)
        if not do_exec:
            tr.setup_input(input_path)
            print(tr.environ_str(), tr.format_command(input_path))
        else:
            tr.run_input(input_path, tag)
        if setup_process and not setup_process.returncode:
            setup_process.kill()

    def print_supported_parsers(self, input_type=None):
        self.defn_loader.print_supported_parsers(input_type)


def run(args):
    p = argparse.ArgumentParser()
    p.add_argument("-p", "--parser", action="store", default="poppler")
    p.add_argument("-V", "--parser-version", action="store")
    p.add_argument("-b", "--parser-bin", action="store")
    p.add_argument("-z", "--compress", action="store_true")
    p.add_argument("-T", "--timeout", action="store", type=float, default=None,
                   help="Override default timeout with this value, in minutes")
    p.add_argument("-n", "--dont-exec", action="store_true",
                   help="Don't exectute any of the commands, print them "
                   "out instead.")
    p.add_argument("-r", "--results-dir", action="store", default="/results",
                   help="Path to root results directory to store results")
    p.add_argument("-a", "--track-all", action="store_true",
                   help="Track everything, don't set ENABLE_LOG/DISABLE_LOG")
    p.add_argument("-e", "--enable", action="append", default=[],
                   help="Name of function to add to list of enabled functions")
    p.add_argument("-d", "--defn-dir", action="store",
                   default=os.path.join(os.path.dirname(__file__),
                                        "parser-settings"))
    p.add_argument('--rio-root', default="/opt/dynamorio",
                   help='directory dynamorio install lives')
    p.add_argument('-B', '--build-dir', default="/build",
                   help='directory where built dynamorio tool '
                   '(libmemcalltrace.so) lives')
    p.add_argument('-P', "--pruned-log", action="store_true",
                   help="Generate pruned version of log (experimental)")
    p.add_argument("-t", "--tag", action="store", default=None,
                   help="tag generated results with name")
    p.add_argument("--list",
                   help="List names of supported parser familes and binaries",
                   action="store_true")
    p.add_argument("input", nargs="*", type=str)

    a = p.parse_args(args[1:])
    if not a.list and not a.input:
        logging.error("Must supply at least one input file to process")
        sys.exit(-1)

    d = DefnManager(a.defn_dir, a.rio_root, a.build_dir, a.results_dir)
    if a.list:
        d.print_supported_parsers()
    else:
        if a.tag and len(a.input) > 1:
            logging.warning("--tag specified but nore than one input "
                            "supplied, tag will only be applied to first")
        for i in a.input:
            d.run_version(a.parser, a.parser_version, a.parser_bin, i,
                          not a.dont_exec, a.track_all,
                          a.enable, a.timeout, a.compress, a.pruned_log,
                          a.tag)
            a.tag = None


if __name__ == "__main__":
    run(sys.argv)
