#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import os
import re
import sys
import argparse
import time
import shlex
import glob
import queue
import subprocess
import threading
from tracetools.results import Results
from tracetools.signatures.addr_calculator import AddrCache


class ProcessMonitor():
    def __init__(self, cmd, output_file):
        self.cmd = cmd
        self.output_file = open(output_file, "wb")
        self.queue = queue.Queue()
        self.proc = None
        self.thread = None
        self.runtime = None
        self.returncode = None

    def run(self, timeout_secs):
        self.proc = subprocess.Popen(shlex.split(self.cmd),
                                     stderr=subprocess.STDOUT,
                                     stdout=subprocess.PIPE)
        self.thread = threading.Thread(target=self.queue_output,
                                       args=(self.proc.stdout, self.queue))
        self.thread.daemon = True
        self.thread.start()
        ret = None
        timeout = False
        t0 = time.time()
        done_time = t0 + timeout_secs
        try:
            while ret is None and not timeout:
                ret = self.proc.poll()
                if timeout_secs > 0 and time.time() > done_time:
                    timeout = True
                    self.force_kill()
                self.save_output()
        except KeyboardInterrupt:
            ret = None
            self.force_kill()
        except Exception as e:
            print("Unexpected exception:", e, file=sys.stderr)
            ret = None
            self.force_kill()
        self.output_file.close()
        t1 = time.time()
        self.runtime = t1 - t0
        self.returncode = ret

    def queue_output(self, output, q):
        for line in iter(output.readline, b""):
            q.put(line)
        output.close()

    def save_output(self):
        try:
            line = self.queue.get_nowait()
        except queue.Empty:
            line = None
        if line:
            sys.stdout.write(line.decode('utf-8', errors='ignore'))
            self.output_file.write(line)

    def force_kill(self):
        self.save_output()
        if not self.proc.returncode:
            self.proc.kill()


class TraceRunner():
    RIO_ROOT = "/opt/dynamorio"
    BUILD_DIR = "/build"
    RESULTS_DIR = "/results"
    ALLOC = True
    TIME = False
    VERBOSE = False
    TRACE_SOCKET = False
    TRACE_FILE = True
    CALL = True
    BB = False
    NO_RUN = False
    COMPRESS = False
    PARSER = None
    PARSER_ARGS = '{in_file}'
    ERROR_OFFSET = None
    ENABLE = None
    DISABLE = None
    MEMORY = True
    DELETE = []
    COPY = []
    TIMEOUT = 0
    PRINT_RESULTS_PATH = False
    PRUNED_LOG = False
    TRACK_WRITES = True
    RIO_PLUGIN_NAME = "memcalltrace"

    def __init__(self, rio_root=RIO_ROOT, build_dir=BUILD_DIR,
                 results_dir=RESULTS_DIR, alloc=ALLOC, memory=MEMORY,
                 time=TIME, trace_socket=TRACE_SOCKET,
                 trace_file=TRACE_FILE, call=CALL, verbose=VERBOSE,
                 bb=BB, no_run=NO_RUN, compress=COMPRESS,
                 parser=PARSER, parser_args=PARSER_ARGS,
                 error_offset=ERROR_OFFSET, enable=ENABLE,
                 disable=DISABLE, delete=DELETE, timeout=TIMEOUT,
                 print_results_path=PRINT_RESULTS_PATH,
                 pruned_log=PRUNED_LOG, track_writes=TRACK_WRITES,
                 parser_root_dir=None, inputs=[], copy=COPY,
                 *args, **kwargs):
        self.inputs = inputs
        self.rio_root = rio_root
        self.build_dir = build_dir
        self.results_dir = results_dir
        self.alloc = "a" if alloc else ""
        self.memory = "m" if memory else ""
        self.time = time
        # self.fileop = "f" if fileop else ""
        self.socket = "s" if trace_socket else ""
        self.trace_file = trace_file
        self.call = "c" if call else ""
        self.verbose = "v" if verbose else ""
        self.bb = "i" if bb else ""
        self.pruned_log = "p" if pruned_log else ""
        self.track_writes = "w" if track_writes else ""
        self.no_run = no_run
        self.compress = compress
        self.parser = parser
        self.parser_root_dir = os.path.dirname(self.parser) \
            if parser_root_dir is None else parser_root_dir
        self.parser_args = parser_args
        self.error_offset_val = error_offset
        self.error_offset = 'o' if error_offset else ''
        self.enable_fns = enable if enable is not None else "main"
        self.disable_fns = disable
        self.delete = delete
        self.copy = copy
        self.timeout = timeout
        self.print_results_path = print_results_path
        self.drrun = os.path.join(self.rio_root, "bin64", "drrun")
        self.custom_environ = {}

        if self.error_offset_val:
            self.set_environ(Results.ERROR_OFFSET_ENVIRON,
                             self.error_offset_val)

        # split and rejoin while making sure there are no duplicates
        self.enable_fns = ",".join(list(set(self.enable_fns.split(","))))
        self.enable = "e"
        if self.enable_fns:
            self.set_environ(Results.ENABLE_FN_ENVIRON, self.enable_fns)
        # else:
        #     self.enable = "E"
        if self.disable_fns:
            self.disable = "D"
            # split and rejoin while making sure there are no duplicates
            self.disable_fns = ",".join(list(set(self.disable_fns.split(","))))
            self.set_environ(Results.DISABLE_FN_ENVIRON, self.disable_fns)
        else:
            self.disable = ""
        lib_path = os.environ.get("LD_LIBRARY_PATH", "")

        if self.parser:
            self.viewer = self.parser
            lib_path = self.parser_root_dir if not lib_path \
                else f"{self.parser_root_dir}:{lib_path}"
            self.set_environ("LD_LIBRARY_PATH", lib_path)
        else:
            build = "/opt/poppler0840_build"
            b = f"{build}:{lib_path}" if lib_path else build
            self.set_environ("LD_LIBRARY_PATH", b)
            self.viewer = os.path.join(build, "utils", "pdftotext")

        if not os.path.exists(self.results_dir):
            os.mkdir(self.results_dir)

        self.results_log = Results(self.results_dir)
        self.results_log.init_parser(self.viewer)
        if pruned_log and not os.environ.get(Results.PRUNE_LIST_ENVIRON):
            caches = [(lib, AddrCache.load_cache(self.results_log, lib))
                      for lib in
                      glob.glob(f"{self.results_log.parser_bins_dir}/*")
                      if AddrCache.has_cache(self.results_log, lib)]
            if not caches:
                raise Exception("Cannot create pruned trace no addr cache found")
            libs = []
            all_addrs = []
            libc_name = None
            libcname = re.compile("^libc[-0-9.]*\.so[0-9.]*$")
            for (lib, addr_dict) in caches:
                addrs = set()
                for (k, v) in addr_dict.items():
                    addrs.update(v)
                if not addrs:
                    continue
                addrs = list(addrs)
                addrs.sort()
                num_addrs = len(addrs)
                basename = os.path.basename(lib)
                libs += [basename, f"{num_addrs}"]
                all_addrs += addrs
                if libcname.match(basename):
                    libc_name = basename
            self.set_environ(Results.PRUNE_LIST_LIBS_ENVIRON,
                             ",".join(libs))
            self.set_environ(Results.PRUNE_LIST_ENVIRON,
                             ",".join([f"0x{a:x}" for a in all_addrs]))
            self.set_environ(Results.PRUNE_LIBC_ENVIRON, libc_name)

    @classmethod
    def from_args(cls, args):
        return TraceRunner(**vars(args))

    def set_environ(self, k, v):
        for d in [self.custom_environ, os.environ]:
            d[k] = v

    def merge_environ(self, environ):
        for (k, v) in environ.items():
            self.set_environ(k, v)

    def setup_input(self, in_file: str):
        if in_file and self.trace_file:
            self.set_environ(Results.DOC_PATH_ENVIRON, in_file)

    def environ_str(self):
        return " ".join(f"{k}='{v}'" for (k, v) in self.custom_environ.items())

    def format_command(self, in_file):
        file_arg = "I" if in_file and self.trace_file else ""
        test_args = self.parser_args.format(in_file=in_file)
        test_cmd = "%s %s" % (self.viewer, test_args)

        cmd = f"{self.drrun} -c " \
            f"{self.build_dir}/lib{self.RIO_PLUGIN_NAME}.so " \
            f"-dA{self.memory}{self.alloc}{self.call}{self.socket}" \
            f"{self.verbose}{self.bb}{self.error_offset}{file_arg}{self.enable}" \
            f"{self.disable}{self.pruned_log}{self.track_writes} -- {test_cmd}"
        return cmd

    def run(self):
        for i in self.inputs:
            self.run_input(i)

    def run_input(self, i, tag=None):
        self.setup_input(i)
        res_dir = self.results_log.gen_result_dir()
        self.set_environ("NOMAD_META_MR_MT_LOG_DIR", res_dir)
        cmd = self.format_command(i)
        if self.no_run:
            print(" ".join(f"{k}='{v}'"
                           for (k, v) in self.custom_environ.items()) +
                  " " + cmd)
            return 0
        print("LD_LIBRARY_PATH: " + os.environ.get("LD_LIBRARY_PATH",
                                                   "(not set)"))
        print(cmd)

        m = ProcessMonitor(cmd, os.path.join(res_dir, "subprocess.out"))
        m.run(self.timeout)
        res_info = self.results_log.update_from_run(res_dir, i, cmd,
                                                    m.runtime, self.compress,
                                                    m.returncode,
                                                    self.custom_environ,
                                                    self.copy)
        for d in self.delete:
            self.del_file(d)

        if self.time:
            print("%s took %f secs to process" % (i, (m.runtime)))
        if self.print_results_path:
            print(f"Results saved to {res_info.result_dir}")
        if tag:
            ok = res_info.tag(tag)
            if ok:
                print(f"Results tagged as {tag}")
        return m.returncode

    def del_file(self, f):
        if os.path.isfile(f):
            os.remove(f)


def run(args):
    tr = TraceRunner.from_args(args)
    for i in args.inputs:
        tr.setup_input(i)
        tr.run_input(i)
    # tr.run()


if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description='test dynamorio-based memtrace tool '
        '(must be run on docker instance), results stored '
        'in /build/*.log. See memtrace-tools repo for '
        'information on parsing/processing these files')
    p.add_argument('-v', '--verbose', action='store_const',
                   const=not TraceRunner.VERBOSE,
                   default=TraceRunner.VERBOSE)
    p.add_argument('-s', '--trace-socket', action='store_const',
                   const=not TraceRunner.TRACE_SOCKET,
                   default=TraceRunner.TRACE_SOCKET,
                   help='trace socket reads')
    p.add_argument('-F', '--no-trace-file', action='store_const',
                   const=not TraceRunner.TRACE_FILE,
                   default=TraceRunner.TRACE_FILE,
                   help="don't trace input file activity")
    p.add_argument('-M', '--memory', action='store_const',
                   const=not TraceRunner.MEMORY,
                   default=TraceRunner.MEMORY,
                   help='dont trace memory access operations')
    p.add_argument('-C', '--call', action='store_const',
                   const=not TraceRunner.CALL,
                   default=TraceRunner.CALL,
                   help='dont trace calls/returns')
    p.add_argument('-A', '--alloc', action='store_const',
                   const=not TraceRunner.ALLOC,
                   default=TraceRunner.ALLOC,
                   help='dont trace alloc/free operations')
    p.add_argument('-b', '--bb', action='store_const',
                   const=not TraceRunner.BB,
                   default=TraceRunner.BB,
                   help='trace basic blocks')
    p.add_argument('-n', '--no-run', action="store_const",
                   const=not TraceRunner.NO_RUN,
                   default=TraceRunner.NO_RUN,
                   help="don't run, just print out env vars "
                   "and tool command")
    p.add_argument('-z', '--compress', action='store_const',
                   const=not TraceRunner.COMPRESS,
                   default=TraceRunner.COMPRESS,
                   help='compress results/logs')
    p.add_argument('-t', '--time', action='store_true',
                   help='print how long analysis took for each input')
    p.add_argument('--parser', action='store', required=True,
                   help='path to parser binary to instrument', default=None)
    p.add_argument('--parser-args', default=TraceRunner.PARSER_ARGS,
                   help='arguments to pass to parser binary using "{in_file}" '
                   'to represent path of file that is being parsed.')
    p.add_argument('-r', '--results-dir', default=TraceRunner.RESULTS_DIR,
                   help='root directory where all results will be saved')
    p.add_argument('-B', '--build-dir', default=TraceRunner.BUILD_DIR,
                   help='directory where built dynamorio tool '
                   '(libmemcalltrace.so) lives')
    p.add_argument('--rio-root', default=TraceRunner.RIO_ROOT,
                   help='directory dynamorio install lives')
    p.add_argument('-o', '--error_offset', default=TraceRunner.ERROR_OFFSET,
                   action='store',
                   help='offset to error in file')
    p.add_argument('-e', '--enable',
                   action='store',
                   help='Name of function that whose call enables logging'
                   'and returns disables logging separated by commas.'
                   ' Default is "main"')
    # p.add_argument("-E", "--log-all", action="store_true", help="always log")
    p.add_argument('-D', '--disable',
                   action='store',
                   help='Name of function that whose call disables logging'
                   'and returns enables logging, separated by commas')
    p.add_argument('-d', '--delete', default=[], action="append",
                   help='files to delete after test run')
    p.add_argument('-c', '--copy', default=[], action="append",
                   help='files to copy after test run')
    p.add_argument('--timeout', default=TraceRunner.TIMEOUT,
                   action="store", type=float,
                   help="Number of minutes to allow instrumented parser to run "
                   "before killing process and giving us. No limit by default "
                   "(0 mins).")
    p.add_argument("-R", "--print-results-path", action="store_true")
    p.add_argument("-p", "--pruned-log", action="store_const",
                   const="p", default="",
                   help="Enabled pruned log, NOMAD_META_MR_MT_PRUNE_LIST, "
                   "NOMAD_META_MR_MT_PRUNE_LIST_LIBS, and "
                   "NOMAD_META_MR_MT_LIBC_NAME must be set")
    p.add_argument("inputs", nargs="+", type=str,
                   help='pdf(s) to process')

    a = p.parse_args()
    if a.parser is None:
        a.parser_args = "{in_file} out.txt"
        a.delete = ["out.txt"]
    if a.timeout:
        a.timeout = a.timeout * 60
    else:
        delattr(a, "timeout")
    # if a.log_all:
    #     a.enable = ""
    # elif not a.enable:
    #     a.enable = "main"
    a.enable = a.enable if a.enable else "main"
    run(a)
