#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import IPython
from tracetools import parse_log, yarn_args


def parse_args():
    parser = yarn_args.YarnArgParser('open yarn ipython console',
                                     multiprocess=True, skip=True)
    p = parser.parse_args()
    return p


class LogConsole():
    def __init__(self, res, memtrace_log):
        self.res = res
        self.memtrace_logs = memtrace_log
        print("self.memtrace_logs are now ready")
        IPython.embed()


def run(args):
    rs = []
    mls = []
    for i in range(len(a.results_obj)):
        r = a.results_obj[i]
        rs.append(r)
        mls.append(parse_log.MemtraceLog(yarn_args=args,
                                         yarn_args_result_idx=i))

    LogConsole(rs, mls)


if __name__ == "__main__":
    a = parse_args()
    run(a)
