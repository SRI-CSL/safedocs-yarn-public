#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import collections
import logging
from tracetools import parse_log, yarn_args
from tracetools.signatures import utils


def parse_args():
    parser = yarn_args.YarnArgParser("Print number of times functions"
                                     " are invoked",
                                     demangle=True, out=True,
                                     skip=True, ask_binja=True)
    parser.add_argument("-L", "--print-lib", action="store_true",
                        help="Also print library information for each function")
    parser.add_argument("-n", "--numerical-sort", action="store_true",
                        help="sort by count instead of alphabetical")
    parser.add_argument('-f', '--fn', action='append',
                        default=[],
                        help='name of function to count # of calls to')
    p = parser.parse_args()
    return p


def run(a):
    count_all = not bool(a.fn)
    demangled = {utils.Demangler.demangle(f): f for f in a.fn}
    fn_counts = collections.defaultdict(int) if count_all else \
        {f: 0 for f in demangled.keys()}
    include_libs = a.include_libs
    track_all_libs = not bool(include_libs)
    ml = parse_log.MemtraceLog(yarn_args=a, filters=["CallEntry"],
                               include_libs=a.include_libs,
                               track_all_libs=track_all_libs)
    out = ml.print_out
    binfo = ml.binfo
    msg = "counting all function calls" if count_all else \
        "counting calls to %s" % list(fn_counts.keys())
    logging.info(msg)

    # iterate through all CallEntries in log
    for entry in ml:
        # if is a call or indirect jump
        if entry.call_kind != entry.RET:
            target_addr = entry.target_addr
            target_seg = binfo.get_segment_at(target_addr)
            if not (track_all_libs or target_seg.is_tracked):
                # if calling a function in untracked library, continue
                continue
            # lookup function that starts at target address
            fn = binfo.addr_to_fn(target_addr, target_seg, exact=True)
            # if found and is a function symbol (as opposed to a PLT entry)
            if fn and fn.symbol.type == 0:
                # compare against demangled name
                name = utils.Demangler.demangle(fn.name)
                if name and (count_all or name in fn_counts):
                    fn_counts[name] += 1

    def sort_key(x):
        return x[1] if a.numerical_sort else x[0]

    for (f, count) in sorted(tuple(fn_counts.items()), key=sort_key):
        if a.print_lib:
            lib = "@{" + ",".join(set([l.basename for (_, l) in
                                      binfo.get_fn_info_from_name(f)])) + \
                                      "}"
        else:
            lib = ""

        print(f"{demangled.get(f, f)}{lib}: {count}", file=out)
    ml.close()


if __name__ == "__main__":
    a = parse_args()
    if False:
        import profile
        profile.run("run(a)")
        try:
            profile.run("run(a)")
        except KeyboardInterrupt:
            pass
    else:
        run(a)
