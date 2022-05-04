#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from tracetools import parse_log, yarn_args
import platform


class BNInfo():
    def __init__(self, bv, addr):
        self.addr = addr
        self.bv = bv
        self._tags = None

    @property
    def disasm(self):
        return self.bv.get_disassembly(self.addr)

    @property
    def tags(self):
        if self._tags is None:
            self._tags = []
            fns = self.bv.get_functions_containing(self.addr)
            fns = [] if fns is None else fns
            for f in fns:
                for (arch, addr, tag) in f.address_tags:
                    if addr == self.addr:
                        self._tags.append(tag)
        return self._tags

    def __repr__(self):
        return "0x%x: " % self.addr + \
            ",".join(["(%s-%s)" % (t.type.name, t.data)
                      for t in self.tags])


def run(args):
    # tags = ["array", "dict", "stream", "bool", "number",
    #         "int", "real", "indirect", "string", "hex",
    #         "literal", "header", "xref", "trailer", "comment", "name"]

    pl = parse_log.MemtraceLog(yarn_args=args,
                               filters=['MemEntry'])
    out = pl.print_out
    pl._enable_bin_info()
    for e in pl.iter_entries():
        seg = pl.binfo.get_segment_at(e.pc)
        if pl.binfo.has_binja(seg):
            tags = pl.binfo.get_binja_tags_at(e.pc, seg)
            if tags and (not (tags.empty() and args.ignore_empty)):
                print(tags, file=out)
                if args.verbose:
                    print(tags)
    pl.close()


def parse_args():
    parser = yarn_args.YarnArgParser('Match up memory accesses with bndb tags',
                                     out=True)
    parser.add_argument('--ignore_empty', action="store_true")
    p = parser.parse_args()
    p.no_binja = False
    return p


if __name__ == "__main__":
    if platform.python_implementation() == "PyPy":
        raise Exception("Binary ninja required to use this tool, which"
                        " isn't compatible with pypy")

    args = parse_args()
    if args.output is None:
        args.verbose = True
    run(args)
