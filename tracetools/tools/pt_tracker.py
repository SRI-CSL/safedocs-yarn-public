#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from tracetools import yarn_args
from tracetools.signatures.pdf import PDFEnum as PTEnum
from tracetools.signatures.pdf import PDFPT as PT
from tracetools.signatures import utils
from tracetools.signatures.versions import VersionManager
from tracetools.signatures.context import ParseReason
import sys
import logging

__version__ = "0.6"


def parse_args(desc='Process mem trace log', additional_args=[], args=None):
    parser = yarn_args.YarnArgParser(desc, demangle=True, out=True)
    parser.add_argument('--print-offset', action="store_true",
                        help="also print information on nested "
                        " reads of input file offsets")
    parser.add_argument('-s', '--save-results', action="store_true",
                        help='save derived PT and dict malform '
                        'information to results'
                        'directory for later analysis')
    parser.add_argument('-u', '--unique-objects-only', action="store_true",
                        help="Skip tracking of objects that have been "
                        "tracked previously")
    parser.add_argument('-c', '--continue-on-error', action="store_true",
                        help="Continue when recoverable error occurs instead "
                        "of quitting")
    parser.add_argument("-a", "--show-all", action="store_true",
                        help="If printing PT, print all derived objects "
                        "including those parsed from deflated stream")
    parser.add_argument("-S", "--show-stack", action="store_true",
                        help="print callstack for each PT")
    parser.add_argument("-F", "--show-fixups", action="store_true")
    parser.add_argument("-j", "--load-from-json", action="store_true")
    parser.add_argument("-i", "--print-image-ops", action="store_true")

    for a in additional_args:
        parser.add_argument()
    p = parser.parse_args(args if args else sys.argv[1:])

    utils.raise_exception = not p.continue_on_error
    return p


class PTTracker():
    pt_results_file = "derived-pt.json"

    def __init__(self, a):
        if a.output:
            self.output = open(a.output, 'w')
        else:
            self.output = None

        self.ri = a.results_obj
        self.show_all = a.show_all
        self.show_fixups = a.show_fixups
        self.show_stack = a.show_stack
        a.no_binja = True
        self.tracker = VersionManager.create_tracker(a,
                                                     a.unique_objects_only,
                                                     print_image_ops=a.print_image_ops,
                                                     output_stream=self.output
                                                     if self.output
                                                     else sys.stdout,
                                                     print_offset=a.print_offset)

    def save_results(self):
        # create empty file but remember path
        r = PT.dump_pts_to_file(self.tracker.pts, self.pt_results_file,
                                self.ri)
        logging.info(f"dumped pt to {r}")

    def close(self, save=False):
        self.tracker.close(save)
        if self.output:
            self.output.close()

    def load_pts(self):
        f = self.ri.get_results_file_path(self.pt_results_file)
        out = self.output if self.output else sys.stdout
        for a in PT.load_pts_from_json(f):
            a.print(index=True, file=out)

    def print_pts(self):
        out = self.output if self.output else sys.stdout
        for c in self.tracker.pt_info:
            if self.show_all or \
               c.pt.type in [PTEnum.INDIRECT_OBJ,
                             PTEnum.XREF_OBJ] \
                or (self.show_fixups and c.pt.type ==
                    PTEnum.RECONSTRUCTED_XREF_TABLE):
                if self.show_stack:
                    reason = c.pt.get_context(ParseReason)
                    print(reason.callstack
                          if reason and reason.callstack else
                          c.stack_str,
                          c.pt, file=out)
                else:
                    print(c, file=out)
                print("------", file=out)

    def run(self):
        self.tracker.run()


def run(a):
    p = PTTracker(a)
    if a.load_from_json:
        p.load_pts()
        p.close()
        return
    p.run()

    if a.save_results:
        p.save_results()
        if a.show_all:
            p.print_pts()
    else:
        print("----------------- extracted pts ----------------------")
        p.print_pts()
    p.close(a.save_results)


if __name__ == "__main__":
    args = parse_args()
    if False:
        import cProfile
        cProfile.run("run(args)")
    else:
        run(args)
    sys.exit(0)
