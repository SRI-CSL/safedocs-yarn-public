#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.

from tracetools import parse_log, yarn_args, log_entries, global_config
import importlib.util


def parse_args():
    parser = yarn_args.YarnArgParser('Process mem trace log',
                                     demangle=True, out=True,
                                     skip=True, threads=True, ask_binja=True)
    parser.add_argument('-e', '--org-mode', action='store_true',
                        help='print emacs org-mode style')
    parser.add_argument('-L', '--print-log-state', action='store_true',
                        help='Also print out log enabling/disabling events')
    parser.add_argument('--index', action='store_true',
                        help='print callstack index')
    parser.add_argument('--log-index', action='store_true',
                        help='print log index')
    parser.add_argument("-j", "--longjmp", action="append", default=[])
    parser.add_argument('-r', '--raw', action='store_true',
                        help='print raw information about trace\'s'
                        ' calls and retuns')
    p = parser.parse_args()
    return p


class PrintCallstack():
    def __init__(self, a):
        self.org_mode_style = a.org_mode
        self.index = a.index
        self.log_index = a.log_index
        self._raw = a.raw
        thread_cb = self.on_next_thread if a.results_obj.num_threads > 1 \
            else None

        # automatically set no_binja=True if binaryninja module not available
        if not a.no_binja and importlib.util.find_spec("binaryninja") is None:
            a.no_binja = True

        self.ml = parse_log.MemtraceLog(yarn_args=a,
                                        track_callstack=self.print_callstack,
                                        track_thread_switch=thread_cb,
                                        longjmp_functions=a.longjmp)
        self.print_out = self.ml.print_out
        self._print_log_state = a.print_log_state
        self.last_line = None

    def on_next_thread(self, curr, last):
        print(f"switching to parse thread {curr}------",
              file=self.print_out)

    def print_callstack(self, o, parselog):
        if self._raw:
            return
        if self.org_mode_style:
            s = parselog.stack.org_mode_str()
        else:
            s = str(parselog.stack)
        s = s.strip()
        if self.index:
            s = f"{s} {parselog.stack.index}" if self.org_mode_style else \
                f"{parselog.stack.index}:{s}"
        if self.log_index:
            s = f"{s} {o.log_index}" if self.org_mode_style else \
                f"{o.log_index}:{s}"
        # if self.org_mode_style or self.last_line != s:
        print(s, file=self.print_out)

    def _fn_name(self, fn):
        if fn is None:
            return ""
        return fn.symbol.full_name if global_config.demangle and fn.symbol \
            and fn.symbol.full_name else fn.name


    def print_raw(self, entry):
        pc_seg = self.ml.binfo.get_segment_at(entry.pc)
        pc_virt = self.ml.binfo._abs_to_virt(entry.pc, pc_seg)
        pc_fn = self._fn_name(self.ml.binfo.addr_to_fn(entry.pc, pc_seg))
        target_seg = self.ml.binfo.get_segment_at(entry.target_addr)
        target_virt = self.ml.binfo._abs_to_virt(entry.target_addr,
                                                 target_seg)
        target_fn = self._fn_name(self.ml.binfo.addr_to_fn(entry.target_addr,
                                                           target_seg))
        s = "%d:" % entry.log_index if self.log_index else ""
        if entry.call_kind in [entry.RET, entry.INDIRECT_JMP]:
            ind = "*>?" if entry.call_kind == entry.INDIRECT_JMP else ""
            print(f"{s}{target_fn}@0x{target_virt:x}:{target_seg.basename}"
                  f" <{ind} {pc_fn}@0x{pc_virt:x}:{pc_seg.basename} "
                  f"({entry.retval:x})",
                  file=self.print_out)
        else:
            ind = "*" if entry.call_kind == entry.INDIRECT else ""
            top = self.ml.stack.top()
            cid = f"({top._callsite_id})" if top else ""
            print(f"{s}{pc_fn}@0x{pc_virt:x}:{pc_seg.basename}"
                  f" {cid}{ind}> "
                  f"{target_fn}@0x{target_virt:x}:{target_seg.basename}",
                  file=self.print_out)

    def run(self):
        print_log = self._print_log_state
        for i in self.ml:
            if print_log and (log_entries.is_kind(i, log_entries.LogOnEntry) or
                              log_entries.is_kind(i, log_entries.LogOffEntry)):
                print(f"{i.log_index}: {i}" if self.log_index else i,
                      file=self.print_out)
            if log_entries.is_kind(i, log_entries.CallEntry):
                if self._raw:
                    self.print_raw(i)

    def close(self):
        self.ml.close()


def run(a):
    p = PrintCallstack(a)
    p.run()
    p.close()


if __name__ == "__main__":
    a = parse_args()
    if False:
        import profile
        try:
            profile.run("run(a)")
        except KeyboardInterrupt:
            pass
    else:
        run(a)
