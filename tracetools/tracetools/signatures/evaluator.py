# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from typing import List
from tracetools.signatures.signatures import SigRegistrar, SigID, Signature
from collections import OrderedDict
from tracetools.signatures.ghoststack import StackOverlayEntry
from tracetools.signatures.utils import SigEvalException, OOPS
from tracetools.signatures.versions import Version
from tracetools.signatures.context import ParseReason

import sys


class SigEval():
    """Performs signature evaluation on memtrace log based on current list
    of installed signatures.  Allows for dynamic insertion and removal
    of signatures as well as ghoststack-specific signatures that are
    tied to a specific frame of an overlay ghoststack.

    """
    dynamic_classes = []

    def __init__(self, parse_log, setup_sigs=True, **kwargs):
        self.ml = parse_log
        self.ri = parse_log.ri
        self.sig_registrars = {}
        self.signatures = SigRegistrar()
        self.ghoststack = []
        self.pop_callbacks = OrderedDict()
        self.push_callbacks = OrderedDict()
        self.exiting = False
        if setup_sigs:
            self.signatures.setup_sig_classes(self, self.ml)
            StackOverlayEntry.setup_frame_classes(self, self.ml,
                                                  self.signatures,
                                                  dynamic_classes=self.dynamic_classes)

    def sig_from_id(self, sig_id: SigID, *args, **kwargs):
        return self.signatures.create_sig(sig_id, *args, **kwargs)

    def run(self):
        print("running", file=sys.stderr)
        for i in self.ml:
            self.signatures.do_log_entry(i)
        if self.ghoststack:
            print("ghost stack not empty, popping remaining entries",
                  file=sys.stderr)
            self.exiting = True
            for e in self.ghoststack:
                try:
                    e.return_sig.do_flag(i)
                except Exception as ex:
                    print("Caught exception while popping ghostframe",
                          f"{e}:", ex, file=sys.stderr)

    def add_sig(self, sig, group=None, enable=True):
        return self.signatures.add_sig(sig, group, enable)

    def add_sig_group(self, sigs: List[Signature], enable=True):
        return self.signatures.add_sig_group(sigs, enable)

    def remove_sig(self, sig, callback=None):
        return self.signatures.remove_sig(sig, callback)

    def remove_sig_group(self, group, callback=None):
        return self.signatures.remove_sig_group(group, callback)

    def ghoststack_overlay(self, cls=None):
        return [c for c in self.ghoststack
                if cls is None or isinstance(c, cls)]

    def stack_top(self, cls=None):
        stack = self.ghoststack_overlay(cls)
        return stack[-1] if stack else None

    def stack_bottom(self, cls=None):
        stack = self.ghoststack_overlay(cls)
        return stack[0] if stack else None

    def ghoststack_depth(self, cls=None):
        return len(self.ghoststack_overlay(cls))

    def push_stack(self, new_top):
        if new_top is None:
            OOPS(SigEvalException("When pushing stack, new_top should not be",
                                  "None\n", self.debug_string()))
        old_top = self.stack_top()
        self.ghoststack.append(new_top)
        if old_top:
            old_top.on_push_from_top(new_top)
        new_top.on_push(old_top)
        for c in self.push_callbacks.keys():
            c(new_top, old_top, self)

    def pop_stack(self, pop_top=None):
        pop_top = pop_top if pop_top else self.ghoststack.stack_top()
        try:
            idx = self.ghoststack.index(pop_top)
        except ValueError:
            OOPS(SigEvalException, f"Stack does not contain {pop_top}: "
                 f"{self.ghoststack}", "\n", self.debug_string())
        num_pop = len(self.ghoststack) - idx
        old_top = None
        for _ in range(num_pop):
            old_top = self.ghoststack.pop()
            new_top = self.stack_top()
            old_top.on_pop(new_top)
            if new_top:
                new_top.on_pop_to_top(old_top)
            for c in self.pop_callbacks.keys():
                c(old_top, new_top, self)
        return old_top

    def add_pop_callback(self, callback):
        self.pop_callbacks[callback] = 0

    def add_push_callback(self, callback):
        self.push_callbacks[callback] = 0

    def rm_pop_callback(self, callback):
        try:
            self.pop_callbacks.pop(callback)
        except KeyError:
            pass

    def rm_push_callback(self, callback):
        try:
            self.push_callbacks.pop(callback)
        except KeyError:
            pass

    def flag(self, sig_id, why=None):
        self.signatures.flag_floating_sig(sig_id, why=why)

    def floating_sig(self, sig_id):
        return self.signatures.floating_sigs.get(sig_id, None)

    def callstack_summary(self, idx=None):
        stack_len = len(self.ml.stack.stack)
        idx = (stack_len - 1) \
            if idx is None or idx < 0 or idx >= stack_len else idx
        stack = [e.pc for e in self.ml.stack.stack[:idx+1]]
        if stack:
            stack.append(self.ml.stack.stack[idx].target_pc)
        return stack

    @property
    def floating_sigs(self):
        return self.signatures.floating_sigs.values()

    def remove_sig_from_group(self, sig: Signature, group):
        return self.signatures.remove_sig_from_group(sig, group)

    def add_sig_flag_callback(self, sig_id: SigID, callback):
        self.signatures.add_sig_flag_callback(sig_id, callback)

    def debug_string(self):
        return f"At log index: {self.ml.log_count}, " + \
            f"current stack: {self.ml.stack.detail_string()}" + \
            "\ncurrent ghoststack: " + \
            str([(c, c.callstackentry.callsite_id, c.flagged_log_index)
                 for c in self.ghoststack]) + "\n" + \
                     f"result info: {self.ml.ri.result_info}\n"

    def close(self, save=False):
        for m in self.floating_sigs:
            m.on_exit(save)
        if self.ml:
            self.ml.close()

    # for debugging
    def callback_MEM_READ(self, signature):
        print("read %x [%s] %s (%x)" % (signature.virtpc,
                                        signature.seg.basename,
                                        signature.value,
                                        signature.flagged_entry.addr))

    def callback_CALL_TRACE(self, signature):
        print(self.ml.stack.detail_string())

    def callback_FN_CALL_TRACE(self, signature):
        top = self.ml.stack.top()
        if top:
            print(f"{top.virtpc:x}:{top.pc_seg.basename} > {top}")

    def callback_FN_BB_TRACE(self, signature):
        seg = Version.bin_info.get_segment_at(signature.flagged_entry.pc)
        virtpc = Version.bin_info._abs_to_virt(signature.flagged_entry.pc, seg)
        print(f"BB({signature.callsite_id}): 0x%x:%s" %
              (virtpc, seg.basename))

    def callback_FN_MEM_TRACE(self, signature):
        seg = Version.bin_info.get_segment_at(signature.flagged_entry.pc)
        virtpc = Version.bin_info._abs_to_virt(signature.flagged_entry.pc, seg)
        print(f"MEM({signature.callsite_id}): 0x%x:%s" %
              (virtpc, seg.basename),
              signature.flagged_entry)

    @classmethod
    def setup(cls):
        pass


class PTInfo():
    def __init__(self, pt, stack=None):
        self.pt = pt
        self.stack = stack if stack is not None else []
        self._stack_len = None
        self._stack_segs = {}
        self._stack_fns = {}

    @property
    def stack_len(self):
        if self._stack_len is None:
            self._stack_len = len(self.stack)
        return self._stack_len

    def segment_at(self, idx):
        if idx >= self.stack_len or idx < 0:
            return None
        seg = self._stack_segs.get(idx, None)
        if seg is None:
            seg = Version.bin_info.get_segment_at(self.stack[idx])
            self._stack_segs[idx] = seg
        return seg

    def virt_pc_at(self, idx, seg=None):
        if seg is None:
            seg = self.segment_at(idx)
        if seg:
            return Version.bin_info._abs_to_virt(self.stack[idx], seg)
        else:
            return 0

    def fn_at(self, idx, seg=None):
        fn = self._stack_fns.get(idx, None)
        if not fn:
            if seg is None:
                seg = self.segment_at(idx)
            if seg is None:
                fn = None
            else:
                fn = Version.bin_info.addr_to_fn(self.stack[idx], seg)
            self._stack_fns[idx] = fn
        return fn

    def __repr__(self):
        seg = self.segment_at(self.stack_len - 1)
        if not seg:
            return ""
        pc = self.virt_pc_at(self.stack_len - 1, seg)
        return f"[{pc:x}:{seg.basename}]:{self.pt}"

    @property
    def stack_str(self):
        return "[" + ">".join(
            [f"{self.virt_pc_at(i):x}:{self.fn_at(i)}:" +
             f"{self.segment_at(i).basename}:"
             for i in range(self.stack_len)]
        ) + f"]:{self.pt}"


class SigPTEval(SigEval):
    def __init__(self, parse_log, unique_objs_only=False,
                 print_offset: bool = False,
                 **kwargs):
        super(SigPTEval, self).__init__(parse_log, **kwargs)
        self._PTs = []
        self.unique_objs_only = unique_objs_only
        self.unique_objs = {}
        self.print_offset = print_offset
        # store in OrderedDict to remember order items were inserted and
        # ensure uniqueness

    @property
    def pts(self):
        for a in self._PTs:
            yield a.pt

    @property
    def pt_info(self):
        for a in self._PTs:
            yield a

    def register_pt(self, pt, stack_info=None):
        if pt and self.print_offset:
            pt.__class__.print_taint = True
            self.print_offset = None
        cxt = pt.get_context(ParseReason)
        if not cxt:
            cxt = ParseReason.create(self, manager=True)
            pt.add_context(cxt)
        if not cxt.registered:
            self._PTs.append(PTInfo(pt, stack_info))
            cxt.registered = True

    def cache_id(self, begin, stack=None):
        stack = self.callstack_summary() if stack is None else stack
        return f"{begin}--" + ":".join(["%x" % pc for pc in stack])

    def cache_pt(self, pt, cache_id=None, first_taint=None):
        if cache_id is None:
            first_taint = first_taint if first_taint else pt.first_taint
        stackid = self.cache_id(first_taint) if cache_id is None else cache_id
        self.unique_objs[stackid] = pt

    def lookup_cached_pt(self, begin=None, cache_id=None):
        stackid = self.cache_id(begin) if cache_id is None else cache_id
        return self.unique_objs.get(stackid)

    def has_cached_pt(self, begin=None, cache_id=None) -> bool:
        return self.lookup_cached_pt(begin, cache_id) is not None
