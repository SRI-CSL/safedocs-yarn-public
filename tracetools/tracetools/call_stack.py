# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import os
from tracetools import global_config as config


class CallStackException(Exception):
    pass


class CallStackEntry():
    _next_callsite_id = 0

    def calc_id(self, fn):
        if fn:
            return fn.symbol.full_name if config.demangle \
                and fn.symbol and fn.symbol.full_name else fn.name
        else:
            return "fn_%s_%x" % (self.locname, self.target_virtpc)

    def __init__(self, pc, target_pc, pc_seg, target_seg, sp, call_index,
                 binfo):
        self.binfo = binfo
        self.pc = pc
        self._virtpc = None
        self._target_virtpc = None
        self.pc_seg = pc_seg
        self._ret = None
        self.sp = sp
        self.target_pc = target_pc
        self.recursive_count = 0
        self.log_call_index = call_index
        self.target_seg = target_seg
        self.locname = os.path.basename(target_seg.path)
        self._fn_id = None
        self._fn = None
        self._callsite_id = self._next_callsite_id
        self.__class__._next_callsite_id += 1
        self.setjmp_info = None

    @property
    def callsite_id(self):
        return f"{self._callsite_id}:{self.recursive_count}"

    @property
    def target_virtpc(self):
        if self._target_virtpc is None:
            self._target_virtpc = self.binfo._abs_to_virt(self.target_pc,
                                                          self.target_seg)
        return self._target_virtpc

    @property
    def ret(self):
        # lazily calculate
        if self._ret is None:
            self._ret = self.binfo.next_ip(self.pc, self.pc_seg)
        return self._ret

    @property
    def virtpc(self):
        # lazily calculate
        if self._virtpc is None:
            self._virtpc = self.binfo._abs_to_virt(self.pc, self.pc_seg)
        return self._virtpc

    @property
    def fn_id(self):
        # lazily calculate because calculation (of self.fn) can be slow
        if self._fn_id is None:
            self._fn_id = self.calc_id(self.fn)
        return self._fn_id

    @property
    def fn(self):
        # lazily calculate because calculation can be slow
        if self._fn is None:
            self._fn = self.binfo.addr_to_fn(self.target_pc, self.target_seg)
        return self._fn

    def __repr__(self):
        rec = "" if not self.recursive_count else f"({self.recursive_count})"
        if self.fn:
            return self.fn_id + rec
        else:
            return "fn(%s:%x<%x)%s" % (self.locname,
                                       self.target_virtpc,
                                       self.ret, rec)

    def __eq__(self, o):
        attrs = ['pc', 'ret', 'recursive_count', 'locname']
        return all([getattr(self, a) ==
                    getattr(o, a) for a in attrs])


class CallStack():
    def __init__(self, binfo, log_enable_fns=None,
                 log_disable_fns=None, longjmp_fns=None):
        self.log_enable_fns = log_enable_fns if log_enable_fns else []
        self.log_disable_fns = log_disable_fns if log_disable_fns else []
        self.stack = []
        self.binfo = binfo
        self.index = 0
        self._last = None
        self.in_longjmp = False
        self.setlongjmp_addrs = self._lookup_longjmp("__sigsetjmp")
        self.longjmp_addrs = set()
        self.longjmp_pop = []
        if not longjmp_fns:
            longjmp_fns = []
        for f in ["siglongjmp"] + longjmp_fns:
            self.longjmp_addrs.update(self._lookup_longjmp("siglongjmp"))

    @property
    def setjmp_stack(self):
        return [s for s in self.stack if s.setjmp_info]

    def _lookup_longjmp(self, longjmp_fn):
        if not longjmp_fn:
            return []
        fns = []
        for b in (False, True):
            fns += [(f, seg) for (f, seg) in
                    self.binfo.get_fn_info_from_name(longjmp_fn, anytype=b)]
        return [self.binfo._virt_to_abs(f.start, seg) for (f, seg) in fns]

    @property
    def last_returned(self):
        return self._last

    def top(self):
        if self.stack:
            return self.stack[-1]
        else:
            return None

    def get_idx(self, idx):
        try:
            return self.stack[idx]
        except Exception:
            return None

    def size(self):
        return len(self.stack)

    def detail_string(self):
        return ">".join(["%s:%x:%s:(%s/%d)" %
                         (c.fn_id, c.virtpc, c.pc_seg.basename,
                          c.callsite_id, c.log_call_index)
                         for c in self])

    def _update(self, e):
        stack_len = len(self.stack)
        target_seg = self.binfo.get_segment_at(e.target_addr)
        if e.call_kind == e.RET:
            if stack_len == 0:
                return False
            idx = stack_len
            for i in range(0, stack_len)[::-1]:
                if self.stack[i].ret == e.target_addr:
                    if self.stack[i].recursive_count > 0:
                        # found return from recursive call
                        self.stack[i].recursive_count -= 1
                        # do not pop recursive call from stack
                        idx = i + 1
                        # recurse = True
                    else:
                        idx = i
                    break
            if idx < stack_len:
                self._last = self.stack[idx]
                # self.stack = self.stack[0:idx]
                del self.stack[idx:]
                return True
            else:  # didn't find anything to pop
                self._last = None
                # return True if we are returning to a tracked segment
                return False if target_seg is None else target_seg.is_tracked
        elif e.call_kind == e.INDIRECT_JMP:
            self.longjmp_pop = []
            if not self.in_longjmp or stack_len == 0:
                return False
            idx = stack_len
            # see if this indirect jump is "returning" us to a
            # corresponding setjmp
            for i in range(0, stack_len)[::-1]:
                entry = self.stack[i]
                setjmp_info = entry.setjmp_info
                # if stack pointer matches then we found longjmp destination
                if setjmp_info and setjmp_info.sp == e.sp:
                    idx = i + 1
                    entry.setjmp_info = None
                    break

            # pop all functions above longjmp destination from stack
            if idx < stack_len:
                self.in_longjmp = False  # leaving longjmp call
                self._last = self.stack[idx]
                if self._last.recursive_count > 0:
                    raise CallStackException("longjmp returns within recursive"
                                             " calls hasn't been tested yet "
                                             f"idx {idx+1} in {self.stack}")

                    self.last.recursive_count -= 1
                    idx += 1  # don't trim recursive function from stack
                self.longjmp_pop = self.stack[idx:]
                self.stack = self.stack[:idx]
                return True
            else:  # didn't find anything to pop
                self._last = None
                return False
        else:
            if not self.in_longjmp:
                self.in_longjmp = e.target_addr in self.longjmp_addrs
            # only track calls between binaries we are traking
            # unless we are jumping into a function where logging is enabled
            pc_seg = self.binfo.get_segment_at(e.pc)
            if stack_len == 0 and (e.target_addr in self.log_enable_fns):
                # this is an annoying corner case -- if dynamorio has
                # just enabled logging for this function and the
                # function was called indirectly, then the log entry
                # may have miscalculated the caller's address, so
                # check if current instruction is direct call, if not
                # then check if pc + 3 is call (direct call
                # instruction is 2 bytes longer than indirect) and use
                # that instead. It would be nicer if we could instead
                # fix this in the dynamorio client
                disasm = self.binfo.get_disassembly(e.pc, pc_seg)
                if disasm and not disasm.split()[0].startswith("call"):
                    e.pc += 3
                    again = self.binfo.get_disassembly(e.pc, pc_seg)
                    if not again.split()[0].startswith("call"):
                        raise CallStackException("cannot find call instruction"
                                                 f"g near %x/{pc_seg}" %
                                                 self.binfo.abs_to_virt(e.pc,
                                                                        pc_seg))
            if pc_seg is None or target_seg is None or \
               ((e.target_addr not in self.log_enable_fns) and
                (not (pc_seg.is_tracked and target_seg.is_tracked))):
                return False
            # don't add new entry for recursive calls
            if stack_len > 0:
                last = self.stack[-1]
                # if recursively called at same callsite
                if (last.target_pc == e.target_addr) and (last.pc == e.pc):
                    last.recursive_count += 1
                    return True
            c = CallStackEntry(e.pc, e.target_addr, pc_seg,
                               target_seg, e.sp, e.log_index,
                               self.binfo)
            if e.target_addr in self.setlongjmp_addrs and self.stack:
                self.stack[-1].setjmp_info = c
            self.stack.append(c)
            return True

    def __iter__(self):
        return iter(self.stack)

    # returns True if change was made to stack else False
    # also keeps track of callstack ("index" -- number of times it has changed)
    def update(self, e):
        changed = self._update(e)
        if changed:
            self.index += 1
        return changed

    def __repr__(self):
        return "| > " + " > ".join([str(f) for f in self.stack]) + "|"

    def org_mode_str(self):
        if self.stack:
            o = self.stack[-1]
            rec_count = sum([i.recursive_count for i in self.stack])
            return "*"*(len(self.stack)+rec_count) + " " + str(o)
        else:
            return ""

    def __eq__(self, o):
        sz = self.size()
        if sz == o.size():
            return all([self.stack[i] == o.stack[i] for i in range(sz)])
        else:
            return False
