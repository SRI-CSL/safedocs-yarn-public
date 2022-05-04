# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from log_entries import FileReadEntry, MmapEntry, FileOpEntry, MemEntry, \
    is_kind
import intervaltree as it # use this instead of quicksect for chop().
# from bx import intervals # doesn't do 64-bit
# from banyan import SortedSet, OverlappingIntervalUpdator
# import portion as P # this is much slower than intervaltree
# import interlap


class FileTrackers():
    def __init__(self, binfo):
        self.binfo = binfo
        self.mem = it.IntervalTree()
        self.open_files = {}  # file descritor -> FileMemTracker
        self._reset_lastop()

    def chop(self, start, end):
        return self.mem.chop(start, end)

    def add(self,  start, end, data):
        ret = self.overlap(start, end)
        if ret:  # if there is an exact match in the tree, replace the data
            r = ret.pop()
            if len(ret) == 1 and \
               r.begin == start and r.end == end:
                r.data = data
                return
            else:  # otherwise remove the overlppa
                self.chop(start, end)
        if start != end:
            self.mem.add(it.Interval(start, end, data))

    def find(self, i):
        # return self.mem.get(i)
        return self.mem.at(i)

    def overlap(self, start, end):
        # return self.mem.get(P.closedopen(start, end))
        return self.mem[start: end]

    def offset_at(self, addr, size=0):
        o = self.find(addr)
        if o:
            # if len(o) > 1:
            #     print(o)
            #     print([i.data for i in o])
            #     raise Exception
            o = o.pop()
            return o.data.offset + (addr - o.data.addr_start)
        else:
            return None

    def _reset_lastop(self):
        self._lastfd = None
        self._lastreadop = None
        self._lastmemop = None

    def update(self, e):
        if is_kind(e, FileReadEntry):
            addr_start = e.addr
            addr_end = addr_start + e.count
            # if there is any overlap, remove it now
            # self.chop(addr_start, addr_end)
            # if not self._lastreadop == e.READ:
            #     raise Exception
            f = FileMemTracker(self._lastfd, addr_start, e,
                               FileReadEntry)
            self.add(addr_start, addr_end, f)

            self._reset_lastop()
        elif is_kind(e, MmapEntry):
            addr_start = e.addr
            addr_end = addr_start + e.length
            # self.chop(addr_start, addr_end)
            # if self._lastop not in [e.MMAP, e.MUNMAP]:
            #     raise Exception
            if self._lastmemop == e.MMAP:
                f = FileMemTracker(self._lastfd, addr_start, e,
                                   MmapEntry)
                self.add(addr_start, addr_end, f)
            else:  # munmap
                self.chop(addr_start, addr_end)
            self._reset_lastop()
        elif is_kind(e, FileOpEntry):
            if e.op_kind == e.OPEN:
                # not really keeping track of open files properly
                # or doing anything with this information
                self.open_files[e.fd] = True
            elif e.op_kind == e.CLOSE:
                if e.fd in self.open_files:
                    del self.open_files[e.fd]
            else:  # [e.READ, e.MMAP, e.MUNMAP]
                self._lastfd = e.fd
                if e.op_kind == e.READ:
                    self._lastreadop = e.op_kind
                else:
                    self._lastmemop = e.op_kind
        elif is_kind(e, MemEntry):
            # only WRITE ops are passed here by parse_log.py
            # if byte overwritten in memory, then doesn't
            # count as file offset anymore
            self.chop(e.addr, e.addr + e.size)


class FileMemTracker():
    def __init__(self, fd, addr_start, entry, kind):
        self.fd = fd
        self.offset = entry.offset
        self.addr_start = addr_start
        self.count = entry.count
        self.kind = kind

    def file_offset_at(self, addr):
        if (self.addr_start <= addr) and (addr < self.addr_start + self.count):
            return (addr - self.addr_start) + self.offset

    def __repr__(self):
        return "F %d:@%x (%x+%x)" % (self.fd, self.addr_start, self.offset,
                                     self.count)
