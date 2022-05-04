# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import quicksect as it


class Heap():
    def __init__(self, binfo, track_libs=[]):
        self.binfo = binfo
        self.mallocs = it.IntervalTree()
        self.track_libs = track_libs

    def find(self, it):
        return [i for i in self.mallocs.find(it) if i.data]

    def overlap(self, start, end):
        return [i for i in self.mallocs[start: end] if i.data]

    def update(self, e):
        vmallocaddr = e.malloc_addr
        if e.kind_meta == e.MALLOC:
            i = it.Interval(vmallocaddr, vmallocaddr +
                            e.size, True)
            self.mallocs.insert(i)
            return [i]
        else:  # free
            # cannot delete from this interval tree impl, so just mark data as None instead
            overlap = self.find(it.Interval(vmallocaddr, vmallocaddr + 1))
            # if not overlap or (len(overlap) != 1):
            #     print("(%s) overlaps with 0 or more than 1 malloc or free doesn't align with any malloc address {overlaps: %s, free addr: %x}, double free?" % (
            #         str(e), str(overlap), vmallocaddr))
            old = []
            for o in overlap:
                # if o.data and o.start != vmallocaddr:
                #     print(o.data)
                #     print(type(o.data))
                #     print("freeing an address in the middle of an interval %s %x, not updating mallocs" % (
                #         str(overlap), vmallocaddr))
                # else:
                #     print("normal free")
                old.append(it.Interval(o.start, o.end, o.data))
                o.data = False
            return old
