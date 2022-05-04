# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
# makes a cache of binja tags
import bisect


class BinjaTagEntry():
    def __init__(self, addr, tags):
        self.addr = addr
        self.tags = tags

    def empty(self):
        return False if self.tags else True

    def __repr__(self):
        return "0x%x: " % self.addr + \
            ",".join(["(%s-%s)" % (t.type.name, t.data)
                      for t in self.tags])

    def __lt__(self, x):
        return self.addr < x.addr


class BinjaTagCache():
    def __init__(self, bv):
        addr_map = {}
        for fn in bv.functions:
            for (arch, addr, tag) in fn.address_tags:
                tags = addr_map.get(addr, [])
                tags.append(tag)
                addr_map[addr] = tags
        self._tags = [BinjaTagEntry(addr, tags)
                      for (addr, tags) in addr_map.items()]
        self._tags.sort(key=lambda x: x.addr)
        self._len = len(self._tags)

    def tags_by_addr(self, addr):
        'Locate the leftmost value exactly equal to x'
        i = bisect.bisect_left(self._tags, BinjaTagEntry(addr, []))
        if self._len > 0 and \
           (i == 0 and self._tags[0].addr > addr) or (i >= self._len) \
           or (not self._tags[i].addr == addr):
            # not in list
            return BinjaTagEntry(addr, [])
        return self._tags[i]
