# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import intervaltree


def int_repr(self):
    if self.end > 0xFFFFFFFF:
        ct = 16
    else:
        ct = 8
    fmt = "({0:%dX}, {1:%dX})" % (ct, ct)
    return fmt.format(self.begin, self.end)


intervaltree.Interval.__str__ = int_repr
intervaltree.Interval.__repr__ = int_repr

# export version of intervaltree that prints all values as hex
globals()['intervaltree'] = intervaltree
