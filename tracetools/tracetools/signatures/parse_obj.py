# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import intervaltree as it
from collections import OrderedDict
import json
import sys


class ContextContainer():
    def __init__(self, cxts=None):
        self.cxts = {}
        if cxts:
            [self.add_context(c.__class__.__name__) for c in cxts]

    def add_context(self, context):
        match = self.get_context(context.__class__.__name__)
        if match:   # merge context
            match.merge(context)
        else:
            self.cxts[context.__class__.__name__] = context

    def get_context(self, cls=None, default=None):
        if cls is not None:
            cls = cls if isinstance(cls, str) else cls.__name__
        return self.cxts.get(cls, default) if cls else list(self.cxts.values())


class ParseObj():
    """Base class for all parsed objets (token, pt). Not meant to be
    directly instantiated

    """
    print_taint = False
    print_first_taint_only = False
    index = 0
    type_enum = None
    db = OrderedDict()

    def __init__(self, typ, value=None, taint_tree=None, first_taint=None,
                 context=None):
        if typ is not None and self.type_enum is not None and \
           not isinstance(typ, self.type_enum):
            raise Exception("type of object 'typ' not valid "
                            f"Node {type(self)} expects type {self.type_enum} "
                            f"but got {type(typ)} ({typ})")
        self.type = typ
        self.value = value
        self.taint_tree = taint_tree if taint_tree else it.IntervalTree()
        self.first_taint = first_taint
        self.index = ParseObj.index
        ParseObj.index += 1
        self.context = context if context else ContextContainer()
        ParseObj.db_insert(self)
        # self.dump_db(ParseObj.index - 2, ParseObj.index)

    def add_context(self, context):
        self.context.add_context(context)

    def get_context(self, cls=None, default=None):
        return self.context.get_context(cls, default)

    def add_taint(self, taint_tree, first_taint=None):
        self.taint_tree |= taint_tree
        if first_taint is not None:
            self.first_taint = first_taint

    def merge_taint(self, obj):
        self.add_taint(obj.taint_tree, obj.first_taint)

    @classmethod
    def encode_taint(cls, its):
        return [(i.begin, i.end) for i in its]

    @classmethod
    def decode_taint(cls, its):
        return it.IntervalTree([it.Interval(begin, end) for
                                (begin, end) in its])

    @property
    def children(self):
        return []

    def children_idxs(self):
        return [c.index for c in self.children]

    def min_taint(self):
        t = self.get_taint()
        if t:
            return sorted(t)[0].begin
        else:
            return None

    def max_taint(self):
        t = self.get_taint()
        if t:
            return sorted(t)[-1].end
        else:
            return None

    def get_taint(self):
        self.taint_tree.merge_overlaps(strict=False)
        self.taint_tree.merge_equals()
        return self.taint_tree

    def _context_str(self):
        cxt = ",".join(filter(lambda x: x,
                              [str(c)
                               for c in self.get_context()]))
        return f"({cxt})" if cxt else ""

    def _type_str(self):
        return self.type.name

    def _offset_str(self, print_taint=False):
        if not ((print_taint or self.print_taint) and self.get_taint()):
            return ""
        out = self.first_taint \
            if print_taint or self.print_first_taint_only else \
            str(self.get_taint())
        return f"<{out}>"

    def _value_str(self):
        return "" if self.value is None else f"={self.value}"

    def _node_to_str(self, no_context=False, index=False, print_taint=False):
        offset_str = self._offset_str(print_taint)
        cxt_str = "" if no_context else self._context_str()
        out = self._type_str() + self._value_str() + offset_str + cxt_str
        idx = f"{self.index}:" if index else ""
        out = f"{idx}{out}" if (self.value is None) and \
            (not (offset_str and cxt_str)) \
            else "{%s%s}" % (idx, out)
        return out

    def __repr__(self, flattened=False, depth=0, no_context=False, index=False,
                 print_taint=False):
        return self._node_to_str(no_context, index, print_taint)

    def print(self, flattened=False, depth=0, no_context=False,
              index=False, print_taint=False, file=sys.stdout):
        s = self.__repr__(flattened, depth, no_context, index, print_taint)
        try:
            print(s, file=file)
        except UnicodeEncodeError:
            print(s.encode('utf-8', errors='replace'),
                  file=file)

    @classmethod
    def to_dict(cls, obj):
        pass

    @classmethod
    def db_insert(cls, node):
        if cls.db is not None:
            cls.db[node.index] = node

    @classmethod
    def db_lookup(cls, idx):
        return cls.db.get(idx, None) if cls.db else None

    @classmethod
    def dump_db(cls, start_idx=0, end_idx=None):
        if not cls.db:
            return
        for (k, v) in cls.db.items():
            if (k >= start_idx) and (end_idx is None or (k < end_idx)):
                print(k, v.__class__.__name__, ":",
                      v.__repr__(flattened=True,
                                 depth=v.__class__.print_depth))

    class ParseObjEncoder(json.JSONEncoder):
        def de(self, s):
            return s.decode(errors="replace") if isinstance(s, bytes) else s

        def default(self, o):
            d = {"type": int(o.type),
                 "value": self.de(o.value),
                 "children": [],
                 "context": {c.__class__.__name__: c.to_dict()
                             for c in o.get_context()},
                 "index": o.index,
                 "first_taint": o.first_taint,
                 "__class__": o.__class__.__name__,
                 "taint_tree": o.encode_taint(o.get_taint()),
                 }
            if o.children:
                d["children"] = o.children_idxs()
            return d
