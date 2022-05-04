# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
# regular enum doesnt work well with pypy3 so use aenum
from aenum import IntEnum
import sys
import json
import dataclasses
import typing
from tracetools.signatures.context import DataContext
from tracetools.signatures.parse_obj import ParseObj
from tracetools.signatures.utils import OOPS
from tracetools.signatures.versions import VersionManager

sys.setrecursionlimit(3500)


class PTException(Exception):
    pass


class PTEnum(IntEnum):
    pass


class EmptyPTEnum(IntEnum):
    _EMPTY = -1


@dataclasses.dataclass(repr=False)
class NodeInfo(DataContext):
    provisional: bool = False
    pseudo_node: bool = False
    spawned: bool = False
    orphans_idx: typing.List[int] = dataclasses.field(default_factory=list)
    done: bool = False

    def __repr__(self):
        # don't print orphan info
        contents = ", ".join(filter(lambda x: x,
                                    [self.field_repr(field)
                                     for field in dataclasses.fields(self) if
                                     field.name != "orphans_idx"]))
        return f"{self.__class__.__name__}({contents})" if contents else ""


class PT(ParseObj):
    type_enum = None
    childless_types = []
    from_json_idx = {}

    def __init__(self, typ, value=None, taint_tree=None,
                 first_taint=None, children=None,
                 context=None, **kwargs):
        if typ is None:
            OOPS(PTException, "type for new PT cannot be none")
        self._children = []
        super(PT, self).__init__(typ, value, taint_tree, first_taint, context)
        if self.get_context(NodeInfo) is None:
            self.add_context(NodeInfo(**kwargs))
        if children:
            for c in children:
                self.add_child(c)
        self.__children_idxs = []

    @property
    def children(self):
        return self._children

    @property
    def orphans(self):
        return [ParseObj.db_lookup(o)
                for o in self.get_context(NodeInfo).orphans_idx]

    def __eq__(self, o):
        # include taint offsets in equality calculation
        pt = self.print_taint
        pf = self.print_first_taint_only
        self.print_first_taint_only = o.print_first_taint_only = False
        self.print_taint = o.print_taint = True
        self.print_first_taint_only = False
        res = str(self) == str(o)
        self.print_taint = o.print_taint = pt
        self.print_first_taint_only = o.print_first_taint_only = pf
        return res

    def get_taint(self):
        self.taint_tree.merge_overlaps(strict=False)
        self.taint_tree.merge_equals()
        return self.taint_tree

    def __repr__(self, flattened=False, depth=0, no_context=False,
                 index=False, print_taint=False):
        typ = self._node_to_str(no_context, index, print_taint)
        if not self.children:
            return typ
        else:
            children = [f"{len(self.children_idxs())} kids"] \
                if (flattened and depth <= 0) \
                else [c.__repr__(flattened, depth - 1, True,
                                 index, print_taint)
                      for c in self.children]
            return typ + "[" + \
                ", ".join(filter(lambda x: x,
                                 [str(c)
                                  for c in children])) \
                + "]"

    def add_orphan(self, o):
        self.get_context(NodeInfo).orphans_idx.append(o.index)

    def add_child(self, o):
        if not issubclass(o.__class__, self.__class__):
            OOPS(PTException, "Adding an object that is not an PT sublcass",
                 f"as a child to pt: ({type(self)}){self},",
                 f"child: ({type(o)}){o}")
        # def in_tree(obj, tree):
        #     if id(tree) == id(obj):
        #         return True
        #     else:
        #         return any([in_tree(obj, c) for c in tree.children])
        # if in_tree(o, self) or in_tree(self, o):
        #     raise Exception(f"{o} already in tree {self} (or other way)")
        if self.type in self.childless_types:
            OOPS(PTException, f"Node type {type(self)},{self} shouldn't "
                 "have children")
        self.children.append(o)

    def reset_children(self, new_children):
        self._children = new_children

    def set_last_child(self, typ, value=None, taint=None, first_taint=None):
        if self.children:
            child = self.children[-1]
            child.type = typ
            if value is not None:
                child.value = value
            if taint is not None:
                child.taint_tree = taint
            if first_taint is not None:
                child.first_taint = first_taint

    def get_last_child(self):
        if self.children:
            return self.children[-1]

    @classmethod
    def count_type_in_PT(cls, typ, value, tree):
        if tree.type == typ:
            count = 1
        else:
            count = 0
        return count + sum([cls.count_type_in_PT(typ, value, c)
                            for c in tree.children])

    @classmethod
    def dump_pts_to_file(cls, pts, name, ri):
        path = ri.import_file(name, True, "")
        with open(path, "w") as f:
            f.write(json.dumps({"version": "0.8",
                                "top_level_pts": [a.index for a in pts],
                                "bin_hashes": VersionManager.calc_bin_hashes(ri),
                                "input_file": ri.result_info.orig_pdf_path
                                })
                    + "\n")
            for k in sorted(ParseObj.db.keys()):
                obj = ParseObj.db[k]
                json.dump(obj, f, cls=ParseObj.ParseObjEncoder)
                f.write("\n")
        return path

    @classmethod
    def pt_json_info(cls, path):
        with open(path, "r") as f:
            return json.loads(f.readline())

    @classmethod
    def load_pts_from_json(cls, path):
        with open(path, "r") as f:
            top_level = json.loads(f.readline())
            for line in f.readlines():
                cls.from_dict(json.loads(line))
            cls.resolve_json_children()
            return [cls.from_json_idx[idx]
                    for idx in top_level.get("top_level_pts", [])]

    @classmethod
    def from_dict(cls, j):
        def get_matches(name, c):
            ms = [sub for sub in c.__subclasses__()
                  if sub.__name__ == name]
            for sub in c.__subclasses__():
                ms += get_matches(name, sub)
            return ms

        cls_name = j.get("__class__", "PT")
        matches = get_matches(cls_name, ParseObj)
        obj_cls = matches[0] if len(matches) == 1 else None
        if obj_cls is None or not issubclass(obj_cls, cls):
            return None
        try:
            typ = obj_cls.type_enum(j["type"])
        except ValueError:
            typ = obj_cls.type_enum._EMPTY
        a = obj_cls(typ, j["value"],
                    taint_tree=PT.decode_taint(j["taint_tree"]),
                    first_taint=j["first_taint"])
        cxts = j.get("context", {})

        for (k, cxt_dict) in cxts.items():
            match = [c for c in DataContext.__subclasses__()
                     if c.__name__ == k]
            if len(match) == 1:
                match = match[0]
                cxt = match.from_dict(cxt_dict)
                if k == "NodeInfo":
                    # just clobber existing cxt
                    a.context.cxts[k] = cxt
                else:
                    a.add_context(cxt)
        idx = j.get("index", None)
        if idx is not None:
            a.index = idx
            cls.from_json_idx[idx] = a
            a.__children_idxs = j.get("children", [])
        else:
            # if don't have indices, then recurse in to children.
            # This should eventually be deleted
            a._children = [cls.from_dict(c) for c in j.get("children", [])]
            a._children = [c for c in a._children if c]
        return a

    @classmethod
    def resolve_json_children(cls):
        """ only to be called after from_dict is called across all pt objs """
        for k in sorted(cls.from_json_idx.keys()):
            o = cls.from_json_idx[k]
            o._children = [cls.from_json_idx[i] for i in o.__children_idxs]
            ParseObj.db[k] = o
            ParseObj.index = k + 1
