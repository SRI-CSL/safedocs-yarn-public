#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import sys
import os
from tracetools import yarn_args
from tools.pt_tracker import PTTracker
from tracetools.signatures.pdf import PDFPT as PT
from tracetools.signatures.versions import VersionManager
import tkinter as tk
from tkinter import ttk
from typing import Dict, Callable
from aenum import IntEnum, auto
from tracetools.signatures.utils import Demangler

__version__ = "0.6"


class Events(IntEnum):
    REFRESH = auto()
    OBJ_SELECTED = auto()
    IDX_CLICKED = auto()


class ObjView():
    def __init__(self, root, parent,
                 callbacks: Dict[Events, Callable[..., None]]):
        self.root = root
        self.parent = parent
        self.callbacks = callbacks
        self._widget = ttk.Frame(parent)
        columns = ["Type", "Value", "ID"]
        self._tree = ttk.Treeview(self.widget, selectmode="browse",
                                  columns=columns)
        for i in range(len(columns)):
            self.tree.heading(f"#{i+1}", text=columns[i], anchor=tk.W)
            self.tree.column(f"#{i+1}", minwidth=1, stretch=tk.NO, anchor=tk.W)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.vsb = ttk.Scrollbar(self.widget, orient=tk.VERTICAL,
                                 command=self.tree.yview)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.configure(yscrollcommand=self.vsb.set)
        self.tree.bind('<<TreeviewSelect>>', self._item_selected)

    @property
    def tree(self):
        return self._tree

    @property
    def widget(self) -> ttk.Treeview:
        """Return tk widget."""
        return self._widget

    def _item_selected(self, event):
        if event.delta == 0:
            self.callbacks[Events.OBJ_SELECTED](self.current_obj())

    def add_item(self, parent_handle: str, name: str, index: int,
                 value: str = "", extra_info: Dict =
                 None) -> str:
        handle = self.tree.insert(parent_handle, "end",
                                  values=(name, value, index,),
                                  tags=tuple([]))
        return handle

    def view_obj(self, row):
        current = self.current_obj()
        if current != row:
            self.tree.selection_set(row)
            self.tree.focus(row)
            self.tree.see(row)

    def lookup_obj(self, row):
        return self.tree.item(row)

    def current_obj(self):
        return self.tree.selection()[0]


class InfoView():
    """ Panel on right that displays context for selected object
    """
    def __init__(self, root, parent,
                 callbacks: Dict[Events, Callable[..., None]]):
        self.root = root
        self.parent = parent
        self.callbacks = callbacks
        self._widget = ttk.Frame(parent)
        self.columns = ["Name", "Value"]
        self.tree = ttk.Treeview(self.widget, columns=self.columns)
        self.tree.column("#0", width=0, stretch=tk.NO)
        self.tree.heading("#0", anchor=tk.W)
        for i in range(len(self.columns)):
            last = i == (len(self.columns) - 1)
            self.tree.heading(f"#{i+1}", text=self.columns[i], anchor=tk.W)
            self.tree.column(f"#{i+1}", minwidth=1 if not last else 10000,
                             stretch=tk.NO if not last else tk.YES,
                             anchor=tk.W)
        self.hsb = ttk.Scrollbar(self.widget, orient=tk.HORIZONTAL,
                                 command=self.tree.xview)

        self.vsb = ttk.Scrollbar(self.widget, orient=tk.VERTICAL,
                                 command=self.tree.yview)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.configure(xscrollcommand=self.hsb.set,
                            yscrollcommand=self.vsb.set)
        self.tree.bind("<Double-Button-1>", self.on_doubleclick)

    @property
    def widget(self) -> ttk.Treeview:
        """Return tk widget."""
        return self._widget

    def update_view(self, node_idx, typ, val, new_data):
        self.tree.delete(*self.tree.get_children())
        summary = {"ID": node_idx, "Type": typ}
        if val != "":
            summary["Value"] = val
        self.add_info("Node Summary", summary)
        for (name, vals) in new_data.items():
            self.add_info(name, vals)

    def on_doubleclick(self, event):
        col = self.tree.identify_column(event.x)
        row = self.tree.identify_row(event.y)
        item = self.tree.item(row)
        key = item["values"][0]
        value = item["values"][1]
        if col == "#2" and key.endswith("_idx") and isinstance(value, int):
            self.callbacks[Events.IDX_CLICKED](value)

    def add_info(self, name, values):
        self.tree.insert("", "end", values=("", "",), tags=tuple())
        self.tree.insert("", "end", values=(f"~~{name}~~", "",), tags=tuple())
        for (k, v) in values.items():
            if name == "ParseReason" and k == "callstack":
                # make callstack easier to read
                # trim of extraneous info for each entry
                names = [entry.split(":", 1)[0] for entry in v.split(">")]
                # demangle names
                calls = Demangler.demangle_names(names)
                # trim off arguments
                calls = [call.split("(", 1)[0] for call in calls]
                # rebild callstack string
                v = " > ".join(calls)
            val = str(v)
            self.tree.insert("", "end", values=(k, val,), tags=tuple())


class View(tk.Tk):
    """ Main view widget
    """
    def __init__(self, title, callbacks: Dict[Events, Callable[..., None]],
                 *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.callbacks = callbacks
        self.resizable(width=True, height=True)
        self.geometry('1280x720')
        self.top_frame = tk.Frame()
        self.window = tk.PanedWindow(orient='horizontal')
        self.wm_title(title)
        self.tree_view = ObjView(self, self.window, self.callbacks)
        self.info_view = InfoView(self, self.window, self.callbacks)
        self.window.add(self.tree_view.widget, minsize=450)
        self.window.add(self.info_view.widget, minsize=10)
        self.window.pack(fill=tk.BOTH, expand=True)
        self.window.configure(sashrelief=tk.RAISED)
        for i in ["add_item", "view_obj", "lookup_obj", "current_obj"]:
            setattr(self, i, getattr(self.tree_view, i))


class PTViewer():
    def __init__(self, a):
        path = PTTracker.pt_results_file
        self.pt = a.results_obj.get_results_file_path(path) \
            if a.results_obj else a.parse_tree
        if not self.pt or not os.path.exists(self.pt):
            raise Exception(f"Cannot view tree, no file exists at {self.pt}")

        a.no_binja = True
        self.output = a.output
        hashes = []
        if a.parse_tree:
            info = PT.pt_json_info(a.parse_tree)
            hashes = info.get("bin_hashes", [])
            path = info.get("input_file", "")
        else:
            path = a.results_obj.result_info.orig_pdf_path
        path = os.path.basename(path)
        # use load_modules to force the correct set of context and
        # parse object classes to be loaded, but don't setup the
        # corresponding Signatures/Frames (setup_sigs=False),
        # otherwise it'll try to lookup addresses from the
        # binja-generated cache, which isn't necessary and may not
        # exist
        VersionManager.load_modules(a, hashes)
        if a.text_only:
            self.view = None
        else:
            self.view = View(title=f"PT Viewer: {path}",
                             callbacks={
                                 Events.OBJ_SELECTED: self.selectobj_callback,
                                 Events.IDX_CLICKED: self.idxclick_callback
                             })

            self.pt_nodes = {}
            self.idx_ids = {}
            self._populate_view()
            self.idx_view_prev = []
            self.view.bind("<Key>", self.key_pressed)

    def run(self):
        if self.view:
            self.view.mainloop()
        else:
            out = open(self.output, "w") if self.output else sys.stdout
            for pt in self._pts():
                pt.print(index=True, file=out)
            if out != sys.stdout:
                out.close()

    def append_prev(self, row):
        if (not self.idx_view_prev) or self.idx_view_prev[-1] != row:
            self.idx_view_prev.append(row)

    def selectobj_callback(self, row):
        self.append_prev(row)
        item = self.view.lookup_obj(row)
        item_idx = item["values"][-1]
        item_typ = item["values"][0]
        item_val = item["values"][1]

        if item_idx != "":
            node = self.pt_nodes.get(item_idx)
            cxts = node.context
            items = {
                self._tstr(cxt_name): cxt.to_dict()
                for (cxt_name, cxt) in cxts.cxts.items()
            } if cxts else {}
            if node and node.get_taint():
                items["File Taint"] = {"offset":
                                       node.encode_taint(node.get_taint())}
            self.view.info_view.update_view(item_idx, item_typ, item_val,
                                            items)

    def key_pressed(self, event):
        if event.char == "p":
            self.view_prev_obj()

    def view_prev_obj(self):
        current = self.view.current_obj()
        if self.idx_view_prev:
            prev = self.idx_view_prev.pop()
            if current == prev and self.idx_view_prev:
                prev = self.idx_view_prev.pop()
            if current != prev:
                self.view.view_obj(prev)

    def idxclick_callback(self, idx):
        row = self.idx_ids.get(idx)
        if row:
            self.append_prev(row)
            self.view.view_obj(row)

    @classmethod
    def _tstr(cls, enum):
        return str(enum).rsplit(".")[-1]

    def _populate_pt_view(self, root, parent="", prefix=""):
        tstr = self._tstr(root.type.name)
        if root.value is None and len(root.children) == 1:
            prefix = f"{prefix}{tstr}:"
        else:
            parent = self.view.add_item(parent, f"{prefix}{tstr}",
                                        root.index,
                                        "" if root.value is None
                                        else str(root.value))
            self.idx_ids[root.index] = parent
            self.pt_nodes[root.index] = root
            prefix = ""
        for c in root.children:
            self._populate_pt_view(c, parent, prefix)

    def _populate_view(self):
        for pt in self._pts():
            self._populate_pt_view(pt)

    def _pts(self):
        if not (self.pt and os.path.exists(self.pt)):
            return
        for a in PT.load_pts_from_json(self.pt):
            yield a


def parse_args(args=None):
    parser = yarn_args.YarnArgParser('view parse tree', demangle=True,
                                     require_results=False, out=True)
    parser.add_argument("-p", "--parse-tree", action="store",
                        help="Path to parse tree json file")
    parser.add_argument("-t", "--text-only", action="store_true",
                        help="Print tree to terminal, don't invoke GUI")
    return parser.parse_args(args if args else sys.argv[1:])


def run(args=None):
    ptv = PTViewer(parse_args(args))
    ptv.run()


if __name__ == "__main__":
    run()
