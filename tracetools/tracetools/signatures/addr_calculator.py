# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import elftools.elf.elffile as elf
import bisect
import os
import json
from typing import List, Dict, Union, Tuple
import functools
import logging
from tracetools.signatures.addr_info_const import AddrKind as Kind
from tracetools.signatures.addr_info_const import AddrField as Field
from tracetools.signatures.addr_info_const import AddrSubtype as Subtype
from tracetools.signatures.addr_info_const import AddrInstype as Instype
from tracetools.results import Results
from tracetools.signatures.utils import Demangler


try:
    # only import this if absolutely necessary incase binja isn't
    # installed
    from tracetools.bin_info import BinaryInfo
    import binaryninja as bn
except Exception:
    bn = None

__version__ = "0.6"


class AddrCacheException(Exception):
    pass


@functools.total_ordering
class LineInfo():
    def __init__(self, path: str, lineno: str, addr: int = None,
                 fn_names: List[str] = [], command: int = None):
        self.path = path
        self.lineno = lineno
        self.addr = addr
        self.fn_names = fn_names
        self.command = command

    def __repr__(self):
        addr = f"0x{self.addr:x}" if self.addr is not None else ""
        return f"{self.path}:{self.lineno} ({addr})[{self.fn_names}]"

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, o):
        if self.addr is None or o.addr is None:
            addr_matches = True
        else:
            addr_matches = self.addr == o.addr
        return self.path == o.path and self.lineno == o.lineno and addr_matches

    def __lt__(self, o):
        if self.addr is None or o.addr is None:
            addr_lt = False
        else:
            addr_lt = self.addr < o.addr
        return (self.path < o.path) or \
            ((self.path == o.path) and (self.lineno < o.lineno)) or \
            ((self.path == o.path) and (self.lineno == o.lineno) and addr_lt)


class DwarfInfo():

    def __init__(self, binary, bv, files):
        self.binary = binary
        self.bv = bv
        self.files = files
        self._line_info = None
        self._len_lines = None
        self._line_addrs = None

    @property
    def len_lines(self) -> int:
        if self._len_lines is None:
            self._len_lines = len(self.lines)
        return self._len_lines

    @property
    def lines(self) -> List[LineInfo]:
        if self._line_info is None:
            self._parse_dwarf()
        return self._line_info

    @classmethod
    def fn_name(cls, fn, demangled: bool = False) -> str:
        # binja add a "_0" to function name if underlying address
        # refererence's function's PLT entry and not function
        # directory. Strip this if present also strip _imp_ if present
        end = "_0"
        name = fn.name if not fn.name.endswith(end) else fn.name[:-1*len(end)]
        start = "__imp__"
        res = name if not name.startswith(start) else name[len(start)-1:]
        return Demangler.demangle(res) if demangled else res

    def _fns(self, addr: int):
        return [self.fn_name(f) for f in self.bv.get_functions_containing(addr)]

    def find_matches(self, path: str, lineno: int) -> List[LineInfo]:
        test_line = LineInfo(path, lineno)
        lidx = bisect.bisect_left(self.lines, test_line)
        if lidx < self.len_lines:  # otherwise bigger than everything
            entry = self.lines[lidx]
            if entry == test_line:  # match found
                ridx = bisect.bisect_right(self.lines, test_line)
                return self.lines[lidx:ridx]
        return []

    def get_line_min_max_addrs(self, path: str, lineno: int) -> List[Tuple[LineInfo, LineInfo]]:
        addrs = self.find_matches(path, lineno)
        # filter out duplicates, then sort
        addrs = list(set(addrs))
        addrs.sort()
        max_addrs = []
        for a in addrs:
            ks = list(self._line_addrs.keys())
            ks.sort()
            lks = len(ks)
            idx = bisect.bisect_right(ks,
                                      a.addr)
            if idx >= lks:
                entry = None
            else:
                entry = self._line_addrs[ks[idx]]
                while entry and (entry.path == a.path) and \
                      (entry.lineno == a.lineno):
                    idx += 1
                    entry = self._line_addrs[ks[idx]] if idx < lks else None
            if entry is None:  # then find end of basic block @ a.addr
                end = max([b.end for b in self.bv.get_basic_blocks_at(a.addr)])
                entry = LineInfo(a.path, a.lineno + 1, end, a.fn_names)
            max_addrs.append((a, entry))
        return max_addrs

    def _parse_dwarf(self):
        li = set()
        if not self.files:
            self._line_info = []
            return
        logging.debug(f"Parsing DWARF of {self.binary}")
        all_files = set()
        with open(self.binary, "rb") as f:
            elf_binary = elf.ELFFile(f)
            dwarf = elf_binary.get_dwarf_info()
            for cu in dwarf.iter_CUs():
                lp = dwarf.line_program_for_CU(cu)
                files = lp['file_entry']
                directories = ["."] + [str(d, 'utf8')
                                       for d in lp['include_directory']]
                for lpe in lp.get_entries():
                    if lpe.state:
                        lfile = files[lpe.state.file-1]
                        name = str(lfile['name'], 'utf8')
                        path = os.path.join(directories[lfile['dir_index']],
                                            name)
                        all_files.add(path)
                        addr = lpe.state.address
                        if path in self.files:
                            li.add(
                                LineInfo(path, lpe.state.line, addr,
                                         self._fns(addr), lpe.command)
                            )
        logging.debug(f"found dwarf sources: {all_files}")
        self._line_info = list(li)
        self._line_info.sort()
        self._line_addrs = {i.addr: i
                            for i in sorted(list(li),
                                            key=lambda x: x.addr)}


class AddrCache():
    SUFFIX = ".addrs.json"
    VERSION_KEY = "version"
    ADDR_KEY = "addrs"

    def __init__(self, results_info, libname, libsummary):
        self.ri = results_info
        self.libname = libname
        self.libsummary = libsummary
        self._libpath = None
        self._binja_view = None
        self._metadata_path = None
        self._bndb_path = None
        self.dwarf_info = None

    @property
    def metadata_path(self):
        if self._metadata_path is None:
            self._metadata_path = self.ri.get_bin_metadata_path(self.libname,
                                                                self.SUFFIX)
        return self._metadata_path

    @property
    def bndb_path(self):
        if self._bndb_path is None:
            self._bndb_path = self.ri.get_bin_metadata_path(self.libname)
        return self._bndb_path

    @property
    def binja_view(self):
        global bn
        if self._binja_view is None and bn is not None:
            self._binja_view = BinaryInfo.open_or_create_bndb(self.lib_path,
                                                              self.bndb_path)
        return self._binja_view

    @property
    def lib_path(self):
        if self._libpath is None:
            self._libpath = self.ri.get_lib_path(self.libname)
        return self._libpath

    def _iter_llil_instructions(self, search_addrs, fn, addrinfo,
                                debug, *kargs):
        addrs = set()
        for (start, end) in search_addrs:
            start_next = start
            while start_next < end:  # in case range extends past end of func
                func = None
                for func in self.binja_view.get_functions_containing(start_next):
                    # if we iterate through the instructions
                    # (func.llil.instructions) sometimes the last few
                    # are minising from the iterator, so we force
                    # iteration over each istruction using
                    # get_low_level_il_at
                    if not (start_next < min(end, func.highest_address)):
                        func = None
                        break
                    while start_next < min(end, func.highest_address):
                        il = func.get_low_level_il_at(start_next)
                        if start_next < end and il:
                            addrs.update(fn(il, start_next, addrinfo, debug,
                                            *kargs))
                        # sometimes binja combines lifted instructions
                        # (e.g., cmp followed by jmp), so calculate the
                        # next addr using the il.address
                        if il:
                            start_next = il.address + \
                                self.binja_view.get_instruction_length(il.address)
                        else:
                            logging.debug("Could not get IL for instruction "
                                          f"at address {start_next:x}")
                            start_next += self.binja_view.get_instruction_length(start_next)

                if func is None:  # keep on trying till we find a function
                    ins_len = self.binja_view.get_instruction_length(
                        start_next
                    )
                    if not ins_len:
                        ins_len = 1
                    last = start_next
                    start_next = start_next + ins_len
                    logging.debug("Binja didn't find a function or llil "
                                  "instruction defined at at %x " % last +
                                  "hopefully it isn't the instruction we are "
                                  "looking for and it can be safely skipped. "
                                  "skipping to instruction at %x" % start_next)
        return sorted(list(addrs))

    def _find_load_op_src(self, il, debug=False):
        o = self._find_op(il, bn.LowLevelILOperation.LLIL_LOAD, debug)
        if o:
            return o.src
        o = self._find_op(il, bn.LowLevelILOperation.LLIL_UNIMPL_MEM, debug)
        if o and hasattr(o, "src"):
            return o.src

    def _find_op(self, il, ilop, debug=False):
        if debug:
            logging.debug(f"{il}, {ilop}, {il.operation}")
        if isinstance(il, bn.LowLevelILOperation) or \
           isinstance(il, bn.LowLevelILInstruction):
            if il.operation == ilop:
                return il
            for o in il.operands:
                op = self._find_op(o, ilop)
                if op:
                    return op

    def _sum_il_operands(self, il):
        if il.operation == bn.LowLevelILOperation.LLIL_CONST:
            return il.value.value
        elif il.operation == bn.LowLevelILOperation.LLIL_SUB:
            modifier = -1
        elif il.operation == bn.LowLevelILOperation.LLIL_ADD:
            modifier = 1
        else:
            return 0
        return sum([modifier * self._sum_il_operands(o)
                    for o in il.operands])

    def _lookup_call_addrs(self, il, addr, addrinfo, debug, called):
        empty = []
        last_called = called.get("last_call", [])
        # last_pc = called.get("last_pc")
        ret_op = self._find_op(il, bn.LowLevelILOperation.LLIL_RET)
        match_name = addrinfo.demangled_function \
            if addrinfo.subtype == Subtype.RETURN \
            else addrinfo.demangled_target
        cs_fns = [self.binja_view.get_function_at(a)
                  for a in self.binja_view.get_callees(addr)]
        if debug and cs_fns:
            addr_str = "%x" % addr
            logging.debug(f"Call searching {addr_str} for {match_name} in "
                          f"{[Demangler.demangle(f.name) for f in cs_fns]}")

        cs_fns = [f for f in cs_fns
                  if (not match_name) or
                  match_name == DwarfInfo.fn_name(f, True)]
        called["last_call"] = cs_fns
        # called["last_pc"] = addr
        is_return = True if ret_op else False
        if addrinfo.subtype == Subtype.RETURN:
            if (addrinfo.field == Field.PC and is_return) or \
               (addrinfo.field == Field.TARGET_ADDR and last_called):
                return [addr]  # current address
            return empty
        else:
            addrs = [f.start for f in cs_fns] \
                if addrinfo.subtype == Subtype.TARGET_ADDR else [addr]
            return addrs if len(cs_fns) > 0 else empty

    def _lookup_mem_addrs(self, il, addr, addrinfo, debug):
        empty = []
        if addrinfo.subtype == Subtype.READ and addrinfo.ins_type and \
           ((addrinfo.ins_type == Instype.CMP and
            il.operation != bn.LowLevelILOperation.LLIL_IF) or
            (addrinfo.ins_type == Instype.MOV and
             il.operation != bn.LowLevelILOperation.LLIL_SET_REG)):
            return empty

        if addrinfo.subtype == Subtype.WRITE and \
           il.operation == bn.LowLevelILOperation.LLIL_STORE:
            op = il.dest
        elif addrinfo.subtype == Subtype.READ:
            op = self._find_load_op_src(il)
        else:
            op = None
        if op:
            s = self._sum_il_operands(op)
            if debug:
                addr_str = "%x" % addr
                logging.debug(f"Found at {addr_str} op {op}, operand sum {s}")
            if addrinfo.offset is None or \
               addrinfo.offset == s:
                return [addr]
        return empty

    def _calc_addrs(self, addrinfo: LineInfo, name: str,
                    debug_addr: bool) -> Union[List[str], None]:
        logging.debug(f"Calculating addresses for {name}: {addrinfo}...")
        if addrinfo.kind in [Kind.BEGIN, Kind.END]:
            fn_name = addrinfo.demangled_function
            candidates = [f for f in self.binja_view.functions
                          if Demangler.demangle(f.name) == fn_name and
                          f.symbol.type != bn.SymbolType.ImportedFunctionSymbol]
            if len(candidates) != 1:
                if not candidates:
                    logging.error("No candidate values found")
                else:
                    logging.warning("More than one candidate found: %s" %
                                    [(c.name, c.symbol.type,
                                      "%x" % c.lowest_address,
                                      "%x" % (c.highest_address + 1))
                                     for c in candidates])
                # print([(f.name, f.symbol.type) for f in self.binja_view.functions],
                # file=sys.stderr)
            if addrinfo.kind == Kind.END:
                addrs = set([fn.highest_address + 1 for fn in candidates])
            else:
                addrs = set([fn.lowest_address for fn in candidates])
        else:
            loc = addrinfo.path
            line = addrinfo.lineno
            if (loc is None) or (line is None):
                logging.debug("path or lineno is empty, nothing to calculate")
                return []
            matches = [[m, e] for (m, e) in
                       self.dwarf_info.get_line_min_max_addrs(addrinfo.path,
                                                              addrinfo.lineno)
                       if not addrinfo.function or
                       (addrinfo.function and
                        (addrinfo.subtype == Subtype.RETURN or
                         addrinfo.demangled_function in
                         Demangler.demangle_names(m.fn_names)))]
            logging.debug(f"Found matching dwarf entries: {matches}")
            # merge overlaps in matches (matches are already sorted)
            search_addrs = []
            for (m, e) in matches:
                if len(search_addrs) > 0 and search_addrs[-1][1] > m.addr:
                    search_addrs[-1][1] = e.addr
                else:
                    search_addrs.append([m.addr, e.addr])
            if not search_addrs:
                return []
            logging.debug(f"Searching %s for {addrinfo}" %
                          ["(%x -- %x)" % (s, e) for (s, e) in search_addrs])
            # if there is 1 result and it's either assembly or not a PC entry
            # (because if its a PC entry we want to be sure we get an address
            # at the beginning of a basic block)
            # and there is only one instruction in the result, just accept it
            if len(search_addrs) == 1 and \
               ((addrinfo.kind != Kind.PCENTRY) or
                (addrinfo.path[-2:] in [".s", ".S"])) and \
               (search_addrs[0][1] ==
                (search_addrs[0][0] +
                 self.binja_view.get_instruction_length(search_addrs[0][0]))):
                # libc has a bunch of instructions that binja cannot
                # lift, (more specificaly __strcpy_avx2 of in
                # libc-2.31.so) which are all hand-coded assembly.  so
                # if there result only contains one instruction, just
                # return its address instead of trying to lift it to
                # see if it matches the addrinfo's constraints
                return ["0x%x" % search_addrs[0][0]]
            if addrinfo.kind == Kind.PCENTRY:
                # get first address in first block
                bbs = self.binja_view.get_basic_blocks_at(
                    min([m[0].addr for m in matches])
                )
                addrs = set([min([b.start for b in bbs])])
            elif addrinfo.kind == Kind.CALLENTRY:
                addrs = self._iter_llil_instructions(search_addrs,
                                                     self._lookup_call_addrs,
                                                     addrinfo, debug_addr,
                                                     {})
            elif addrinfo.kind == Kind.MEMENTRY:
                addrs = self._iter_llil_instructions(search_addrs,
                                                     self._lookup_mem_addrs,
                                                     addrinfo, debug_addr)
            else:
                raise AddrCacheException("Cannot resolve address type "
                                         f"{addrinfo.kind} for {addrinfo}")
        return [str("0x%x" % a) for a in addrs]

    def calculate_addrs(self, debug_addrs: List[str]) -> Dict[str, List[int]]:
        src_files = set()
        resolved = {}
        for (name, addrinfo) in self.libsummary.addresses.items():
            if addrinfo.path:
                src_files.add(os.path.join(self.libsummary.src_root,
                                           addrinfo.path))
        src_files.update(self.libsummary.additional_files)
        self.dwarf_info = DwarfInfo(self.lib_path, self.binja_view,
                                    src_files)
        for (name, addrinfo) in self.libsummary.addresses.items():
            debug_addr = name in debug_addrs
            if debug_addr:
                log_level = logging.getLogger().level
                logging.getLogger().setLevel(logging.DEBUG)
            addrs = self._calc_addrs(addrinfo, name, debug_addr)
            if addrs:
                logging.debug(f"Calculated {name}: {addrinfo}:\n{addrs}")
            else:
                log = logging.error if addrinfo.required else logging.debug
                opt = "" if addrinfo.required else "optional "
                log(f"Calculation failed for {opt}{name}: {addrinfo}")
                addrs = addrinfo.active_addresses
            if debug_addr:
                logging.getLogger().setLevel(log_level)
            if addrs:
                resolved[name] = addrs
        return resolved

    def create_cache(self, force=False, debug_addrs=[]):
        if os.path.exists(self.metadata_path) and not force:
            logging.error(f"Cache at {self.metadata_path} already "
                          "exists. Force overwrite with --force")
            return
        addrs = self.calculate_addrs(debug_addrs)
        global __version__
        with open(self.metadata_path, "w") as f:
            json.dump({self.VERSION_KEY: __version__,
                       self.ADDR_KEY: addrs},
                      f, indent=2, sort_keys=True)

    @classmethod
    def has_cache(cls, ri, libname):
        fn = ri.lookup_bin_metadata if isinstance(ri, Results) else \
            ri.get_bin_metadata_path
        return os.path.exists(fn(libname, cls.SUFFIX))

    @classmethod
    def load_cache(cls, ri, libname):
        global __version__
        fn = ri.lookup_bin_metadata if isinstance(ri, Results) else \
            ri.get_bin_metadata_path
        path = fn(libname, cls.SUFFIX)
        with open(path, "r") as f:
            j = json.load(f)
        version = j.get(cls.VERSION_KEY)
        if version is None:
            addr_dict = j
        elif j.get(cls.VERSION_KEY) == __version__:
            addr_dict = j[cls.ADDR_KEY]
        else:
            raise AddrCacheException(
                "Do not know how to load addr cache version " +
                version
            )
        return {k: [int(a, 0) for a in addrs]
                for (k, addrs) in addr_dict.items()}
