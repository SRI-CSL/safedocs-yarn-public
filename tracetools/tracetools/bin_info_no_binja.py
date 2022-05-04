# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import os
import dbm
import subprocess
import logging
# aenum because pypy3 cannot handle enum
from aenum import IntEnum, auto
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import functools
import bisect
import capstone
import shelve
from typing import List
import dataclasses
import intervaltree as it
import bin_info_common
from tracetools import global_config


__version__ = "0.6"


class SymTypeEnum(IntEnum):
    FUNCTION = 0
    PLT = auto()
    UNKNOWN = auto()


@dataclasses.dataclass
class Symbol():
    name: str
    type: SymTypeEnum = SymTypeEnum.UNKNOWN
    _full_name: dataclasses.InitVar[str] = None

    @property
    def full_name(self):
        if self._full_name is None:
            self._full_name = self.demangle(self.name)
        return self._full_name

    @classmethod
    def demangle(cls, name: str):
        args = ['c++filt']
        if name.endswith("_0"):
            name = name[:-2]
        args.append(name)
        pipe = subprocess.Popen(args,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        stdout, _ = pipe.communicate()
        return stdout.decode("utf-8", errors="ignore").split("\n")[0].strip()

    # @classmethod
    # def from_dict(cls, d: dict):
    #     return cls(**{f.name: d.get(f.name)
    #                   for f in dataclasses.fields(cls)})

    # def to_dict(self):
    #     return {f.name: getattr(self, f.name)
    #             for f in dataclasses.fields(self)}


@functools.total_ordering
class Function():
    def __init__(self, name: str, start: int, symbol: Symbol = None,
                 demangle: bool = True):
        self.name = name
        self.start = start
        self.symbol = symbol
        self.__post_init__()
        if demangle and symbol and name:
            # force demangling now
            self.symbol.full_name

    def __cmp__(self, o):
        return self.name == o.name and self.start == o.start

    def __eq__(self, o):
        return self.__cmp__(o)

    def __lt__(self, o):
        return self.start < o.start

    @classmethod
    def from_ELF_symbol(cls, cs, typ=SymTypeEnum.FUNCTION):
        if cs['st_value'] > 0 and len(cs.name) > 0:
            name = cs.name + "_0" if typ == SymTypeEnum.FUNCTION else cs.name
            return Function(name, cs['st_value'])
        else:
            return None

    def __repr__(self):
        name = self.name \
            if not global_config.demangle and self.symbol and \
            self.symbol.full_name else \
            self.symbol.full_name
        return "%s:%x" % (name, self.start)

    def __post_init__(self):
        if self.symbol is None or self.symbol.type == SymTypeEnum.UNKNOWN:
            typ = SymTypeEnum.FUNCTION if self.name.endswith("_0") \
                else SymTypeEnum.PLT
            self.symbol = Symbol(self.name, typ)

    # @classmethod
    # def from_dict(cls, d):
    #     return cls(d["name"], d["start"],
    #                Symbol.from_dict(d["symbol"]),
    #                force_demangle=False)

    # def to_dict(self):
    #     return {"name": self.name,
    #             "start": self.start,
    #             "symbol": self.symbol.to_dict()
    #             }


class BinaryView():
    DB_KEY = "syms"
    VERSION_KEY = "version"

    def __init__(self, binary: str, ri):
        self.binary = binary
        self._functions = None
        self._num_functions = None
        self.ri = ri
        self.capstone = capstone.Cs(capstone.CS_ARCH_X86,
                                    capstone.CS_MODE_64)
        self.basename = os.path.basename(self.binary)
        self.bin_file = open(self.binary, 'rb')
        self.elf = ELFFile(self.bin_file)
        self.has_symbols = self.elf.get_section_by_name(".symtab") is not None
        self.bndb = ri.r.lookup_bin_metadata(os.path.basename(self.binary),
                                             BinaryInfo.suffix)
        self.cached_ins_length = {}
        self._elf_seg_addr_it = None

    def setup_functions(self):
        if not self.has_symbols:
            self._functions = []
            self._num_functions = 0
            return
        try:
            db = shelve.open(self.bndb, "r")
        except dbm.error:
            db = None
        if db:
            logging.info(f"importing cache of symbol info {self.bndb}")
            self.load_syms(db)
        else:
            db = shelve.open(self.bndb)
            logging.info(f"creating cache of symbol info {self.bndb}")
            self.functions_from_ELF(db)
        logging.info("... done")
        db.close()
        self._functions.sort()
        self._num_functions = len(self._functions)

    def load_syms(self, db: shelve.Shelf):
        global __version__
        version = db.get(self.VERSION_KEY)
        if version is not None and version != __version__:
            raise bin_info_common.BinInfoException(
                "Do not know how to process symbol cache version" +
                version
            )
        self._functions = db[self.DB_KEY]

    @property
    def elf_seg_addrs(self):
        if self._elf_seg_addr_it is None:
            self._elf_seg_addr_it = it.IntervalTree()
            for seg in self.elf.iter_segments():
                # consider LOAD only to prevent same address being yielded twice
                if seg['p_type'] != 'PT_LOAD':
                    continue
                self._elf_seg_addr_it.addi(seg['p_vaddr'],
                                           seg['p_vaddr'] + seg['p_filesz'],
                                           seg)
        return self._elf_seg_addr_it

    def _virt_addr_to_elf_seg(self, addr: int):
        segs = self.elf_seg_addrs.at(addr)
        if len(segs) != 1:
            msg = "Warning: 0 or multiple ELF segments exist for " \
                "virtual address %x in %s: %s" % \
                (addr, self.binary, segs)
            raise bin_info_common.BinInfoException(msg)
        return segs

    def get_disassembly(self, virt_addr: int, seg=None) -> str:
        if seg is None:
            segs = self._virt_addr_to_elf_seg(virt_addr)
            if len(segs) != 1:
                return None
            s = segs.pop()
        else:
            s = seg
        self.bin_file.seek(virt_addr + s.data['p_offset'] - s.data['p_vaddr'])
        ins_bytes = self.bin_file.read(32)
        for (_, _, mn, opstr) in self.capstone.disasm_lite(ins_bytes,
                                                           virt_addr, 1):
            return f"{mn} {opstr}"

    def get_instruction_length(self, virt_addr: int) -> (int, int):
        cached = self.cached_ins_length.get(virt_addr, None)
        if cached is not None:
            return cached
        segs = self._virt_addr_to_elf_seg(virt_addr)
        if len(segs) != 1:
            return 0
        s = segs.pop()
        self.bin_file.seek(virt_addr + s.data['p_offset'] - s.data['p_vaddr'])
        ins_bytes = self.bin_file.read(32)
        for (_, sz, _, _) in self.capstone.disasm_lite(ins_bytes, virt_addr, 1):
            self.cached_ins_length[virt_addr] = sz
            return sz
        self.cached_ins_length[virt_addr] = 0
        return 0

    def functions_from_ELF(self, db: shelve.Shelf):
        global __version__
        self._functions = []
        db[self.VERSION_KEY] = __version__
        db[self.DB_KEY] = []
        rel_plt = self.elf.get_section_by_name(".rela.plt")
        plt = self.elf.get_section_by_name(".plt")
        if rel_plt is None or plt is None:
            return
        rel_sym_index = rel_plt.header.sh_link
        rel_sym_section = self.elf.get_section(rel_sym_index)
        plt_start = plt.header.sh_addr
        sections = [s for s in range(self.elf.num_sections())
                    if isinstance(self.elf.get_section(s),
                                  SymbolTableSection)
                    and s != rel_sym_index]
        # dynamic_sections = [s for s in range(self.elf.num_sections())
        #                     if isinstance(self.elf.get_section(s),
        #                                   DynamicSection)]
        for s in sections:
            for sym in self.elf.get_section(s).iter_symbols():
                # bija attaches a '_0' to the end of symbol names
                # for non-plt locations
                f = Function.from_ELF_symbol(sym)
                if f and f.name not in db:
                    self._functions.append(f)
        num = rel_plt.num_relocations()
        for i in [0, 1, 2, num - 3, num - 2, num - 1]:
            r = rel_plt.get_relocation(i)
            sym = rel_sym_section.get_symbol(r.entry.r_info_sym)

        for idx in range(rel_plt.num_relocations()):
            rel = rel_plt.get_relocation(idx)
            sym = rel_sym_section.get_symbol(rel.entry.r_info_sym)
            # plt_start + (0x10*(1+idx)) is address of function's
            # PLT entry
            f = Function(sym.name, plt_start + (0x10*(1+idx)))
            if f:  # and f.name not in db:
                self._functions.append(f)

        # this next bit is somewhat clunky -- it tries to extract
        # symbols that correspond to .plt.got by looking at each
        # entry's first instruction's jmp destination and finding the
        # coresponding .rela.dyn entry's (whose offset == jmp's
        # dereferenced address) symbol
        # if there is a .plt.got, then its entries look like
        # (gdb) disassemble 0x259f80
        # Dump of assembler code for function _ZN6ObjectD1Ev@plt:
        # 0x0000000000259f80 <+0>:	jmp    *0x2f27b2(%rip)        # 0x54c738
        # 0x0000000000259f86 <+6>:	xchg   %ax,%ax
        # the addr dereferenced by the jump can be matched with the relocation
        # entry in .rela.dyn whose offset is the same value, e.g.,
        # 000000000054c738 00003ca1 00000006 R_X86_64_GLOB_DAT 00000000002a0354 _ZN6ObjectD1Ev + 0
        # this relocation entry's corresponding symbol is what we want
        # any calls to 0x259f80 ultimately land at the funtion corresponding
        # to the symbol we looked up, e.g.,
        #   0x0000000000359d9d <+227>:	call   0x259f80 <_ZN6ObjectD1Ev@plt>
        plt_got = self.elf.get_section_by_name(".plt.got")
        rela_dyn = self.elf.get_section_by_name(".rela.dyn")
        sz = plt_got.header.sh_size if plt_got else 0
        entry_sz = 0x10
        if plt_got and rela_dyn and sz > entry_sz:
            offset = plt_got.header.sh_offset
            end = offset + sz
            self.capstone.detail = True
            sym_sec = self.elf.get_section(rela_dyn.header.sh_link)
            while offset < end:
                self.bin_file.seek(offset)
                ins_bytes = self.bin_file.read(entry_sz)
                found = False
                for ins in self.capstone.disasm(ins_bytes, offset):
                    if ins and capstone.CS_GRP_JUMP in ins.groups:
                        op = ins.operands[0]
                        rela_addr = op.mem.disp + offset + ins.size
                        for r in rela_dyn.iter_relocations():
                            if r.entry.r_offset == rela_addr:
                                # found the corresponding symbol name
                                sym = sym_sec.get_symbol(r.entry.r_info_sym)
                                self._functions.append(Function(sym.name,
                                                                offset))
                                found = True
                                break
                    if found:
                        break
                offset += entry_sz
            self.capstone.detail = False
        # we need to do something similar for .plt.sec sections
        #  to truly resolve all function addrs
        # example: libopenjp2.so.2.3.1
        # [13] .plt.sec PROGBITS  00000000000032c0 0032c0 000270 10 AX 0 0 16
        # (gdb) disassemble 0x32c0
        # Dump of assembler code for function lrintf@plt:
        # 0x00000000000032c0 <+0>: endbr64
        # 0x00000000000032c4 <+4>: bnd jmp *0x51d4d(%rip) # 0x55018 <lrintf@got.plt>
        # 0x00000000000032cb <+11>: nopl   0x0(%rax,%rax,1)
        # in .rela.plt section:
        # 0000000000055018  0000000100000007 R_X86_64_JUMP_SLOT  0000000000000000 lrintf@GLIBC_2.2.5 + 0
        plt_sec = self.elf.get_section_by_name(".plt.sec")
        rela_plt = self.elf.get_section_by_name(".rela.plt")
        sz = plt_sec.header.sh_size if plt_sec else 0
        entry_sz = 0x10
        if plt_sec and rela_plt and sz > entry_sz:
            offset = plt_sec.header.sh_offset
            end = offset + sz
            self.capstone.detail = True
            sym_sec = self.elf.get_section(rela_plt.header.sh_link)
            while offset < end:
                self.bin_file.seek(offset)
                ins_bytes = self.bin_file.read(entry_sz)
                for ins in self.capstone.disasm(ins_bytes, offset):
                    # this may easily break if the compiler/linker changes
                    # the implementation details
                    if ins and capstone.CS_GRP_JUMP in ins.groups:
                        op = ins.operands[0]
                        rela_addr = op.mem.disp + ins.address + ins.size
                        for r in rela_plt.iter_relocations():
                            if r.entry.r_offset == rela_addr:
                                # found the corresponding symbol name
                                sym = sym_sec.get_symbol(r.entry.r_info_sym)
                                self._functions.append(Function(sym.name,
                                                                offset))
                                break
                offset += entry_sz
            self.capstone.detail = False

        db[self.DB_KEY] = self._functions

    def functions_at_addr(self, addr: int) -> List[Function]:
        # we assume functions are sequential and end just before
        # where the next function begins
        allowed_syms = [SymTypeEnum.FUNCTION, SymTypeEnum.PLT]

        def skip_until_fn(idx):
            if idx < 0 or idx >= self._num_functions:
                return None
            entry = self.functions[idx]
            while idx > 0 and entry.symbol.type not in allowed_syms:
                idx -= 1
                entry = self.functions[idx]
            if entry.symbol.type in allowed_syms:
                return idx

        lidx = bisect.bisect_right(self.functions, Function("", addr))
        if lidx >= self._num_functions:
            lidx = self._num_functions - 1
        res = []
        lidx = skip_until_fn(lidx)
        entry = self.functions[lidx] if lidx is not None else None
        while entry and lidx >= 0:
            # if addr matches or is less than entry and either
            # we haven't found any matches yet, or we have found matches
            # but the current's entry start address is an exact match
            if entry.start <= addr and ((not res) or entry.start == addr):
                res.append(entry)
            if entry.start < addr:
                break
            lidx = skip_until_fn(lidx - 1)
            entry = self.functions[lidx] if lidx is not None else None
        return res

    def close(self):
        # print("num ins len keys", len(list(self.cached_ins_length.keys())))
        self.bin_file.close()

    @property
    def functions(self):
        if self._functions is None:
            self.setup_functions()
        return self._functions


class BinaryInfo(bin_info_common.BinaryInfoCommon):
    bin_type = 'ELF'
    suffix = ".otherdb"

    def __init__(self, binary, ri=None, mmap_file=None, src_dirs=[],
                 bin_dir=None):
        super(BinaryInfo, self).__init__(binary, BinaryView(binary, ri),
                                         mmap_file, src_dirs, bin_dir)
        # one of binary or bndb must exist.
        self.ri = ri
        if mmap_file:
            self._parse_mmap_file(mmap_file)

    def get_binary_view_basename(self, f):
        return f.basename

    def get_fn_addrs_from_name(self, name, find_all=False):
        return self._get_fn_addrs_from_name(name, SymTypeEnum.FUNCTION,
                                            find_all)

    def get_fn_info_from_name(self, name, anytype=False, lib=None):
        return self._get_fn_info_from_name(name, SymTypeEnum.FUNCTION,
                                           anytype, lib)

    def add_library_bv(self, path, db_path=None, notrack=False):
        def cb():
            return BinaryView(path, self.ri)
        self._add_library_bv(path, db_path, cb, notrack)

    def addr_to_fn(self, ip, segment, exact=False):
        if segment is None:
            return None
        virtip = self._abs_to_virt(ip, segment)
        bv = self.all_bvs.get(segment.basename, None)
        if bv:
            fns = [f for f in bv.functions_at_addr(virtip) if
                   ((not exact) or f.start == virtip)]
            return fns[0] if fns else None
        return None

    def close(self):
        for b in self.all_bvs.values():
            b.close()


if __name__ == "__main__":
    # some quick manual tests
    f = '/bin/ls'
    b = BinaryInfo(f)
