# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import struct


class EntryObj():
    unpack = "I"
    addrs = []
    encoding = -1
    pc = None
    log_idx = 0
    log_num = 0

    def __init__(self, b):
        self.unpacked = self._struct.unpack(b)
        self.kind = self.unpacked[-1]

    @classmethod
    def calcsize(cls, unpack):
        return cls._struct.size

    def normalize_pcs(self, mmap):
        return self.normalize_addrs(mmap)

    def normalize_addrs(self, mmap):
        if mmap:
            for i in self.addrs:
                setattr(self, i, mmap.abs_to_virt(getattr(self, i)))
        return self


class MallocEntry(EntryObj):
    encoding = 2
    name = "malloc"
    malloc_kinds = ["MALLOC", "CALLOC", "REALLOC", "REALLOCARRAY", "FREE",
                    "REALLOC_FREE", "REALLOCARRAY_FREE"]
    for o in range(len(malloc_kinds)):
        setattr(EntryObj, malloc_kinds[o], o)
    malloc = 0
    free = 1
    unpack = "=QQQi" + EntryObj.unpack
    _struct = struct.Struct(unpack)
    struct_size = _struct.size
    addrs = ["pc"]

    def __init__(self, b):
        super(MallocEntry, self).__init__(b)
        (self.malloc_addr, self.pc, self.size,
         self.malloc_kind, kind) = self.unpacked
        if self.malloc_kind < self.FREE:
            self.kind_meta = self.MALLOC
        else:
            self.kind_meta = self.FREE
        self.kind_name = self.malloc_kinds[self.malloc_kind]

    def __repr__(self):
        if self.kind_meta == self.malloc:
            return "MALLOC: %s - 0x%x-0x%x" % (self.kind_name,
                                               self.malloc_addr,
                                               self.malloc_addr + self.size)
        else:
            return "MALLOC: %s - 0x%x" % (self.kind_name,
                                          self.malloc_addr)


# class RegEntry(EntryObj):
#     encoding = 4
#     name = "reg"
#     read = 0
#     write = 1
#     unpack = "=QQIHIH" + EntryObj.unpack
#     _struct = struct.Struct(unpack)
#     struct_size = _struct.size
#     addrs = ["pc"]

#     def __init__(self, b):
#         super(RegEntry, self).__init__(b)
#         (self.pc, self.value, self.reg, self.rw, pack0,
#          pack1, kind) = self.unpacked
#         if self.rw == self.read:
#             self.kind_name = "R"
#         else:
#             self.kind_name = "W"
#         self.reg_name = reg_table.reg_names[self.reg]

#     def __repr__(self):
#         return "REG: @PC 0x%x: <%s(%d): 0x%x> %s" % (self.pc, self.reg_name,
#                                                      self.reg, self.value,
#                                                      self.kind_name)


class CallEntry(EntryObj):
    encoding = 0
    name = "call"
    INDIRECT = 0
    CALL = 1
    RET = 2
    INDIRECT_JMP = 3
    unpack = "=QQQI" + EntryObj.unpack
    _struct = struct.Struct(unpack)
    struct_size = _struct.size
    addrs = ["target_addr", "pc"]

    def __init__(self, b):
        super(CallEntry, self).__init__(b)
        (self.target_addr, self.pc,
         self.sp, self.call_kind,
         kind) = self.unpacked
        self.retval = None
        if self.call_kind == self.INDIRECT:
            self.kind_name = "*>"
        elif self.call_kind == self.CALL:
            self.kind_name = ">"
        elif self.call_kind == self.INDIRECT_JMP:
            # if it is a return, the sp field actually contains the
            # contents of rax instead of xsp
            self.retval = self.sp
            self.kind_name = "**"
        else:
            # if it is a return, the sp field actually contains the
            # contents of rax instead of xsp
            self.retval = self.sp
            self.kind_name = "<"

    def __repr__(self):
        info = "" if self.call_kind == self.RET else f" TOS: {self.pc:x}"
        return f"C: {self.kind_name} 0x{self.target_addr:x} "\
            f"PC: 0x{self.pc:x}{info}"


class MemEntry(EntryObj):
    encoding = 1
    name = "mem_ref"
    unpack = "=QQQHH" + EntryObj.unpack
    _struct = struct.Struct(unpack)
    struct_size = _struct.size
    READ = 0
    WRITE = 1
    addrs = ["pc", "addr"]

    _struct_read_fmts = {s.size: s for s in
                         [struct.Struct(f)
                          for f in ["B", "H", "I", "L", "Q"]]
                         }

    def __init__(self, b):
        super(MemEntry, self).__init__(b)
        self._value = None
        (self.addr, self.pc, self.raw_value, self.typ,
         self.size, kind) = self.unpacked
        self.mem = True
        if self.typ == self.READ:
            self.typ_name = "R"
        elif self.typ == self.WRITE:
            self.typ_name = "W"
            # self.value = 0
        # else:  # this isn't used by dynamorio
        #     self.mem = False
        #     self.typ_name = op_table.op_instr[self.typ]

    @property
    def value(self):
        if self._value is None:
            self._value = self.unpack_int()
        return self._value

    @property
    def value_bytes(self):
        return self._struct_read_fmts[self.size].pack(
            self.value
        )

    def unpack_int(self):
        return self.raw_value & ((2 ** (self.size * 8)) - 1)

    def unpack_signed_int(self):
        val = self.unpack_int()
        bits = self.size * 8
        return val - (1 << bits) if val & (1 << (bits - 1)) != 0 else val

    def __repr__(self):
        if self.mem:
            return "MI: 0x%x: %s %d bytes %s 0x%x [%x]" % \
                (self.pc, self.typ_name, self.size,
                 "from" if self.typ == self.READ else "to  ",
                 self.addr, self.value)
        else:
            return "M:  0x%x %s (%d)" % (self.pc, self.typ_name, self.size)


class PCEntry(EntryObj):
    encoding = 3
    name = "ins"
    unpack = "=QQbQhb" + EntryObj.unpack
    _struct = struct.Struct(unpack)
    struct_size = _struct.size

    def __init__(self, b):
        super(PCEntry, self).__init__(b)
        (self.pc, self.rax, self.reg_saved, self.pack0,
         self.pack1, self.pack2, kind) = self.unpacked

    def __repr__(self):
        regs = f" RAX=0x{self.rax:x}" if self.reg_saved \
            else ""
        return f"INS: 0x{self.pc:x}{regs}"


class FileWriteEntry(EntryObj):
    encoding = 10
    name = "write"
    unpack = "=QQQI" + EntryObj.unpack
    _struct = struct.Struct(unpack)
    struct_size = _struct.size

    def __init__(self, b):
        super(FileWriteEntry, self).__init__(b)
        (self.index, self.offset, self.count, self.fd,
         kind) = self.unpacked
        self._file = None

    @property
    def file(self):
        if self._file is None:
            if self.fd == 1:
                self._file = "STDOUT"
            elif self.fd == 2:
                self._file = "STDERR"
            else:
                self._file = f"FILE({self.fd})"
        return self._file

    def __repr__(self):
        return f"F_W: {self.count} bytes to {self.file} "\
            f"offset {self.offset}"


class LogOnEntry(EntryObj):
    encoding = -1
    name = "logon"
    unpack = "=QQQI" + EntryObj.unpack
    _struct = struct.Struct(unpack)
    struct_size = _struct.size

    def __init__(self, b):
        super(LogOnEntry, self).__init__(b)
        (self.pc, pack1, pack2, pack3,
         kind) = self.unpacked

    def __repr__(self):
        return f"LOGGING ENABLED @0x{self.pc:x}"


class LogOffEntry(EntryObj):
    encoding = -2
    name = "logoff"
    unpack = "=QQQI" + EntryObj.unpack
    _struct = struct.Struct(unpack)
    struct_size = _struct.size

    def __init__(self, b):
        super(LogOffEntry, self).__init__(b)
        (self.pc, pack1, pack2, pack3,
         kind) = self.unpacked

    def __repr__(self):
        return f"LOGGING DISABLED @0x{self.pc:x}"


class SigEntry(EntryObj):
    encoding = 8
    name = "sig"
    unpack = "=QIQQ" + EntryObj.unpack
    _struct = struct.Struct(unpack)
    struct_size = _struct.size

    def __init__(self, b):
        super(SigEntry, self).__init__(b)
        (self.pc, self.sig, pack1, pack2,
         kind) = self.unpacked

    def __repr__(self):
        return "Sig: %d at 0x%x" % (self.sig, self.pc)


class MmapEntry(EntryObj):
    encoding = 5
    name = "mmap"
    unpack = "=QQQI" + EntryObj.unpack
    _struct = struct.Struct(unpack)
    struct_size = _struct.size

    def __init__(self, b):
        super(MmapEntry, self).__init__(b)
        (self.addr, self.length, self.offset, pack0,
         kind) = self.unpacked

    def __repr__(self):
        if self.offset == 0:
            return "MMAP: unmap 0x%x-0x%x" % (self.addr,
                                              self.addr + self.length)
        else:
            return "MMAP: 0x%x to 0x%x-0x%x" % (self.offset,
                                                self.addr,
                                                self.addr + self.length)


class FileOpEntry(EntryObj):
    encoding = 6
    name = "fop"
    unpack = "=QIIQI" + EntryObj.unpack
    _struct = struct.Struct(unpack)
    struct_size = _struct.size
    op_kinds = ["OPEN", "CLOSE", "READ", "MMAP", "MUNMAP"]
    for o in range(len(op_kinds)):
        setattr(EntryObj, op_kinds[o], o)
    addrs = ["pc"]

    def __init__(self, b):
        super(FileOpEntry, self).__init__(b)
        (self.pc, self.fd, self.op_kind, pack0, pack1,
         kind) = self.unpacked
        # note this is actually the pc following the
        # syscall

    def __repr__(self):
        return "F_OP: fd %d @ 0x%x - %s" % (self.fd,
                                            self.pc,
                                            self.op_kinds[self.op_kind])


class FileReadEntry(EntryObj):
    encoding = 7
    name = "fread"
    unpack = "=QQQI" + EntryObj.unpack
    _struct = struct.Struct(unpack)
    struct_size = _struct.size

    def __init__(self, b):
        super(FileReadEntry, self).__init__(b)
        (self.addr, self.offset, self.count, self.fd,
         kind) = self.unpacked

    def __repr__(self):
        return "F_RD: fd %d @ offsets %d-%d to addr 0x%x" % \
            (self.fd, self.offset, self.offset + self.count, self.addr)


class SockRecvEntry(EntryObj):
    encoding = 9
    name = "fread"
    unpack = "=QQIQ" + EntryObj.unpack
    _struct = struct.Struct(unpack)
    struct_size = _struct.size

    def __init__(self, b):
        super(SockRecvEntry, self).__init__(b)
        (self.addr, self.count, self.fd, pack0,
         kind) = self.unpacked

    def __repr__(self):
        return "S_RV: fd %d @ to addr 0x%x-0x%x" % \
            (self.fd, self.addr, self.addr + self.count)


entry_kinds = [MallocEntry, CallEntry, MemEntry, PCEntry, MmapEntry,
               FileOpEntry, FileReadEntry, SigEntry, LogOnEntry,
               LogOffEntry, SockRecvEntry, FileWriteEntry]
entry_kind_map = {e.encoding: e for e in entry_kinds}

# for e in entry_kinds:
#     e.setup()


def is_kind(entry, entry_cls):
    return entry.encoding == entry_cls.encoding
