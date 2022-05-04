# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from tracetools.signatures.versions import Version
import struct
from collections import OrderedDict
import intervaltree as it
import logging
from tracetools.pt import PT
from tracetools.signatures.utils import SigException, OOPS
from tracetools.log_entries import is_kind, CallEntry, MemEntry, MallocEntry, \
    PCEntry


class SigID():
    """Acts as an IntEnum which assigns unique ids to each Signature that
    registers with this class.  """
    _next_id = 0
    _registered_classes = {}

    @classmethod
    def register(cls, sigcls):
        if hasattr(cls, sigcls.sig_id_name) \
           or sigcls in cls._registered_classes.values():
            inclass = getattr(cls, sigcls.sig_id_name)
            logging.error(f"Signature class already registered: "
                          f" {sigcls} ({sigcls.sig_id_name}/{inclass})")
            return None

        setattr(cls, sigcls.sig_id_name, cls._next_id)
        value = getattr(cls, sigcls.sig_id_name)
        cls._registered_classes[value] = sigcls
        sigcls.sig_id_val = value
        cls._next_id += 1
        return value

    @classmethod
    def from_int(cls, i):
        return cls._registered_classes.get(i)


class Signature():
    exception_class = SigException
    sig_id_val = -1
    sig_id_name = None
    callback = None
    manager = None
    parse_log = None
    lib_start = 0
    floating = False
    lib_name = None
    supported_group_ids = []
    primary_binary = None
    log_type = None
    attr_name = "pc"
    check_values = None
    single = True
    additional_libs = []
    struct_format = None
    struct = None
    packer = None
    mask = None
    subattr_value = None
    _float_map = {
        "d": "Q",
        "f": "I"
    }
    _struct_int_strs = ['b', 'h', 'i', 'l', 'q']
    _setup_done = False

    @classmethod
    def setup_sig_class(cls, manager, parselog, callback=None):
        cls.manager = manager
        cls.callback = callback
        cls.parse_log = parselog
        cls.bin_info = cls.parse_log.binfo
        # store in OrderedDict to remember order items were inserted and
        # ensure uniqueness
        cls._user_callbacks = OrderedDict()
        if cls.struct_format:
            if len(cls.struct_format) != 1:
                raise SigException("Bad struct format string for signature " +
                                   cls.sig_id_name)
            if cls.struct_format in cls._float_map:
                cls.packer = struct.Struct(cls._float_map[cls.struct_format])
            cls.struct = struct.Struct(cls.struct_format)
            cls.mask = (2 ** (cls.struct.size * 8)) - 1
        cls.do_flag = cls._do_flag_callback if callback else cls._do_flag
        cls._setup()

    def __init__(self):
        self.do_reset()

    def OOPS(self, *message):
        OOPS(self.exception_class, *message, "\n",
             "For signature:", self)

    def __repr__(self):
        return f"SIG[{self.sig_id_name}:{id(self)}]"

    @classmethod
    def add_flag_callback(cls, callback):
        cls._user_callbacks[callback] = 0

    @classmethod
    def rm_flag_callback(cls, callback):
        try:
            cls._user_callbacks.pop(callback)
        except KeyError:
            pass

    @classmethod
    def setup(cls):
        pass

    @classmethod
    def _setup(cls):
        """ one-time class setup """
        cls.setup()

    def do_reset(self):
        self.flagged_entry = None
        self._detected = False
        self.reset()

    def reset(self):
        pass

    @property
    def detected(self):
        return self._detected

    def flag(self, **kwargs):
        pass

    def _flag(self, log_entry, **kwargs):
        self._detected = True
        self.flagged_entry = log_entry
        # if not self.floating:
        #     self.manager.signatures.flagged_sigs.append(self)

    def _do_flag_callback(self, log_entry, **kwargs):
        self._do_flag(log_entry, **kwargs)
        self.callback(self)

    def _do_flag(self, log_entry, **kwargs):
        self._flag(log_entry, **kwargs)
        self.flag(**kwargs)
        for c in self._user_callbacks.keys():
            c(self, self.manager)

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, self.log_type) \
           and getattr(log_entry, self.attr_name) in self.check_values \
           and (self.subattr_name is None or
                getattr(log_entry, self.subattr_name, None) ==
                self.subattr_value):
            self.do_flag(log_entry)

    # convienance operations for converting from value in MemEntry
    # to actual value if cls.struct_format defined
    @classmethod
    def unpack_val(cls, val):
        if cls.struct_format is None:
            raise SigException("Cannot unpack value for signature with no "
                               f"struct_format: {cls.sig_id_name}")
        val = val & cls.mask
        if cls.struct_format in cls._float_map:
            val = cls.struct.unpack(cls.packer.pack(val))[0]
        elif cls._is_struct_signed():
            # convert to 2s complement if needed
            bits = cls.struct.size * 8
            val = val - (1 << bits) if val & (1 << (bits - 1)) != 0 else val
        return val

    @classmethod
    def pack_val(cls, val):
        if cls.struct_format is None:
            raise SigException("Cannot pack value for signature with no "
                               f"struct_format: {cls.sig_id_name}")
        s = cls.packer if cls.packer else cls.struct
        return s.pack(val & cls.mask)

    @classmethod
    def _is_struct_signed(cls):
        return cls.struct_format[-1] in cls._struct_int_strs \
            if cls.struct_format else False


class SigRegistrar():
    def __init__(self):
        # signatures that flag memtrace log events
        self.tracked_sigs = set()
        # "signatures" that aren't triggered by memtrace log events
        self.floating_sigs = {}
        # maps between signature id and corresponding Signature class
        self.sig_classes = {}
        self.sig_groups = {}
        self.next_group = 0

    def setup_sig_classes(self, manager, parselog, cls=Signature):
        def callback_name(sigclass):
            return f"callback_{sigclass.sig_id_name}"
        if cls.primary_binary is True and \
           Version.group_id in cls.supported_group_ids:
            cls.lib_name = Version.primary_binary()

        if cls in self.sig_classes.values():
            # already has been registered
            return
        if cls.supported_group_ids and \
           Version.group_id not in cls.supported_group_ids:
            # if cls.supproted_group_ids
            # specificied and current group_id isn't included
            return

        if cls.lib_name and not Version.has_lib_info(cls.lib_name):
            # library isn't being used
            return

        # cls = Signature if cls is None else cls
        if not hasattr(cls, "sig_reg_if_no_subclass"):
            cls.sig_reg_if_no_subclass = False
        if cls.sig_id_name is not None and \
           (not cls.sig_reg_if_no_subclass or
            (cls.sig_reg_if_no_subclass and not cls.__subclasses__())):
            value = SigID.register(cls)
            if value is None:
                logging.error(f"Could not register id for {cls}")
            callback = getattr(manager, callback_name(cls), None)
            self.sig_classes[value] = cls
            if (getattr(cls.log_type, "encoding", None) ==
                CallEntry.encoding) and \
                cls.attr_name == "target_addr" and \
                not hasattr(cls, "subattr_name") and \
                (getattr(cls, "flag_addr_fn_name", None) is not None or
                 getattr(cls, "fn_names", None) is not None):
                    cls.subattr_name = "call_kind"
                    cls.subattr_value = CallEntry.CALL
            if not hasattr(cls, "subattr_name"):
                cls.subattr_name = None
            if (cls.lib_name is None or
                Version.has_lib_info(cls.lib_name)) and \
                all([Version.has_lib_info(l)
                     for l in cls.additional_libs]):
                cls.setup_sig_class(manager, parselog, callback)
            if cls.floating:
                self.add_sig(cls())

        for subcls in cls.__subclasses__():
            if not subcls._setup_done or subcls.__subclasses__():
                # only register once per parent signature class
                self.setup_sig_classes(manager, parselog, subcls)
                subcls._setup_done = True
        for subcls in [s for s in manager.dynamic_classes
                       if issubclass(s, Signature)]:
            if not subcls._setup_done:
                # only register once per parent signature class
                self.setup_sig_classes(manager, parselog, subcls)
                subcls._setup_done = True

    def add_sig_flag_callback(self, sig_id, callback) -> bool:
        sig_class = self.sig_classes.get(sig_id)
        if not sig_class:
            return False
        sig_class.add_flag_callback(callback)
        return True

    def flag_floating_sig(self, sig_id, why=None):
        sig = self.floating_sigs.get(sig_id, None)
        if sig:
            sig.do_flag(None, why=why)

    def active_sigs_by_id(self, sig_id):
        return [s for s in self.tracked_sigs if s.sig_id_val == sig_id]

    def do_log_entry(self, entry):
        # self.flagged_sigs = []

        [m.do_log_entry(entry) for m in list(self.tracked_sigs)]
        # if len(self.flagged_sigs) > 1:
        #     print(self.flagged_sigs)
        #     raise Exception

    def get_results(self):
        return {v.sig_id_val: v.detected for v in self.tracked_sigs}

    def get_floating_sig_results(self):
        return {k: v.detected for (k, v) in self.floating_sigs.items()}

    def create_sig(self, sig_id, *args, **kwargs):
        sig = self.sig_classes.get(sig_id)
        return sig(*args, **kwargs) if sig else None

    def _enable_sig(self, sig: Signature):
        if sig.floating:
            if sig.single and sig.sig_id_val in self.floating_sigs:
                sig.OOPS("Only one active instance of signature "
                         f"allowed at a time for {sig}",
                         "Currently active:", self.floating_sigs)

            self.floating_sigs[sig.sig_id_val] = sig
        else:
            if sig.single and \
               any([sig != s and sig.sig_id_val == s.sig_id_val
                    for s in self.tracked_sigs]):
                sig.OOPS(SigException,
                         "Only one active instance of signature",
                         f"allowed at a time for {sig}." "\nCurrently active:",
                         self.tracked_sigs)
            self.tracked_sigs.add(sig)

    def _disable_sig(self, sig: Signature):
        self.tracked_sigs.discard(sig)

    def add_sig(self, sig: Signature, group=None, enable=True):
        if enable:
            self._enable_sig(sig)
        if group is not None and group in self.sig_groups:
            self.sig_groups[group].append(sig)
        else:
            group = self.next_group
            self.sig_groups[group] = [sig]
            self.next_group += 1
        return group

    def remove_sig_from_group(self, sig: Signature, group):
        sig_group = self.sig_groups.get(group, [])
        try:
            sig_group.remove(sig)
            if not sig_group:
                del self.sig_group[group]
        except ValueError:
            pass

    def add_sig_group(self, sigs, enable=True):
        group = self.next_group
        self.sig_groups[group] = sigs
        if enable:
            [self._enable_sig(s) for s in sigs]
        self.next_group += 1
        return group

    def remove_sig_group(self, group, callback=None):
        sigs = self.sig_groups.get(group, [])
        for s in sigs:
            self.remove_sig(s, callback)

    def remove_sig(self, sig, callback=None):
        groups = [k for (k, g) in self.sig_groups.items() if sig in g]
        for g in groups:
            for s in self.sig_groups[g]:
                if s != sig:
                    self._disable_sig(s)
                    if callback:
                        callback(s)
            del self.sig_groups[g]
        if callback:
            callback(sig)
        self._disable_sig(sig)


class ReturnSignature(Signature):
    sig_id_name = "RETURN"
    single = False
    log_type = CallEntry
    attr_name = "target_addr"
    _setup_done = False

    def __init__(self, flag_callback,
                 return_addrs=None):
        super(ReturnSignature, self).__init__()
        if return_addrs is not None:
            self.check_values = [return_addrs] \
                if isinstance(return_addrs, int) else return_addrs
        self.flag_callback = flag_callback
        self._parent_frame = None

    @property
    def parent_frame(self):
        return self._parent_frame

    def _do_flag(self, log_entry, **kwargs):
        super(ReturnSignature, self)._do_flag(log_entry, **kwargs)
        if self.flag_callback:
            self.flag_callback(self)

    def __repr__(self):
        return super(ReturnSignature, self).__repr__() + ":(" + \
            ", ".join("%x" % i for i in self.check_values) + ")"


class MomentSignature(Signature):
    remove_when_flagged = False
    flag_addr_name = None
    flag_addr_idx = None
    flag_addr_fn_name = None
    num_addr_expected = None
    parent_frame_class = None
    enable_sigs = []
    enable_sig_frame_class = None
    enable_sigs_in_frame_only = True

    def _flag(self, log_entry):
        self._detected += 1
        self.flagged_entry = log_entry
        if self.__class__.remove_when_flagged:
            self.disable()
        self._flag_enable_sigs()

    def flag_enable_sigs(self):
        pass

    def _flag_enable_sigs(self):
        self.flag_enable_sigs()
        if not self.enable_sigs:
            return
        parent_frame = self.parent_sig_enable_frame
        if self.enable_sigs_in_frame_only and not parent_frame:
            frame_class = self.enable_sig_frame_class \
                if self.enable_sig_frame_class else self.parent_frame_class
            self.OOPS(f"Must enable enable_sigs in {frame_class}, but",
                      "no no such frame is currently on ghoststack")
        add_sig = parent_frame.add_ghostsite_sig if parent_frame else \
            self.manager.add_sig
        add_sig_group = parent_frame.add_ghostsite_sig_group \
            if parent_frame else self.manager.add_sig_group
        for s in self.enable_sigs:
            if isinstance(s, str):
                add_sig(self.manager.sig_from_id(getattr(SigID, s)))
            else:
                add_sig_group(
                    [self.manager.sig_from_id(getattr(SigID, name))
                     for name in s]
                )

    @property
    def parent_frame(self):
        return self.manager.stack_top(self.parent_frame_class) \
            if self.parent_frame_class else None

    @property
    def parent_sig_enable_frame(self):
        cls = self.enable_sig_frame_class if self.enable_sig_frame_class else \
            self.parent_frame_class
        return self.manager.stack_top(cls) if cls else None

    def disable(self):
        if self.parent_sig_enable_frame:
            self.parent_sig_enable_frame.remove_ghostsite_sig(self)
        else:
            self.manager.remove_sig(self)

    def do_reset(self):
        self._detected = 0
        super(MomentSignature, self).do_reset()

    @classmethod
    def _setup(cls):
        if cls.lib_name:
            cls.lib_start = Version.lib_starts(cls.lib_name)
            if len(cls.lib_start) == 1:
                cls.lib_start = cls.lib_start[0]
        if cls.flag_addr_name:
            addrs = cls.addrs_of(cls.flag_addr_name,
                                 num_expected=cls.num_addr_expected)
            if cls.flag_addr_idx is not None:
                addrs = [addrs[cls.flag_addr_idx]]
            cls.check_values = addrs
        elif cls.flag_addr_fn_name:
            cls.check_values = cls.get_fn_abs_and_plt_addrs(cls.flag_addr_fn_name,
                                                            cls.lib_name)
        cls.setup()

    @classmethod
    def addrs_of(cls, name, num_expected=None, absolute=True, lib_name=None):
        lib_name = cls.lib_name if lib_name is None else lib_name
        return Version.get(lib_name).addrs_of(name, num_expected,
                                              absolute)

    @classmethod
    def get_segment_at(cls, addr):
        return Version.bin_info.get_segment_at(addr)

    @classmethod
    def abs_to_virt(cls, addr, seg):
        return Version.bin_info._abs_to_virt(addr, seg)

    @classmethod
    def lookup_lib_starts(cls, name, num_expected=None):
        return Version.lib_starts(name, num_expected)

    @classmethod
    def get_fn_abs_addr(cls, name, anytype=False, lib=None,
                        num_expected=None):
        return Version.get_fn_abs_addr(name, anytype, lib, num_expected)


    @classmethod
    def get_fn_abs_and_plt_addrs(cls, name, lib=None):
        return Version.get_fn_abs_and_plt_addrs(name, lib)

    def debug_string(self):
        frame_info = ", ".join(f"{c}: {getattr(self, c)},"
                               for c in ["parent_frame_class",
                                         "enable_sig_frame_class"]
                               if getattr(self, c))
        remove = "FLAG:remove" if self.remove_when_flagged else "FLAG:keep"
        return f"{self}({frame_info})[{self.enable_sigs}] {remove}"

    def OOPS(self, *message):
        frame_info = "Frame: " + self.parent_frame.debug_string() + "\n" \
            if self.parent_frame_class and self.parent_frame else ""
        frame_info = f"{frame_info}Sig enable frame: " + \
            self.parent_sig_frame + "\n" \
            if self.enable_sig_frame_class else frame_info
        OOPS(self.exception_class, *message, "\n",
             "Signature information:", self.debug_string(), "\n",
             frame_info,
             f"Evaluator information: {self.manager.debug_string()}")


class Malloc(MomentSignature):
    sig_id_name = "MALLOC"
    log_type = MallocEntry
    attr_name = "target_addr"

    def reset(self):
        self.seg = None

    def _do_flag(self, log_entry):
        super(Malloc, self)._do_flag(log_entry)
        self.seg = self.get_segment_at(log_entry.pc)


class TraceSig(MomentSignature):
    attr_name = "pc"
    remove_when_flagged = False

    def __init__(self, callsite_id):
        super(TraceSig, self).__init__()
        self.callsite_id = callsite_id

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, self.log_type):
            top = self.manager.ml.stack.top()
            if top and top.callsite_id == self.callsite_id:
                self.do_flag(log_entry)


class BBTraceSig(TraceSig):
    log_type = PCEntry
    sig_id_name = "FN_BB_TRACE"


class CallTraceSig(TraceSig):
    sig_id_name = "FN_CALL_TRACE"

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, CallEntry) and \
           log_entry.call_kind == log_entry.CALL and \
           len(self.manager.ml.stack.stack) > 1:
            second_to_top = self.manager.ml.stack.stack[-2]
            if second_to_top.callsite_id == self.callsite_id:
                self.do_flag(log_entry)


class MemTraceSig(TraceSig):
    log_type = MemEntry
    sig_id_name = "FN_MEM_TRACE"


class FileTaintRead(MomentSignature):
    sig_id_name = "TAINT_READ"

    def reset(self):
        self._detected = 0
        self.offsets = it.IntervalTree()
        self.flagged_entries = []
        self._first_taint = None
        self.interval = None

    def get_taint(self):
        self.offsets.merge_overlaps(strict=False)
        self.offsets.merge_equals()
        return self.offsets

    def merge_taint_from(self, other):
        if self.first_taint is None:
            self.first_taint = other.first_taint
        self.offsets |= other.offsets

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

    @property
    def first_taint(self):
        """first taint is first taint encounted, may not be the min offset if
        file's bytes aren't read sequentially"""
        return self._first_taint

    def flag(self):
        o = self.interval
        i = it.Interval(o, o + self.flagged_entry.size)
        self.offsets.add(i)
        self.flagged_entries.append(self.flagged_entry)
        if self.first_taint is None:
            self._first_taint = i.begin

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, MemEntry):
            o = self.parse_log.files.offset_at(log_entry.addr)
            if o and log_entry.typ == log_entry.READ:
                self.interval = o
                self.do_flag(log_entry)


class BasicBlockMoment(MomentSignature):
    sig_id_name = "BASIC_BLOCK"

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, PCEntry):
            self.do_flag(log_entry)


class CallTraceMoment(MomentSignature):
    sig_id_name = "CALL_TRACE"

    def reset(self):
        self.flagged_entry = None
        self.stack_size = 0
        self.stack_top = ''

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, CallEntry):
            stack_top = self.parse_log.stack.top()
            if stack_top and self.stack_top and not (self.stack_top ==
                                                     stack_top.fn_id):
                self.stack_top = "%s" % stack_top.fn_id
                self.do_flag(log_entry)
            if stack_top and (not self.stack_top):
                self.stack_top = stack_top.fn_id


class MemReadMoment(MomentSignature):
    sig_id_name = "MEM_READ"
    struct_format = "Q"

    def reset(self):
        self.value = None
        self.seg = None
        self.virtpc = None

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, MemEntry) and \
           log_entry.typ == log_entry.READ:
            self.seg = self.get_segment_at(log_entry.pc)
            self.virtpc = self.abs_to_virt(log_entry.pc, self.seg)
            self.value = self.struct.pack(log_entry.value)
            self.do_flag(log_entry)


class NewFrameMoment(MomentSignature):
    push_frame_class = None
    fn_names = []

    @classmethod
    def _setup(cls):
        if cls.fn_names:
            cls.check_values = set()
            for f in cls.fn_names:
                # add addresses of functionsn themselves and their
                # plt entries
                cls.check_values.update(
                    cls.get_fn_abs_and_plt_addrs(f, cls.lib_name)
                )
        super(NewFrameMoment, cls)._setup()

    def frame_args(self):
        return None

    def _do_flag(self, log_entry):
        super(NewFrameMoment, self)._do_flag(log_entry)
        args = self.frame_args()
        c = self.push_frame_class(self, *args) if args is not None else \
            self.push_frame_class(self)
        self.manager.push_stack(c)
        if not self.remove_when_flagged:
            self.do_reset()


class PTMoment(MomentSignature):
    pt_type = None
    pt_container_type = None
    expected_lex_obj_value = None
    expected_lex_obj_type = None
    null_lex_obj_ok = False
    pt_class = PT

    def __init__(self, first_lex_obj):
        self.first_lex_obj = first_lex_obj
        super(PTMoment, self).__init__()

    def package_pt_obj(self, obj) -> PT:
        pt = obj.to_pt(self.pt_type)
        if self.pt_container_type:
            pt = self.pt_class(self.pt_container_type, children=[pt])
        return pt

    def lex_obj_val_eq(self, v1, v2):
        return v1 == v2

    def _do_check(self, name, obj, expected_val, val_attr):
        val = getattr(obj, val_attr) if obj else None
        ok = self.lex_obj_val_eq(val, expected_val) or expected_val is None
        if not ok:
            OOPS(SigException, self,
                 f"Did not find expected {name} {expected_val},",
                 f"instead found {val} for lexer object {obj}.",
                 "\nIn ghoststack:",
                 self.manager.ghoststack,
                 self.__dict__, "\n",
                 self.debug_string())
        return ok

    def lex_obj_value_ok(self, obj) -> bool:
        return self._do_check("obj value", obj, self.expected_lex_obj_value,
                              "value")

    def lex_obj_type_ok(self, obj) -> bool:
        return self._do_check("obj type", obj, self.expected_lex_obj_type,
                              "type")

    def lex_obj_ok(self, obj):
        return self.null_lex_obj_ok or obj is not None

    def check_lex_obj(self, obj) -> bool:
        return self.lex_obj_ok(obj) and ((obj is None) or
                                         (self.lex_obj_type_ok(obj) and
                                          self.lex_obj_value_ok(obj)))

    def get_lex_obj(self):
        return self.first_lex_obj

    def _register_pt_with_frame(self, pt, frame):
        frame = self.parent_frame if frame is None else frame
        if not frame:
            self.OOPS("Cannot register pt, no parent frame of class",
                      self.frame_class,
                      "on stack.", "Trying to register pt", pt, "\n")
        frame.register_pt_node(pt, self)

    def handle_lex_obj(self, frame):
        obj = self.get_lex_obj()
        if self.check_lex_obj(obj):
            pt = self.package_pt_obj(obj)
            # if we have a frame to register with, do it
            # the frame may not always be immediately available,
            # particularly if the signature is also a NewFrameMoment
            # and it wants to register iself with the frame its creating
            # In this case, the new frame checks its flagging signature
            # to see if there are any objects to be registered with it and if
            # so, registers it during the frame's construction
            if frame:
                self._register_pt_with_frame(pt, frame)

    def _flag(self, log_entry):
        super(PTMoment, self)._flag(log_entry)
        self.handle_lex_obj(self.parent_frame)


class FloatingSig(Signature):
    floating = True

    def flag(self, why=None):
        self._detected += 1
        if why:
            if isinstance(why, it.IntervalTree):
                self.why.append(why)
            elif isinstance(why, list):
                self.why += why

    def do_reset(self):
        self._detected = 0
        self.why = []
        super(FloatingSig, self).do_reset()

    def __repr__(self):
        detected = "%d" % self._detected
        sig_name = self.sig_name if self.sig_name != self._class_sig_name \
            else "%s" % self.sig_id_name
        why = "" if not (self._detected and self.why) else f" {self.why}"
        return f"{sig_name}: {detected}{why}"

    def on_exit(self, save=True):
        pass


class MalformTrackerSig(FloatingSig):
    sig_name = "Malform"
    _class_sig_name = "Malform"

    @classmethod
    def why_to_array(cls, why):
        return [PT.PTEncoder.encode_taint(i) for i in
                [tree for tree in why]]

    @classmethod
    def why_from_json(self, why):
        return [PT.PTEncoder.decode_taint(i) for i in
                [tree for tree in why]]

    @classmethod
    def from_json(cls, json, *args, **kwargs):
        for sub in cls.__subclasses__():
            if sub.sig_id_name == json["sig_id_name"]:
                c = cls(*args, **kwargs)
                c._detected = json["_detected"]
                c.why = PT.PTEncoder.decode_taint(json["why"])
                return c

    def to_dict(self):
        return {"sig_name": self.sig_name,
                "sig_id_name": self.sig_id_name,
                "why": self.why_to_array(self.why),
                "_detected": self._detected}
