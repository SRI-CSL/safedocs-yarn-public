# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from tracetools.signatures.signatures import SigID, MomentSignature, \
    NewFrameMoment
from tracetools.signatures.pdf import PDFLexObj, PDFEnum
from tracetools.signatures.pdf import PDFPT as PT
from tracetools.signatures.pdf import ProcessStreamInfo, XRefTableInfo
from tracetools.signatures.evaluator import SigPTEval
# import struct
import intervaltree as it
from tracetools.signatures.ghoststack import PTStackOverlayEntry
from tracetools.signatures.versions import Version
from aenum import IntEnum, auto
import dataclasses
import typing
from tracetools.signatures.context import DataContext, ParseReason
from tracetools.log_entries import is_kind, CallEntry, MemEntry, PCEntry


class TokEnum(IntEnum):
    ERROR = 0
    EOF = auto()
    OPEN_ARRAY = auto()
    CLOSE_ARRAY = auto()
    OPEN_DICT = auto()
    CLOSE_DICT = auto()
    OPEN_BRACE = auto()
    CLOSE_BRACE = auto()
    NAME = auto()
    INT = auto()
    REAL = auto()
    STRING = auto()
    KEYWORD = auto()
    R = auto()
    TRUE = auto()
    FALSE = auto()
    NULL = auto()
    OBJ = auto()
    ENDOBJ = auto()
    STREAM = auto()
    ENDSTREAM = auto()
    XREF = auto()
    TRAILER = auto()
    STARTXREF = auto()
    REF = auto()


class MuLexObj(PDFLexObj):
    type_enum = TokEnum
    type_mapping = {
        TokEnum.ERROR: PDFEnum.ERROR,
        TokEnum.EOF: PDFEnum.EOF,
        TokEnum.OPEN_ARRAY: PDFEnum.ARRAY_START,
        TokEnum.CLOSE_ARRAY: PDFEnum.ARRAY_END,
        TokEnum.OPEN_DICT: PDFEnum.DICT_START,
        TokEnum.CLOSE_DICT: PDFEnum.DICT_END,
        TokEnum.OPEN_BRACE: PDFEnum.EXPR_START,
        TokEnum.CLOSE_BRACE: PDFEnum.EXPR_END,
        TokEnum.NAME: PDFEnum.NAME,
        TokEnum.INT: PDFEnum.INT,
        TokEnum.REAL: PDFEnum.REAL,
        TokEnum.STRING: PDFEnum.STRING,
        TokEnum.KEYWORD:  PDFEnum.KEYWORD,
        TokEnum.R: PDFEnum.KEYWORD,
        TokEnum.REF: PDFEnum.REF,
        TokEnum.TRUE: PDFEnum.BOOL,
        TokEnum.FALSE: PDFEnum.BOOL,
        TokEnum.NULL: PDFEnum.NULL,
        TokEnum.OBJ: PDFEnum.KEYWORD,
        TokEnum.ENDOBJ: PDFEnum.KEYWORD,
        TokEnum.XREF: PDFEnum.KEYWORD,
        TokEnum.TRAILER: PDFEnum.KEYWORD,
        TokEnum.STARTXREF: PDFEnum.KEYWORD,
        TokEnum.STREAM: PDFEnum.KEYWORD,
        TokEnum.ENDSTREAM: PDFEnum.KEYWORD
    }

    @classmethod
    def lex_type_to_pt_type(cls, typ):
        return cls.type_mapping[typ]


class MutoolMomentSig(MomentSignature):
    lib_name = "mutool"
    remove_when_flagged = True

    @property
    def parent_frame(self):
        f = super().parent_frame
        if not f:
            self.OOPS("Did not find corresponding parent ghoststack frame"
                      f"of class {self.parent_frame_class}")
        return f


class MutoolFrame(PTStackOverlayEntry):
    lib_name = "mutool"

    def __init__(self, *args, **kwargs):
        self.exception_info = None
        self.exception_sig = None
        super().__init__(*args, **kwargs)

    def register_exception(self, exception_info, sig):
        # this is called by ThrowException signature
        self.exception_info = exception_info
        self.exception_sig = sig


class MutoolPTTracker(SigPTEval):
    tracker_name = "mupdf"

    def __init__(self, memtrace_log, unique_objects_only: bool,
                 print_image_ops: bool = False, output_stream=None,
                 setup_sigs=True,
                 **kwargs):
        super().__init__(memtrace_log, unique_objects_only, **kwargs)
        self.print_image_ops = print_image_ops
        self.output_stream = output_stream
        if setup_sigs:
            [self.add_sig(self.sig_from_id(s)) for s in
             [SigID.PARSE_STM_OBJ, SigID.PARSE_IND_OBJ,
              SigID.PARSE_ARRAY, SigID.CACHE_OBJ, SigID.PARSE_DICT,
              SigID.PROCESS_CONTENTS, SigID.REPAIR_XREF,
              SigID.THROW_EXCEPTION, SigID.PARSE_OLD_XREF,
              SigID.PARSE_NEW_XREF]]

    def callback_MEM_READ(self, signature):
        print("read %x [%s] %s (%x)" % (signature.virtpc,
                                        signature.seg.basename,
                                        signature.value,
                                        signature.flagged_entry.addr))

    def callback_CALL_TRACE(self, signature):
        print(self.ml.stack.detail_string())


class MutoolPTNewFrameSig(MutoolMomentSig, NewFrameMoment):
    remove_when_flagged = False


class MutoolPTFrame(MutoolFrame):
    add_child_on_pop = False
    attr_name = "target_addr"
    log_type = CallEntry
    remove_when_flagged = False
    expected_tok_type = None
    expected_obj_type = None
    _additional_newobj_check = {}

    @dataclasses.dataclass
    class NewObjTok():
        sig_id_name: str
        tok_type: typing.List[TokEnum]
        obj_type: PDFEnum
        obj: PT = None
        _check: typing.ClassVar[typing.Dict] = \
            {"NEW_STRING": (TokEnum.STRING, None, None),
             "NEW_NAME": (TokEnum.NAME, None, None),
             "NEW_INT": (TokEnum.INT, PDFEnum.INT, None),
             "NEW_REAL": (TokEnum.REAL, PDFEnum.REAL, None)}
        check: typing.ClassVar[typing.Dict] = {}
        err: str = ""

        def __post_init__(self):
            if not callable(self.tok_type):
                if isinstance(self.tok_type, TokEnum):
                    self.tok_type = [self.tok_type]
                elif self.tok_type is None:
                    self.tok_type = []

        def docheck(self, requester, sig, obj, tok=-1):
            tok = tok if tok != -1 else requester.last_token
            self.err = ""
            if callable(self.tok_type):
                return self.tok_type(self, requester, sig, obj, tok)
            if ((self.tok_type and
                 tok is not None and
                 tok.type in self.tok_type) or
                not self.tok_type) and \
                ((self.obj_type is None) or
                 (self.obj_type is not None and obj and
                  obj.type == self.obj_type)):
                if self.obj:
                    return self.obj
                elif obj:
                    if tok:
                        obj.merge_taint(tok)
                    return obj
                elif tok:
                    return tok.to_pt()
                else:
                    # nothing to return
                    return None
            else:
                self.err = self._debug_string(requester, sig, obj, tok)
                return None

        def _debug_string(self, requester, sig, obj, tok):
            typ = PT(self.obj_type) if self.obj_type else None
            return f"{self.sig_id_name} Expect new object registered by " \
                f"{requester}/{sig} to be type {typ} and last " \
                "token to be one of " \
                f"{[MuLexObj(t) for t in self.tok_type if t]}, " \
                f"but instead got obj: {obj}, tok: {tok}"

        @classmethod
        def setup(cls):
            def _ref_check(self, requester, sig, obj, tok):
                self.err = ""
                expected = [TokEnum.INT, TokEnum.INT, TokEnum.REF]
                if not len(tok) == 3:
                    self.err = f"Expected 3 tokens but got {tok}"
                elif not [t and t.type == expected for (t, expected) in
                          zip(tok, expected)]:
                    self.err = "Token types do not match expectation: " \
                        f"got: {tok}, expected: {expected}"
                elif obj.type != PDFEnum.REF:
                    self.err = f"Expected obj type to be {PDFEnum.REF} " \
                        f"insetad got {obj}"
                if self.err:
                    self.err = f"{requester}/{sig}: {self.err}"
                    return None
                else:
                    [obj.merge_taint(t) for t in tok]
                    return obj

            cls.check = {sigid: cls(sigid, obj_type, tok_type, obj)
                         for (sigid, (obj_type, tok_type, obj))
                         in list(cls._check.items())}
            cls.check["NEW_REFERENCE"] = cls("NEW_REFERENCE",
                                             _ref_check, None, None)

    def do_obj_check(self, obj, sig, tok=-1):
        checker = self.NewObjTok.check.get(sig.sig_id_name)
        if not checker:
            fields = self._additional_newobj_check.get(sig.sig_id_name)
            if fields:
                checker = self.NewObjTok(*tuple([sig.sig_id_name] +
                                                list(fields)))
        if not checker:
            return obj
        obj = checker.docheck(self, sig, obj, tok)
        if obj is None:
            self.OOPS(checker.err)
        return obj

    def do_pt_check(self, obj, reg_frame):
        checker = self.NewPTObj.check.get(
            reg_frame.flagged_signature.sig_id_name
        )
        if not checker:
            return obj
        obj = checker.docheck(self, reg_frame, obj)
        if obj is None:
            self.OOPS(checker.err)
        return obj

    @dataclasses.dataclass
    class NewPTObj():
        sig_id_name: SigID
        first_tok_type: TokEnum
        last_tok_type: TokEnum
        obj_type: PDFEnum
        err: str = ""
        _check: typing.ClassVar[typing.Dict] = \
            {"PARSE_DICT": (TokEnum.OPEN_DICT, TokEnum.CLOSE_DICT,
                            PDFEnum.DICT),
             "PARSE_ARRAY": (TokEnum.OPEN_ARRAY, TokEnum.CLOSE_ARRAY,
                             PDFEnum.ARRAY)}
        check: typing.ClassVar[typing.Dict] = {}

        def docheck(self, checker, frame, obj):
            self.err = ""
            if frame.sig_id_name != self.sig_id_name:
                self.err = "Unexpected frame/signature, expected " \
                    f"{self.sig_id_name} but got {frame.sig_id_name}"
            elif checker.last_token is None or \
                 checker.last_token.type != self.first_tok_type:
                self.err = "Unexpected last token type, expected " \
                    f"{self.first_tok_type} but got {checker.last_token.type}"
            elif obj is not None and obj.type != self.obj_type:
                self.error = f"Unexpected obj type, got {obj} but " \
                    f"expected {self.obj_type}"
            else:
                first_child = checker.last_token.to_pt()
                if obj:
                    obj._children = [first_child] + obj.children
                else:
                    obj = PT(self.obj_type, children=[first_child])
                return obj
            return None

        @classmethod
        def setup(cls):
            cls.check = {sigid: cls(sigid, first, last, obj_type) for
                         (sigid, (first, last, obj_type))
                         in cls._check.items()}

    NewObjTok.setup()
    NewPTObj.setup()

    def __init__(self, sig, pt=None, pt_tracking_sigs=None):
        sigs = [self.manager.sig_from_id(s) for s in [SigID.LEX_TOK,
                                                      SigID.NEW_REAL,
                                                      SigID.NEW_INT,
                                                      SigID.NEW_NAME,
                                                      SigID.NEW_STRING,
                                                      SigID.NEW_REFERENCE]]

        pt_tracking_sigs = set() if pt_tracking_sigs is None else \
            pt_tracking_sigs
        pt_tracking_sigs.update(sigs)
        self.last_token = None
        self.objects = []
        if self.manager.stack_top(MutoolPTFrame) is None:
            self._register_pt = True
        super().__init__(sig, pt=pt, pt_tracking_sigs=pt_tracking_sigs)

    def register_new_object(self, obj, pc, reg_sig):
        # this is called by NewObject signatures
        self.OOPS(self, "don't know how to handle ",
                  "register new obj from", reg_sig, obj, "0x%x" %
                  pc, self.manager.ml.binfo.get_segment_at(pc))

    def register_token(self, tok, pc, reg_obj):
        # this is called by LexTokFrame frames
        self.last_token = tok

    def register_pt_node(self, obj, from_obj):
        # this is called by any stack frame
        super().register_pt_node(obj, from_obj)

    def on_pop(self, new_top):
        super().on_pop(new_top)
        next_top = [c for c in self.manager.ghoststack_overlay(MutoolPTFrame)
                    if c != self]
        if self.pt:
            if next_top:
                next_top[-1].register_pt_node(self.pt, self)
            else:
                self.do_register_pt(self.pt)

    def register_fetch(self, obj, fetch_frame):
        pass


@dataclasses.dataclass(repr=False)
class MuProcessStreamInfo(ProcessStreamInfo):
    print_depth: typing.ClassVar[int] = 2


@dataclasses.dataclass(repr=False)
class StreamObjInfo(DataContext):
    obj_num: int = None


class ProcessContentsFrame(MutoolPTFrame):
    sig_id_name = "PROCESS_CONTENTS"
    flag_addr_fn_name = "pdf_process_contents"
    remove_when_flagged = False

    def __init__(self, sig, pt=None, pt_tracking_sigs=None):
        sigs = set([self.manager.sig_from_id(i) for i in
                    [SigID.PROCESS_STREAM, SigID.OPEN_CONTENTS_STREAM]])
        if pt_tracking_sigs is not None:
            sigs |= pt_tracking_sigs
        pt = PT(PDFEnum.CONTAINER)
        pt.add_context(ParseReason.create(self))
        pt.add_context(StreamObjInfo())
        super().__init__(sig, pt=pt, pt_tracking_sigs=sigs)

    def register_stream_object_num(self, num, reg_obj):
        self.pt.get_context(StreamObjInfo).obj_num = num

    def register_pt_node(self, obj, reg_obj):
        # this is called by any stack frame
        if isinstance(reg_obj, CacheObjectFrame) or \
           isinstance(reg_obj, RepairXRefFrame):
            obj.add_context(ParseReason.create(self, self.pt.index))
            self.do_register_pt(obj, True)
        else:
            self.pt.add_child(obj)


@dataclasses.dataclass(repr=False)
class FetchXRefInfo(DataContext):
    num: int
    cached: bool = True
    exception: bool = False


class CacheObjectFrame(MutoolPTFrame):
    sig_id_name = "CACHE_OBJ"
    flag_addr_fn_name = "pdf_cache_object"
    remove_when_flagged = False

    def __init__(self, sig, pt=None, pt_tracking_sigs=None):
        sigs = set([self.manager.sig_from_id(i) for i in
                    [SigID.CACHE_NUM]])
        self.num = None
        self.exception = False
        self.obj_parsed = False
        if pt_tracking_sigs is not None:
            sigs |= pt_tracking_sigs
        pt = PT(PDFEnum.INDIRECT_OBJ)
        pt.add_context(ParseReason.create(self))
        super().__init__(sig, pt, pt_tracking_sigs=sigs)

    def register_exception(self, entry, sig):
        self.exception = True
        super().register_exception(entry, sig)

    def register_xref_num(self, num, from_obj):
        self.num = num

    def register_pt_node(self, obj, from_obj):
        self.obj_parsed = True
        self.add_pt_child(obj)

    def on_pop(self, new_top):
        if self.num is not None:
            self.pt.add_context(FetchXRefInfo(self.num,
                                              not self.obj_parsed,
                                              self.exception))
        if self.pt:
            self.do_register_pt(self.pt)
        super().on_pop(new_top)
        top = self.manager.stack_top(MutoolPTFrame)
        if top:
            top.register_fetch(self.pt, self)


class CacheObjectNum(MutoolMomentSig):
    sig_id_name = "CACHE_NUM"
    flag_addr_name = "pdf_cache_obj_num"
    log_type = MemEntry
    attr_name = "pc"
    parent_frame_class = CacheObjectFrame
    struct_format = "l"
    remove_when_flagged = False

    def flag(self):
        self.parent_frame.register_xref_num(
            self.unpack_val(self.flagged_entry.value), self
        )


@dataclasses.dataclass(repr=False)
class StreamArgInfo(DataContext):
    used: bool = False


@dataclasses.dataclass(repr=False)
class StreamOpInfo(DataContext):
    args_idx: typing.List[int] = dataclasses.field(default_factory=list)
    stack_idx: typing.List[int] = dataclasses.field(default_factory=list)
    name_idx: int = None
    string_idx: int = None
    obj_idx: int = None
    executed: bool = True
    img_idx: int = None
    exception_occurred: bool = False
    hail_mary_font: bool = False
    fetched_idx: typing.List[int] = dataclasses.field(default_factory=list)
    print_depth: typing.ClassVar[int] = 2

    @classmethod
    def create_from_exec(cls, array, stack, name, string, obj):
        nidx = name.index if name else None
        sidx = string.index if string else None
        oidx = obj.index if obj else None
        for a in array + stack:
            a.get_context(StreamArgInfo).used = False
        return cls([a.index for a in array], [s.index for s in stack],
                   nidx, sidx, oidx, True)

    def set_img(self, img):
        self.img_idx = img.index

    def merge(self, other):
        super().merge(other)
        # always overrive "executed"
        self.executed = other.executed


@dataclasses.dataclass(repr=False)
class ContentsStreamInfo(DataContext):
    stmobj_idx: int = None


class OpenContentsFrame(MutoolPTFrame):
    sig_id_name = "OPEN_CONTENTS_STREAM"
    flag_addr_fn_name = "pdf_open_contents_stream"
    remove_when_flagged = False

    def __init__(self, sig, pt=None, pt_tracking_sigs=None):
        sigs = set([self.manager.sig_from_id(i)
                    for i in [SigID.PROCESS_STREAM_NUM]])
        if pt_tracking_sigs is not None:
            sigs |= pt_tracking_sigs
        self._register_pt = True
        self.num = None
        super().__init__(sig, pt_tracking_sigs=sigs)

    def register_num(self, num):
        # may be called by ProcessStreamNum sig
        if self.num is not None:
            self.OOPS("num registered twice:", num, "was:", self.num)
        self.num = num

    def on_pop(self, new_top):
        super().on_pop(new_top)
        top = self.manager.stack_top(ProcessContentsFrame)
        if top and self.num is not None:
            top.register_stream_object_num(self.num, self)

    def register_pt_node(self, child, reg_obj):
        # ignore all object registration, but save
        # objects registered by PARSE_IND_OBJ
        top = self.manager.stack_top(ProcessContentsFrame)
        if isinstance(reg_obj, CacheObjectFrame) or \
           isinstance(reg_obj, RepairXRefFrame) and top:
            # pass to parent frame to handle so it can set ParseReason
            top.register_pt_node(child, reg_obj)
        else:
            self.OOPS(self, "don't know how to handle ",
                      "register obj from", reg_obj, child)


class ProcessStreamFrame(MutoolPTFrame):
    sig_id_name = "PROCESS_STREAM"
    flag_addr_fn_name = "pdf_process_stream"
    remove_when_flagged = False
    # in_text_array: pdf_array_push_{real,int,string}, pdf_array_delete
    # else: parse_array, parse_dict, new_name, new_string

    @classmethod
    def setup(cls):
        # cls.drop_args = cls.addrs_of("process_stream_drop_args")
        cls.set_args = cls.addrs_of("process_stream_set_args")
        cls.parse_inline_img = Version.get_fn_abs_addr("parse_inline_image")

    def last_op(self):
        last = self.pt.get_last_child()
        if last and last.type == PDFEnum.KEYWORD:
            return last

    def register_exception(self, exception_info, sig):
        # this is called by ThrowException signature
        self.exception_info = exception_info
        self.exception_sig = sig
        last = self.last_op()
        if last:
            last.get_context(StreamOpInfo).exception_occurred = True
        self.OOPS("this is untested", exception_info, sig)

    def register_token(self, tok, pc, reg_obj):
        if tok.type is TokEnum.KEYWORD:
            tok.add_context(StreamOpInfo(executed=False))
        self.last_token = tok
        self.pt.add_child(tok.to_pt())

    def register_new_object(self, obj, pc, sig):
        if len(self.manager.ml.stack.stack) < 2 or \
           self.manager.ml.stack.stack[-2] != self.callstackentry:
            # only continue if the object registered by a signal
            # invoked by a directly invoked function
            return
        if obj and obj.type not in [PDFEnum.REAL,
                                    PDFEnum.INT,
                                    PDFEnum.String,
                                    PDFEnum.NAME,
                                    PDFEnum.KEYWORD]:
            obj.merge_taint(self.last_token)
        if self.manager.ml.stack.top().pc in self.set_args:
            obj = self.do_obj_check(obj, sig)
            self.arg_obj = obj
        else:
            self.OOPS("Unknown REG NEW OBJ", sig, obj,
                      self.manager.ml.stack.get_idx(-1),
                      self.callstackentry, self.callstackentry_idx,
                      len(self.manager.ml.stack.stack))
        self.pt.add_child(obj)

    def register_pt_node(self, obj, reg_obj):
        pc = reg_obj.callstackentry.pc
        if not obj:
            return
        if pc in self.set_args:
            self.arg_obj = self.do_pt_check(obj, reg_obj)
        elif self.manager.ml.stack.top().target_pc in self.parse_inline_img:
            bi = self.last_op()  # this should be a BI operation
            if bi is None:
                self.OOPS("parse_inline_img was called when processing",
                          "a keyword but no operation was just executed")
            bi.get_context(StreamOpInfo).set_img(obj)
        else:
            last = self.last_op()
            # reason is last operation if there is one
            reg = last if last else self.pt
            obj.add_context(ParseReason.create(self, reg.index))
            if last:
                # also let operation know that an object was fetched
                # while it was being serviced
                last.get_context(StreamOpInfo).fetched_idx.append(obj.index)
        if isinstance(reg_obj, CacheObjectFrame) or \
           isinstance(reg_obj, ProcessContentsFrame):
            self.do_register_pt(obj, True)
        else:
            if pc in self.set_args or \
               self.manager.ml.stack.top().target_pc in self.parse_inline_img:
                self.pt.add_child(obj)
            else:
                self.OOPS("Unknown REG OBJ", reg_obj, obj,
                          pc not in self.parse_inline_img)

    def register_exec_op(self, sig):
        last = self.last_op()
        if last is None:
            self.OOPS("Executing a stream operation, but did not find any pt",
                      "nodes that indicate what operation is being executed")
        last.add_context(StreamOpInfo.create_from_exec(self.arg_array,
                                                       self.arg_stack,
                                                       self.arg_name,
                                                       self.arg_string,
                                                       self.arg_obj))
        self.pt.get_context(MuProcessStreamInfo).ops_idx.append(last.index)

    def register_nested_exception(self, sig):
        # register_exception only called on this frame if exception
        # causes this frame to be popped.  STREAM_EVENTS sig will call
        # this if there is any nested call to throw
        last = self.last_op()
        if last:
            last.get_context(StreamOpInfo).exception_occurred = True

    def register_push_args(self, sig):
        # only append to arg array if directly called by pdf_process_stream
        if self.callstackentry == self.manager.ml.stack.get_idx(-2):
            self.last_token.add_context(StreamArgInfo())
            self.arg_array.append(self.last_token)

    def register_push_stack(self, sig):
        self.last_token.add_context(StreamArgInfo())
        self.arg_stack.append(self.last_token)

    def register_arg_string(self, sig):
        self.last_token.add_context(StreamArgInfo())
        self.arg_string = self.last_token

    def register_arg_pop(self, sig):
        print("array-pop0", self.arg_array, self.arg_stack)
        self.arg_stack[0] = self.arg_array[-1]
        self.arg_array = self.arg_array[:-1]
        print("array-pop1", self.arg_array, self.arg_stack)
        self.OOPS("untested", self.last_token)

    def register_drop_args(self, sig):
        self.arg_array = []
        self.arg_obj = None

    def register_hail_mary_font(self, sig):
        # if directly called or called from called fn
        if self.callstackentry in [self.manager.ml.stack.get_idx(-3),
                                   self.manager.ml.stack.get_idx(-4)]:
            last = self.last_op()
            if last:
                last.get_context(StreamOpInfo).hail_mary_font = True

    def register_set_name(self, sig):
        self.last_token.add_context(StreamArgInfo())
        self.arg_name = self.last_token

    def register_set_string(self, sig):
        self.last_token.add_context(StreamArgInfo())
        self.arg_string = self.last_token

    def register_clear_stack(self, sig):
        self.arg_stack = []
        self.arg_array = []
        self.arg_string = None
        self.arg_name = None
        self.arg_obj = None

    def debug_string(self):
        return super().debug_string() + "\n" + \
            f"arg_obj: {self.arg_obj}, arg_stack: {self.arg_stack}," + \
            f"arg_string: {self.arg_string}, arg_name: {self.arg_name}," + \
            f"arg_array: {self.arg_array}, last_token: {self.last_token}"

    def on_pop(self, new_top):
        super().on_pop(new_top)
        if self.manager.print_image_ops:
            print("Image operations at ",
                  self.manager.ml.stack.detail_string(),
                  file=self.manager.output_stream)
            for op in self.pt.get_context(MuProcessStreamInfo).ops():
                print("exec op", op, file=self.manager.output_stream)

    def register_fetch(self, obj, fetch_frame):
        last_child = self.pt.get_last_child()
        if last_child:
            reason = obj.get_context(ParseReason)
            reason.requester_pt_idx = last_child.index

    def __init__(self, sig):
        self._register_pt = True
        self.arg_stack = []
        self.arg_array = []
        self.arg_string = None
        self.arg_name = None
        self.arg_obj = None
        sigs = set([self.manager.sig_from_id(i) for i in
                    [SigID.STREAM_EVENTS]])
        pt = PT(PDFEnum.STREAM)
        pt.add_context(MuProcessStreamInfo())
        super().__init__(sig, pt=pt, pt_tracking_sigs=sigs)


class ParseIndObjFrame(MutoolPTFrame):
    add_child_on_pop = False
    sig_id_name = "PARSE_IND_OBJ"
    flag_addr_fn_name = "pdf_parse_ind_obj"
    PDF_MAX_NUM = 8388607
    remove_when_flagged = False

    class LexID(IntEnum):
        OBJ_NUM = 0
        OBJ_GEN = auto()
        OBJ_KEYWORD = auto()
        OBJ = auto()
        INT_0 = auto()
        INT_1 = auto()
        TRY_STREAM = auto()

    lexid_type = {
        LexID.OBJ_NUM: [TokEnum.INT],
        LexID.OBJ_GEN: [TokEnum.INT],
        LexID.OBJ_KEYWORD: [TokEnum.KEYWORD],
        LexID.OBJ: [TokEnum.OPEN_ARRAY, TokEnum.OPEN_DICT, TokEnum.NAME,
                    TokEnum.REAL, TokEnum.ENDOBJ, TokEnum.STRING,
                    TokEnum.ENDOBJ,
                    TokEnum.TRUE, TokEnum.FALSE, TokEnum.NULL, TokEnum.INT],
        LexID.INT_0: [TokEnum.STREAM, TokEnum.ENDOBJ, TokEnum.INT],
        LexID.INT_1: [TokEnum.R],
    }
    lexid_containers = {
        LexID.OBJ: PDFEnum.CONTAINER
    }

    def __init__(self, sig):
        self.tokens = []
        self.exception_expected = False
        self.obj_added = False
        self.done = False
        self.int_a = None
        self.int_b = None
        self.last_token = None
        self.try_repair = False
        pt = PT(PDFEnum.INDIRECT_OBJ)
        pt.add_context(ParseReason.create(self))
        super().__init__(sig, pt=pt)

    def register_token(self, tok, pc, reg_obj):
        if self.done:
            self.OOPS("Object parsing should be finished, but another token",
                      f"was registered {tok} by %x" %
                      (pc - self.flagged_signature.lib_start),
                      "regisered by", reg_obj)
        try:
            self.lex_addrs.index(pc)
        except Exception:
            self.OOPS("not sure how to handle token", tok, "registred"
                      "by", reg_obj,
                      "%x" % pc, "%x" % (pc - self.flagged_signature.lib_start),)

        lex_id = self.LexID(self.lex_addrs.index(pc))
        if (lex_id <= self.LexID.INT_1) and len(self.tokens) != (lex_id):
            self.OOPS(f"Expected {lex_id} tokens to be registered but found",
                      f"{len(self.tokens)}, tokens: {self.tokens}")
        elif (lex_id > self.LexID.INT_1) and len(self.tokens) <= self.LexID.OBJ:
            self.OOPS(f"Expected at most {self.LexID.OBJ} tokens to be ",
                      f"registered but found {len(self.tokens)},",
                      f"tokens: {self.tokens}", "registered by",
                      reg_obj)

        if (lex_id in [self.LexID.OBJ_NUM, self.LexID.OBJ_GEN] and
            tok.type != self.lexid_type[lex_id]) or \
            (lex_id == self.LexID.OBJ and tok.type != self.lexid_type[lex_id]):
            self.try_repair = True

        container = self.lexid_containers.get(lex_id)
        if lex_id == self.LexID.OBJ and tok.type == TokEnum.ENDOBJ:
            tok.type = TokEnum.NULL
        if lex_id > self.LexID.INT_1 and not self.obj_added:
            self.OOPS("Expected an object to be added by now,",
                      f"lex_id: {lex_id}",
                      f"tokens: {self.tokens}")
        if lex_id == self.LexID.OBJ and \
           tok.type in [TokEnum.TRUE, TokEnum.FALSE, TokEnum.NULL,
                        TokEnum.ENDOBJ, TokEnum.STREAM]:
            tok_pt = tok.to_pt()
            pt = PT(container, children=[tok_pt]) if container else tok_pt
            self.ad.add_child(pt)
            self.obj_added = True
        if lex_id in [self.LexID.INT_0, self.LexID.INT_1]:
            if not self.last_token.type == TokEnum.INT or \
               self.int_a is not None:
                self.OOPS(f"Expected int_a to be None but is {self.int_a}")
            if lex_id == self.LexID.INT_0:
                self.int_a = self.last_token
            else:
                if self.int_a is not None:
                    self.OOPS(f"Expected int_a to be None but is {self.int_a}")
                self.int_b = self.last_token
        if lex_id in [self.LexID.OBJ_GEN, self.LexID.OBJ_KEYWORD,
                      self.LexID.OBJ]:
            self.pt.add_child(self.last_token.to_pt())
        if (lex_id in [self.LexID.OBJ, self.LexID.INT_0, self.LexID.TRY_STREAM]
           and tok.type is TokEnum.ENDOBJ) or \
           lex_id is self.LexID.TRY_STREAM and tok.type is TokEnum.STREAM:
            self.pt.add_child(tok.to_pt())
        self.tokens.append(tok)

    @property
    def last_token(self):
        if self.tokens:
            return self.tokens[-1]

    @last_token.setter
    def last_token(self, tok):
        pass

    def register_pt_node(self, obj, reg_obj):
        if len(self.pt.children) <= self.LexID.OBJ_KEYWORD and \
           self.obj_added:
            self.OOPS("We expected more pt children to be in place at sig",
                      f"{reg_obj} while registering object: {obj}. pt is:",
                      str(self.pt))
        if not self.last_token:
            self.OOPS("No token currently registered, don't know",
                      "how to create new object", "registered by:",
                      reg_obj, "registering", obj)
        self.obj_added = True
        self.pt.add_child(self.do_pt_check(obj, reg_obj))
        # self.register_new_object(obj, pc, reg_obj.flagged_signature)
        # self.do_pt_check(obj, reg_obj)

    def register_new_object(self, obj, pc, sig):
        if not self.last_token:
            self.OOPS("No token currently registered, don't know",
                      "how to create new object", "called by: %x" %
                      (pc - sig.lib_start), sig,
                      "registering", obj)
        if len(self.pt.children) <= self.LexID.OBJ_KEYWORD and \
           self.obj_added:
            self.OOPS("We expected more pt children to be in place at sig",
                      f"{sig} while registering object: {obj}. pt is:",
                      str(self.pt))

        if sig.sig_id_val in [SigID.NEW_INT,
                              SigID.NEW_REFERENCE]:
            if self.int_a is None or self.int_a.type != TokEnum.INT:
                self.OOPS(f"int_a isn't an int. int_a: {self.int_a}",
                          f"registered by {sig}, obj: {obj}")
            if sig.sig_id_val == SigID.NEW_INT:
                if self.last_token.type not in [TokEnum.STREAM, TokEnum.ENDOBJ]:
                    self.OOPS(f"With signture {sig} expected last token type",
                              "to be STREAM or ENDOBJ, instead is",
                              str(self.last_token))
                obj = self.do_obj_check(obj, sig, self.int_a)
                # obj is from self.int_a
            else:
                obj = self.do_obj_check(obj, sig, [self.int_a,
                                                   self.int_b,
                                                   self.last_token])
                # obj is from self.int_a, self.int_b, self.last_token
        elif sig.sig_id_val in [SigID.NEW_STRING, SigID.NEW_NAME]:
            obj = self.do_obj_check(obj, sig)
        self.obj_added = True
        self.pt.add_child(obj)

    def register_exception(self, entry, sig):
        self.done = True
        super().register_exception(entry, sig)

    @classmethod
    def setup(cls):
        cls.lex_addrs = cls.addrs_of("parse_ind_obj_lex")


class ParseStmObjFrame(MutoolPTFrame):
    sig_id_name = "PARSE_STM_OBJ"
    flag_addr_fn_name = "pdf_parse_stm_obj"
    remove_when_flagged = False
    add_child_on_pop = False

    def __init__(self, sig):
        self.obj = None
        pt = PT(PDFEnum.STREAM)
        pt.add_context(ParseReason.create(self))
        super().__init__(sig, PT(PDFEnum.STREAM))

    def register_token(self, tok, pc, reg_obj):
        self.last_token = tok
        if self.last_token.type in [TokEnum.TRUE, TokEnum.FALSE, TokEnum.NULL]:
            self.obj = tok.to_pt()

    def register_pt_node(self, obj, reg_obj):
        if isinstance(reg_obj, ParseArrayFrame) or \
           isinstance(reg_obj, ParseDictFrame):
            ok = self.last_token is not None and self.obj is None
            if ok:
                if (isinstance(reg_obj, ParseDictFrame) and
                    self.last_token.type != TokEnum.OPEN_DICT and
                    obj.type != PDFEnum.DICT) or \
                    (isinstance(reg_obj, ParseArrayFrame) and
                     self.last_token.type != TokEnum.OPEN_ARRAY and
                     obj.type != PDFEnum.ARRAY):
                    ok = False
            if not ok:
                self.OOPS("Last token's type does not match that of",
                          f"registering object's {reg_obj},",
                          f"is {self.last_token},",
                          f"obj {obj}, or self.last_token is None.",
                          f"last_token: {self.last_token}, ",
                          f"or self.obj ({self.obj}) is not None")
            obj._children = [self.last_token.to_pt()] + obj.children
            self.obj = obj
        else:
            self.OOPS("Not expecting any other type of frame to call",
                      "register_object, but it was called by", reg_obj,
                      "to register obj", obj, ".")

    def register_new_object(self, obj, pc, sig):
        if self.obj is not None:
            self.OOPS(f"{sig} registered obj {obj}, expected",
                      "self.obj to be None but is instead:", self.obj,
                      "with self.last_token:", self.last_token)
        self.obj = self.do_obj_check(obj, sig)

    def on_pop(self, new_top):
        if self.last_token is None:
            self.OOPS("Expected last_token to not be None")
        if self.last_token.type in [TokEnum.TRUE, TokEnum.FALSE, TokEnum.NULL,
                                    TokEnum.OPEN_ARRAY, TokEnum.OPEN_DICT,
                                    TokEnum.NAME, TokEnum.REAL, TokEnum.STRING,
                                    TokEnum.INT]:
            if self.obj is None:
                self.OOPS("Expected self.obj to not be None given",
                          f"last_token: {self.last_token}, self.obj:",
                          f"{self.obj}")
            self.pt.add_child(self.obj)
        super().on_pop(new_top)


class ParseDictFrame(MutoolPTFrame):
    sig_id_name = "PARSE_DICT"
    flag_addr_fn_name = "pdf_parse_dict"
    _additional_newobj_check = {
        "DICT_NEW_KEY": (TokEnum.NAME, None, None),
        "DICT_INT_NULL": (None, None, PT(PDFEnum.NULL)),
    }

    def __init__(self, sig):
        # dict_new_key, dict_lex_key, dict_lex_value, dict_put_int,
        # dict_lex_int (0-1), dict_int_null (0-1), dict_new_value,
        # dict_new_value_error
        self.key_obj = None
        self.value_obj = None
        self.done = False
        self.int_a = None
        self.int_b = None
        self.dict_end = None
        sigs = set([self.manager.sig_from_id(s) for s in
                    [SigID.DICT_INT_NULL, SigID.DICT_PUT,
                     SigID.DICT_CHECK_END, SigID.DICT_NEW_KEY]])
        # sigs.add(self.manager.sig_from_id(SigID.CALL_TRACE))
        pt = PT(PDFEnum.DICT)
        if not self.manager.stack_top():
            pt.add_context(ParseReason.create(self))
        super().__init__(sig, pt, pt_tracking_sigs=sigs)

    @classmethod
    def setup(cls):
        cls.lex_addrs = []
        for i in ["dict_lex_key", "dict_lex_value", "dict_lex_int"]:
            cls.lex_addrs += cls.addrs_of(i)
        cls.lex_int = cls.lex_addrs[-2:]

        cls.new_key_addr = cls.addrs_of("dict_key", 1)
        cls.new_value_addr = cls.addrs_of("dict_val", 1)
        cls.dict_int_null = cls.addrs_of("dict_int_null")
        cls.new_indirect = cls.addrs_of("new_indirect", 1)

    def debug_string(self):
        return f"{self}, key_obj: {self.key_obj}, value_obj:" + \
            f"{self.value_obj}, int_a: {self.int_a}, " + \
            f"int_b: {self.int_b}, last_token: {self.last_token}, " + \
            f"done: {self.done}, exception_info: {self.exception_info}"

    def register_exception(self, entry, sig):
        self.done = True
        super().register_exception(entry, sig)

    def register_token(self, tok, pc, reg_obj):

        if self.done:
            self.OOPS("We should be done, didn't expect another token",
                      f"to be registered: {tok}, by %x" % pc)
        if pc == self.lex_int[0]:
            self.int_a = self.last_token
        elif pc == self.lex_int[1]:  # parsing another int
            self.int_b = self.last_token
        if pc == self.lex_addrs[0] and (tok.type == TokEnum.CLOSE_DICT or
                                        (tok.type == TokEnum.KEYWORD and
                                         tok.value == "ID")):

            # we should be done
            self.done = True
        super().register_token(tok, pc, reg_obj)
        if pc == self.lex_addrs[0]:
            # the DICT_CHECK_END signature will not get flagged if
            # this is the case (b/c the DICT_CHECK_END will not appear
            # to be at the beginning of a basic block, DICT_CHECK_END
            # only gets fired if "goto skip" is used, which skips this
            # particulare pdf_lex call
            self.register_dict_check_end()

    def register_pt_node(self, obj, reg_obj):
        if self.done or self.last_token is None:
            self.OOPS("Either we are done or last_token is None",
                      f"Registered by: {reg_obj}, ",
                      f"obj: {obj}")
        self.value_obj = self.do_pt_check(obj, reg_obj)

    def register_new_object(self, obj, pc, sig):
        if len(self.manager.ml.stack.stack) < 2 or \
           self.manager.ml.stack.stack[-2] != self.callstackentry:
            # only continue if the object registered by a signal
            # invoked by a directly invoked function
            return

        if self.done or self.last_token is None:
            self.OOPS("Either we are done or last_token is None",
                      "From sig: {sig}, at pc %x," % (sig.lib_start - pc),
                      f"obj: {obj}")
        if sig.sig_id_val == SigID.DICT_NEW_KEY:
            if self.key_obj is not None:
                self.OOPS("Expected self.key_obj to be None but is",
                          f"from sig: {sig}, at pc %x," % (sig.lib_start - pc),
                          f"obj: {obj}")
            self.key_obj = self.do_obj_check(obj, sig)
        elif sig.sig_id_val == SigID.NEW_INT:
            self.value_obj = self.do_obj_check(obj, sig, self.int_a)
        elif sig.sig_id_val == SigID.NEW_REFERENCE:
            self.value_obj = self.do_obj_check(obj, sig, [self.int_a,
                                                          self.int_b,
                                                          self.last_token])
        else:
            self.value_obj = self.do_obj_check(obj, sig)

    def register_dict_put(self, pc):
        # called by DictPut signature
        # added key pair to dict
        if self.done:
            self.OOPS("We are done but a dict_put was registered",
                      "at pc %x" % pc)

        vals = [self.last_token, self.key_obj, self.value_obj]
        if any([k is None for k in vals]):
            self.OOPS("Neither last_token or key_obj should be none",
                      "when dict_put called at pc %x" % pc, vals)
        self.pt.add_child(PT(PDFEnum.DICT_KEY,
                             children=[self.key_obj]))
        self.pt.add_child(PT(PDFEnum.DICT_VALUE,
                             children=[self.value_obj]))
        self.key_obj = None
        self.value_obj = None

    def register_dict_check_end(self):
        # this may be called by self or by DictCheckEnd signature
        if self.last_token.type == TokEnum.CLOSE_DICT:
            self.done = True
            self.pt.add_child(self.last_token.to_pt())
        elif (self.last_token.type == TokEnum.KEYWORD and
              self.last_token.value == b"ID") or \
              self.last_token.type != TokEnum.NAME:
            self.done = True


class ParseArrayFrame(MutoolPTFrame):
    sig_id_name = "PARSE_ARRAY"
    flag_addr_fn_name = "pdf_parse_array"

    _additional_newobj_check = {
        "ARRAY_INT_A": (TokEnum.INT, None, None),
        "ARRAY_INT_B": (TokEnum.INT, None, None),
        "ARRAY_PUSH_STRING": (TokEnum.STRING, PDFEnum.STRING, None),
        "ARRAY_PUSH_NAME": (TokEnum.NAME, None, None),
        "ARRAY_PUSH_REAL": (TokEnum.REAL, PDFEnum.REAL, None),
        "ARRAY_PUSH_INT": (None, PDFEnum.INT, None),
        "ARRAY_PUSH_BOOL": ([TokEnum.TRUE, TokEnum.FALSE], None, None),
        "ARRAY_PUSH_DROP": ([TokEnum.OPEN_ARRAY, TokEnum.OPEN_DICT,
                             TokEnum.R], None, None)
    }

    def __init__(self, sig):
        # lex = self.manager.sig_from_id(SigID.LEX_TOK)
        # also need to track:
        # pdf_array_push -> NULL
        # pdf_array_push_bool -> true/false (depending on tok)
        # pdf_array_push_real -> REAL
        # pdf_array_push_name -> NAME
        # pdf_array_push_string > STRING
        # array_push_drop (0-2, depending on dict, array, REF)
        sigs = [self.manager.sig_from_id(s) for s in
                [SigID.ARRAY_PUSH_INT, SigID.ARRAY_PUSH,
                 SigID.ARRAY_PUSH_REAL, SigID.ARRAY_PUSH_BOOL,
                 SigID.ARRAY_PUSH_STRING, SigID.ARRAY_PUSH_NAME,
                 SigID.ARRAY_PUSH_DROP, SigID.ARRAY_INT_A,
                 SigID.ARRAY_INT_B, SigID.ARRAY_CATCH]]
        self.obj = None
        self.int_a = None
        self.int_b = None
        self.int_n = 0
        self.done = False
        pt = PT(PDFEnum.ARRAY)
        if not self.manager.stack_top():
            pt.add_context(ParseReason.create(self))
        super().__init__(sig, pt, pt_tracking_sigs=set(sigs))

    def debug_string(self):
        try_stack = self.manager.signatures.active_sigs_by_id(
            SigID.THROW_EXCEPTION
        )[0].try_stack
        return f"{self}, self.obj: {self.obj}, int_n: {self.int_n}," + \
            f"int_a: {self.int_a}, " + \
            f"int_b: {self.int_b}, last_token: {self.last_token}, " + \
            f"done: {self.done}, nested_call: {self.get_nested_call()} " + \
            f"exception_info: {self.exception_info}, {try_stack}"

    @classmethod
    def setup(cls):
        cls.push_int_addrs = cls.addrs_of("array_push_int")
        cls.push_bool_addrs = cls.addrs_of("array_push_bool")
        cls.push_addrs = cls.addrs_of("array_push")
        cls.push_drop_addrs = cls.addrs_of("array_push_drop")
        cls.int_a_addr = cls.addrs_of("array_int_a", 1)
        cls.int_b_addr = cls.addrs_of("array_int_b", 1)

    def register_exception(self, entry, sig):
        self.done = True
        super().register_exception(entry, sig)

    def register_token(self, tok, pc, reg_obj):
        super().register_token(tok, pc, reg_obj)
        if tok.type == TokEnum.CLOSE_ARRAY and self.int_n == 0:
            self.pt.add_child(tok.to_pt())
            self.done = True

    def get_nested_call(self):
        last = None
        for i in list(range(len(self.manager.ml.stack.stack)))[::-1]:
            entry = self.manager.ml.stack.stack[i]
            if id(entry) == id(self.callstackentry):
                return last
            last = entry

    def register_push(self, pc, sig):
        # called by ArrayPushSig signature
        if self.last_token is None or (self.done and self.int_n == 0):
            self.OOPS(f"Push registered by {sig} but either last_token",
                      "or not expecting any more pushes")
        self.do_obj_check(self.obj, sig)
        entry = None
        if sig.sig_id_val == SigID.ARRAY_PUSH:
            entry = PT(PDFEnum.NULL)
        elif sig.sig_id_val == SigID.ARRAY_PUSH_BOOL:
            entry = self.last_token.to_pt()
        elif sig.sig_id_val == SigID.ARRAY_PUSH_DROP:
            if (pc == self.push_drop_addrs[0] and
               self.obj.type != PDFEnum.REF) or \
               (pc == self.push_drop_addrs[1] and
                self.obj.type != PDFEnum.ARRAY) or \
                (pc == self.push_drop_addrs[2] and
                 self.obj.type != PDFEnum.DICT):
                self.OOPS(f"Current obj doesn't match what signature {sig}",
                          "expects")
            entry = self.obj
        else:
            entry = self.obj
        self.pt.add_child(PT(PDFEnum.ARRAY_ENTRY,
                             children=[entry]))
        self.obj = None

    def register_pt_node(self, obj, reg_obj):
        if self.done or self.last_token is None:
            self.OOPS("Either we are done or last_token is None",
                      f"Registered by: {reg_obj}, ",
                      f"obj: {obj}")
        elif self.obj is not None:
            self.OOPS("When registering object, expected self.obj to be",
                      f"None reg_obj: {reg_obj}, registered {obj}")
        else:
            self.obj = self.do_pt_check(obj, reg_obj)

    def register_new_object(self, obj, pc, sig):
        if sig.sig_id_val not in [SigID.ARRAY_INT_B, SigID.NEW_INT,
                                  SigID.ARRAY_INT_A] and \
           self.obj is not None:
            self.OOPS("When registering object, expected self.obj to be None",
                      f"sig: {sig}, registered, {obj} at pc %x" %
                      (pc - sig.lib_start), self.last_token)
        if sig.sig_id_val in [SigID.NEW_STRING, SigID.NEW_NAME,
                              SigID.NEW_REAL]:
            self.obj = self.do_obj_check(obj, sig)
        elif sig.sig_id_val == SigID.NEW_INT:
            call = self.get_nested_call()
            if call.pc == self.push_int_addrs[0]:
                self.obj = self.int_a.to_pt()
                self.int_n = 0
            elif call.pc == self.push_int_addrs[1]:
                self.obj = self.int_b.to_pt()
                self.int_n = 0
            elif call.pc == self.push_int_addrs[2]:
                self.obj = self.int_a.to_pt()
                self.int_a = self.int_b
                self.int_n -= 1
        elif sig.sig_id_val in [SigID.ARRAY_INT_A,
                                SigID.ARRAY_INT_B]:
            self.do_obj_check(obj, sig, tok=self.last_token)
            if self.int_n > 2:
                self.OOPS(f"Obj registered by {sig} at pc %x" %
                          (pc - sig.lib_start), "int_n should ",
                          "not be > 2.")
            self.int_n += 1
            if sig.sig_id_val == SigID.ARRAY_INT_A:
                self.int_a = self.last_token
            else:
                self.int_b = self.last_token
        elif sig.sig_id_val == SigID.NEW_REFERENCE:
            if self.int_n != 2:
                self.OOPS(f"Obj registered by {sig} at pc %x" %
                          (pc - sig.lib_start), "int_n should ",
                          "be == 2, and int_a and int_b should not",
                          "be None")
            self.obj = self.do_obj_check(obj, sig, [self.int_a,
                                                    self.int_b,
                                                    self.last_token])
            self.int_n = 0
        else:
            self.OOPS(f"Obj registered by {sig} at pc %x" %
                      (pc - sig.lib_start), "something unexpected happened")


class TokTypeFrame(MutoolFrame):
    pt_sig_ids = []
    initial_token_type = None
    initial_token_value = None

    def __init__(self, sig, pt_tracking_sigs=None):
        self.token_value = self.initial_token_value
        self.token_type = self.initial_token_type
        self.bytes = b""
        self.multibytes = []
        self.taint = it.IntervalTree()
        self.first_taint = None
        sigs = pt_tracking_sigs if pt_tracking_sigs else set()
        sigs.update([self.manager.sig_from_id(getattr(SigID, i))
                     for i in self.pt_sig_ids])
        super().__init__(sig, pt_tracking_sigs=sigs)

    def debug_string(self):
        s = ", ".join(f"{k}: {getattr(self, k)}"
                      for k in ["initial_token_value",
                                "token_value",
                                "initial_token_type",
                                "token_type",
                                "bytes", "multibytes", "first_taint"])

        return f"{self}: {s}"

    def register_token_parts(self, typ, val, from_obj):
        # may be called by TokTypeFrame or LexTokValSig
        if typ is not None:
            if self.token_type != self.initial_token_type and \
               typ != self.token_type:
                self.OOPS("Registered type does not match expectation or",
                          f"registered type changed: type: {typ},",
                          f" val: {val}, from obj: {from_obj}",
                          f"expected {self.token_type}/"
                          f"{self.initial_token_type}")
            self.token_type = typ
        if val is not None:
            if self.token_value != self.initial_token_value and \
               val != self.token_value:
                self.OOPS("Registered balue does not match expectation or",
                          f"registered value changed: type: {typ},",
                          f" val: {val}, from obj: {from_obj}",
                          f"expected {self.token_value}/"
                          f"{self.initial_token_value}")
            if isinstance(self.token_value, str) or \
               isinstance(self.token_value, bytes):
                self.token_value += val
            else:
                self.token_value = val

    def register_lex_byte(self, byte):
        # may be called by TokTypeFrame, LexByteFrame
        self.bytes += byte

    def register_lex_multi_bytes(self, byte):
        # may be called by LexByteFrame
        self.multibytes.append(byte)

    def register_taint(self, taint, first_taint):
        # may be called by TokTypeFrame, LexByteFrame
        self.taint |= taint
        if self.first_taint is not None:
            self.first_taint = first_taint

    def on_pop(self, new_top, set_parent=True):
        super().on_pop(new_top)
        top = self.manager.stack_top(TokTypeFrame)
        if top and set_parent:
            if self.token_type is None and \
               self.token_value is None:
                self.OOPS("token_type and token_value should not both be None")
            top.register_token_parts(self.token_type, self.token_value, self)
            top.register_taint(self.taint, self.first_taint)
            for b in self.bytes:
                top.register_lex_byte(b)


class LexTokFrame(TokTypeFrame):
    sig_id_name = "LEX_TOK"
    flag_addr_fn_name = "pdf_lex"
    remove_when_flagged = False

    # EOF -> 547
    # NAME -> (lex_name and not pdf_token_from_keyword called) / 556
    # ERROR -> 560, 574
    # OPEN_DICT -> 564
    # CLOSE_DICT -> 571
    # OPEN_ARRAY -> 576
    # CLOSE_ARRAY -> 578
    # OPEN_BRACE -> 580
    # CLOSE_BRACE -> 582

    # or values returned by calls at: 558 (lex_string), 567
    # (lex_hex_string), 584 (lex_number), (pdf_token_from_keyword) 588

    pt_sig_ids = ["TOK_EOF", "TOK_ERROR", "LEX_BYTE",
                   "TOK_OPEN_DICT", "TOK_CLOSE_DICT",
                   "TOK_OPEN_ARRAY", "TOK_CLOSE_ARRAY", "LEX_NAME",
                   "TOK_OPEN_BRACE", "TOK_FROM_KEYWORD", "LEX_NUMBER",
                   "LEX_STRING", "LEX_HEX_STRING", "TOK_CLOSE_BRACE"]

    def register_token_parts(self, typ, val, from_obj):
        # may be called by TokTypeFrame or LexTokValSig
        if isinstance(from_obj, LexTokKeywordFrame):
            # this value may be overwritten in case of pdf_token_from_keyword
            if self.token_type == TokEnum.NAME:
                if val != self.token_value:
                    # regisered val may differ due to encountering lexing
                    # errors or unpritable bytes
                    # self.OOPS("registered val part does not match current",
                    #           f"token_value, typ: {typ}, val: {val}, ",
                    #           f"from_obj: {from_obj}")
                    self.token_value = val
                self.token_type = None
                # but don't overwrite the value because we already have it
                val = None
        super().register_token_parts(typ, val, from_obj)

    def on_push(self, old_top):
        # self.manager.call_len = len(self.manager.ml.stack.stack)
        s = self.flagged_signature
        others = [s for s in self.manager.ghoststack_overlay(LexTokFrame)
                  if s != self]
        if others:
            s = others[-1].flagged_signature
            self.OOPS("Did not expect nested LexTokFrames, but found",
                      str(others), f"top one flagged by {s}")
        super().on_push(old_top)

    def on_pop(self, new_top):
        super().on_pop(new_top, False)
        if self.manager.stack_top(LexTokFrame) is not None:
            self.OOPS("Did not expect nested LexTokFrames")
        top = self.manager.stack_top(MutoolPTFrame)
        if top:
            tok = MuLexObj(self.token_type, self.token_value,
                           self.taint, self.first_taint)
            top.register_token(tok, self.callstackentry.pc, self)


class LexTokValSig(MutoolMomentSig):
    log_type = PCEntry
    attr_name = "pc"
    flag_token_type = None
    parent_frame_class = LexTokFrame
    initial_token_value = None
    remove_when_flagged = True

    def do_reset(self):
        super().do_reset()
        self.token_value = self.__class__.initial_token_value
        self.flag_token_type = self.__class__.flag_token_type

    def get_value(self):
        return self.unpack_val(self.flagged_entry.value) \
            if self.struct_format else self.token_value

    def get_type(self):
        return self.flag_token_type

    def _do_flag(self, log_entry):
        super()._do_flag(log_entry)
        if self.flag_token_type is None:
            self.OOPS("flag_token_type should not be None")
        self.parent_frame.register_token_parts(self.get_type(),
                                               self.get_value(), self)


class LexStringFrame(TokTypeFrame):
    # STRING -> 411
    # else ERROR
    pt_sig_ids = ["STRING_TOK_TYPE",
                  "LEX_STRING_VALUE"]
    initial_token_type = TokEnum.ERROR
    sig_id_name = "LEX_STRING"
    flag_addr_fn_name = "lex_string"
    initial_token_value = b""

    def append_char(self, byte):
        self.token_value += byte


class LexHexStringFrame(TokTypeFrame):
    # STRING -> 411
    # else ERROR
    pt_sig_ids = ["HEX_STRING_TOK_TYPE",
                  "LEX_HEX_STRING_VALUE"]
    initial_token_type = TokEnum.STRING
    sig_id_name = "LEX_HEX_STRING"
    flag_addr_fn_name = "lex_hex_string"
    initial_token_value = b""

    def append_char(self, byte):
        self.token_value += byte


class LexNameFrame(TokTypeFrame):
    sig_id_name = "LEX_NAME"
    flag_addr_fn_name = "lex_name"
    pt_sig_ids = ["LEX_NAME_VALUE"]
    initial_token_type = TokEnum.NAME
    initial_token_value = b""

    def append_char(self, c):
        self.token_value += c


class LexNumberFrame(TokTypeFrame):
    # KEYWORD -> 215
    # REAL -> 227
    # INT -> 232
    #
    pt_sig_ids = ["NUMBER_REAL_VAL",
                  "NUMBER_ACROBAT_REAL_VAL",
                  "NUMBER_INT_VAL"]
    sig_id_name = "LEX_NUMBER"
    flag_addr_fn_name = "lex_number"
    initial_token_type = TokEnum.KEYWORD


class NewObject(MutoolMomentSig):
    parent_frame_class = MutoolPTFrame
    remove_when_flagged = False
    value = None
    obj_type = None

    def get_value(self):
        return self.unpack_val(self.flagged_entry.value) \
            if self.struct_format else self.value

    def get_obj(self):
        return PT(self.obj_type, self.get_value()) \
            if self.obj_type else None

    def _do_flag(self, log_entry):
        super()._do_flag(log_entry)
        self.parent_frame.register_new_object(self.get_obj(),
                                              self.flagged_entry.pc,
                                              self)


class ArrayIntA(NewObject):
    sig_id_name = "ARRAY_INT_A"
    parent_frame_class = ParseArrayFrame
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "array_int_a"


class ArrayIntB(NewObject):
    sig_id_name = "ARRAY_INT_B"
    parent_frame_class = ParseArrayFrame
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "array_int_b"


class DictNewKey(NewObject):
    sig_id_name = "DICT_NEW_KEY"
    log_type = CallEntry
    attr_name = "pc"
    flag_addr_name = "dict_key"
    parent_frame_class = ParseDictFrame


class DictIntNull(NewObject):
    sig_id_name = "DICT_INT_NULL"
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "dict_int_null"
    parent_frame_class = ParseDictFrame
    obj_type = PDFEnum.NULL


class DictPut(MutoolMomentSig):
    sig_id_name = "DICT_PUT"
    log_type = CallEntry
    attr_name = "target_addr"
    flag_addr_fn_name = "pdf_dict_put"
    parent_frame_class = ParseDictFrame
    remove_when_flagged = False

    def flag(self):
        self.parent_frame.register_dict_put(self.flagged_entry.pc)


class FastAtoiVal(LexTokValSig):
    sig_id_name = "NUMBER_INT_VAL"
    log_type = MemEntry
    attr_name = "pc"
    flag_addr_name = "lex_number_val"
    flag_token_type = TokEnum.INT
    parent_frame_class = LexNumberFrame
    struct_format = "i"


class RealVal(LexTokValSig):
    sig_id_name = "NUMBER_REAL_VAL"
    flag_token_type = TokEnum.REAL
    log_type = MemEntry
    attr_name = "pc"
    flag_addr_name = "lex_number_real_value"
    parent_frame_class = LexNumberFrame
    struct_format = "f"


class LexNumberRealTokType(LexTokValSig):
    sig_id_name = "NUMBER_ACROBAT_REAL_VAL"
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "lex_number_real_acro"
    flag_token_type = TokEnum.REAL
    parent_frame_class = LexNumberFrame
    struct_format = "f"

    # def flag(self):
    #     self.OOPS("lex_number_real_acro called, need to test this")


class LexTokKeywordFrame(TokTypeFrame):
    # if 470: {471: KEYWORD, !471: R}
    # if 473: {!474: TRUE, (474, !475): TRAILER, (474, 475): KEYWORD}
    # if 477: {!478: FALSE, 478: KEYWORD}
    # if 480: {!481: NULL, 480: KEYWORD}
    # if 486: {(!487: ENDOBJ, (487, !488): ENDSTREAM, (487, 488): KEYWORD}
    # if 490: {!491: STREAM, (491, !492): STARTXREF, (491, 492): KEYWORD}
    # if 494: {495: XREF, !495: KEYWORD}
    # if 501: ERROR (after any of the above)
    # else (505) KEYWORD

    initial_token_type = TokEnum.KEYWORD
    sig_id_name = "TOK_FROM_KEYWORD"
    flag_addr_fn_name = "pdf_token_from_keyword"

    def __init__(self, sig):
        self.type_sig = self.manager.sig_from_id(
            SigID.LEX_TOK_FROM_KEYWORD_TYPE
        )
        sigs = set([self.type_sig])
        # , self.manager.sig_from_id(SigID.CALL_TRACE)])
        super().__init__(sig, pt_tracking_sigs=sigs)

    def on_pop(self, new_top):
        if self.type_sig.last_idx is None:
            self.OOPS("type signature's last_idx should not be None in",
                      str(self.type_sig))
        # self.type_sig never flags, but we just want to check
        # what is its last token_type value
        self.token_type = self.type_sig.token_type
        self.token_value = self.type_sig.token_value
        super().on_pop(new_top)


class LexByteFrame(MutoolFrame):
    sig_id_name = "LEX_BYTE"
    flag_addr_fn_name = "fz_read_byte"
    struct_format = "B"

    def __init__(self, sig):
        self.taint_sig = self.manager.sig_from_id(SigID.TAINT_READ)
        super().__init__(sig, pt_tracking_sigs=set([self.taint_sig]))

    def on_pop(self, new_top):
        super().on_pop(new_top)
        if len(self.taint_sig.flagged_entries) == 1:
            e = self.taint_sig.flagged_entries[0]
            value = e.value if e.size == 1 else [e.value]
        else:
            value = [e.value for e in self.taint_sig.flagged_entries]

        if new_top:
            if isinstance(value, list):
                new_top.register_lex_multi_bytes(value)
            else:
                new_top.register_lex_byte(
                    self.flagged_signature.pack_val(value)
                )
            new_top.register_taint(self.taint_sig.get_taint(),
                                   self.taint_sig.first_taint)


class NewIntVal(NewObject):
    sig_id_name = "NEW_INT"
    flag_addr_name = "new_int_val"
    log_type = MemEntry
    attr_name = "pc"
    obj_type = PDFEnum.INT
    struct_format = "i"


class NewRealVal(NewObject):
    sig_id_name = "NEW_REAL"
    flag_addr_name = "new_real_val"
    log_type = MemEntry
    attr_name = "pc"
    struct_format = "f"
    obj_type = PDFEnum.REAL


class NewNameVal(NewObject):
    sig_id_name = "NEW_NAME"
    flag_addr_fn_name = "pdf_new_name"
    log_type = PCEntry
    attr_name = "pc"


class NewStringVal(NewObject):
    sig_id_name = "NEW_STRING"
    flag_addr_fn_name = "pdf_new_string"
    log_type = CallEntry
    attr_name = "target_addr"


class NewRefVal(NewObject):
    sig_id_name = "NEW_REFERENCE"
    flag_addr_name = "new_indirect_val"
    log_type = MemEntry
    attr_name = "pc"
    obj_type = PDFEnum.REF
    struct_format = "i"

    def reset(self):
        self.gen = None
        self.num = None

    def get_value(self):
        if self.gen is None or self.num is None:
            self.OOPS("gen and num should not be None,",
                      f"gen: {self.gen}, num: {self.num}")
        return f"{self.gen} {self.num} R"

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, MemEntry) and \
           log_entry.pc in self.check_values:
            idx = self.check_values.index(log_entry.pc)
            val = self.unpack_val(log_entry.value)
            if idx == 0:
                self.gen = val
            else:
                self.num = val
                self.do_flag(log_entry)


class LexTokEof(LexTokValSig):
    sig_id_name = "TOK_EOF"
    flag_addr_name = "pdf_lex_val"
    flag_addr_idx = 0
    flag_token_type = TokEnum.EOF


class LexTokError(LexTokValSig):
    sig_id_name = "TOK_ERROR"
    log_type = PCEntry
    attr_name = "pc"
    flag_token_type = TokEnum.ERROR
    # pdf_lex_val 2, 3  (560, 574)

    @classmethod
    def setup(cls):
        addrs = cls.addrs_of("pdf_lex_val")
        cls.check_values = [addrs[2], addrs[3]]


class LexTokOpenDict(LexTokValSig):
    sig_id_name = "TOK_OPEN_DICT"
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "pdf_lex_val"
    flag_addr_idx = 4  # 564
    flag_token_type = TokEnum.OPEN_DICT
    token_value = b"<<"


class LexTokCloseDict(LexTokValSig):
    sig_id_name = "TOK_CLOSE_DICT"
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "pdf_lex_val"
    flag_addr_idx = 5  # 571
    flag_token_type = TokEnum.CLOSE_DICT
    token_value = b">>"


class LexTokOpenArray(LexTokValSig):
    sig_id_name = "TOK_OPEN_ARRAY"
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "pdf_lex_val"
    flag_addr_idx = 6  # 576
    flag_token_type = TokEnum.OPEN_ARRAY
    token_value = b"["


class LexTokCloseArray(LexTokValSig):
    sig_id_name = "TOK_CLOSE_ARRAY"
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "pdf_lex_val"
    flag_addr_idx = 7  # 578
    flag_token_type = TokEnum.CLOSE_ARRAY
    token_value = b"]"


class LexTokOpenBrace(LexTokValSig):
    sig_id_name = "TOK_OPEN_BRACE"
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "pdf_lex_val"
    flag_addr_idx = 8  # 580
    flag_token_type = TokEnum.OPEN_BRACE
    token_value = b"{"


class LexTokCloseBrace(LexTokValSig):
    sig_id_name = "TOK_CLOSE_BRACE"
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "pdf_lex_val"
    flag_addr_idx = 9  # 582
    flag_token_type = TokEnum.CLOSE_BRACE
    token_value = b"}"


class LexStringTokType(LexTokValSig):
    sig_id_name = "STRING_TOK_TYPE"
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "lex_string"
    flag_token_type = TokEnum.STRING
    parent_frame_class = LexStringFrame


class LexHexStringTokType(LexTokValSig):
    sig_id_name = "HEX_STRING_TOK_TYPE"
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "lex_hex_string_err"
    flag_token_type = TokEnum.ERROR
    parent_frame_class = LexStringFrame


class LexStringValue(MutoolMomentSig):
    sig_id_name = "LEX_STRING_VALUE"
    log_type = MemEntry
    attr_name = "pc"
    flag_addr_name = "lex_string_val"
    parent_frame_class = LexStringFrame
    struct_format = "B"
    remove_when_flagged = False

    idx_vals = [b'(',  # 338,
                b")",  # 345
                b"\n",  # 354
                b"\r",  # 357
                b"\t",  # 360
                b"\b",  # 363
                b"\f",  # 366
                b"(",  # 369
                b")",  # 372
                b"\\"  # 375
                ]

    def flag(self):
        pc_idx = self.check_values.index(self.flagged_entry.pc)
        byte = self.idx_vals[pc_idx] if pc_idx < len(self.idx_vals) else \
            self.pack_val(self.flagged_entry.value)
        self.parent_frame.append_char(byte)


class LexHexStringValue(MutoolMomentSig):
    sig_id_name = "LEX_HEX_STRING_VALUE"
    log_type = MemEntry
    attr_name = "pc"
    flag_addr_name = "lex_hex_string_val"
    parent_frame_class = LexHexStringFrame
    struct_format = "B"
    remove_when_flagged = False

    def flag(self):
        self.parent_frame.append_char(self.pack_val(self.flagged_entry.value))


class DictCheckEnd(MutoolMomentSig):
    sig_id_name = "DICT_CHECK_END"
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "dict_check_end"
    parent_frame_class = ParseDictFrame
    remove_when_flagged = False

    def flag(self):
        self.parent_frame.register_dict_check_end()


class ArrayPushSig(MutoolMomentSig):
    log_type = CallEntry
    attr_name = "target_addr"
    obj_type = None
    parent_frame_class = ParseArrayFrame
    remove_when_flagged = False

    @classmethod
    def setup(cls):
        call_pcs = cls.addrs_of(cls.flag_addr_name)
        segs = [(pc, cls.get_segment_at(pc)) for pc in call_pcs]
        cls.check_values = [
            Version.bin_info.next_ip(pc, seg)
            for (pc, seg) in segs
        ]

    def _flag(self, log_entry):
        super()._flag(log_entry)
        self.parent_frame.register_push(log_entry.pc, self)


class ArrayPushSigInt(ArrayPushSig):
    sig_id_name = "ARRAY_PUSH_INT"
    flag_addr_name = "array_push_int"
    obj_type = PDFEnum.INT


class ArrayPushSigBool(ArrayPushSig):
    sig_id_name = "ARRAY_PUSH_BOOL"
    flag_addr_name = "array_push_bool"
    obj_type = None


class ArrayPushSigGeneral(ArrayPushSig):
    sig_id_name = "ARRAY_PUSH"
    flag_addr_name = "array_push"
    obj_type = None


class ArrayPushSigString(ArrayPushSig):
    sig_id_name = "ARRAY_PUSH_STRING"
    flag_addr_name = "array_push_string"
    obj_type = PDFEnum.STRING


class ArrayPushSigName(ArrayPushSig):
    sig_id_name = "ARRAY_PUSH_NAME"
    flag_addr_name = "array_push_name"
    obj_type = None


class ArrayPushSigReal(ArrayPushSig):
    sig_id_name = "ARRAY_PUSH_REAL"
    flag_addr_name = "array_push_real"
    obj_type = PDFEnum.REAL


class ArrayPushSigDrop(ArrayPushSig):
    sig_id_name = "ARRAY_PUSH_DROP"
    flag_addr_name = "array_push_drop"
    obj_type = None


class ArrayCatchSig(MutoolMomentSig):
    sig_id_name = "ARRAY_CATCH"
    log_type = CallEntry
    attr_name = "pc"
    flag_addr_name = "array_catch"
    remove_when_flagged = False


class ExceptionStackEntry():
    def __init__(self, tryer, try_idx, throw_log_entry):
        self.tryer = tryer
        self.try_idx = try_idx
        self.throw_log_entry = throw_log_entry

    def __repr__(self):
        f = "" if self.throw_log_entry is None else "EXCEPTION"
        return f"{self.tryer}[{self.try_idx}]{f}"


class ThrowException(MutoolMomentSig):
    sig_id_name = "THROW_EXCEPTION"
    remove_when_flagged = False

    @classmethod
    def setup(cls):
        cls.throw = cls.get_fn_abs_addr("throw")
        cls.fz_catch = cls.get_fn_abs_addr("fz_do_catch")
        cls.fz_try = cls.get_fn_abs_addr("fz_do_try")
        cls.fz_rethrow = cls.get_fn_abs_addr("fz_rethrow")

    def reset(self):
        self.try_stack = []
        self.exception_info = None
        self.last_throw = None

    def do_log_entry(self, log_entry):
        # try_stack = self.try_stack
        # callstack = self.manager.ml.stack.stack
        if is_kind(log_entry, CallEntry):
            # stack_len = len(callstack)
            if log_entry.target_addr in self.throw:
                self.last_throw = log_entry
            elif log_entry.call_kind == log_entry.INDIRECT_JMP and \
                 self.manager.ml.stack.longjmp_pop:
                e = ExceptionStackEntry(self.manager.ml.stack.top(),
                                        len(self.manager.ml.stack.stack),
                                        self.last_throw)
                self.exception_info = e
                self.last_throw = None
                self.do_flag(log_entry)

    def flag(self):
        stack_len = len(self.manager.ml.stack.stack)
        for i in range(0, len(self.manager.ghoststack))[::-1]:
            entry = self.manager.ghoststack[i]
            if entry.callstackentry_idx >= stack_len:
                entry.register_exception(self.exception_info, self)
                entry.return_sig.do_flag(self.flagged_entry)
            else:
                break


class LexNameValueSig(MutoolMomentSig):
    sig_id_name = "LEX_NAME_VALUE"
    log_type = MemEntry
    attr_name = "pc"
    flag_addr_name = "lex_name_val"
    struct_format = "B"
    parent_frame_class = LexNameFrame
    remove_when_flagged = False

    def flag(self):
        self.parent_frame.append_char(self.pack_val(self.flagged_entry.value))


class LexTokenFromKeywordType(LexTokValSig):
    sig_id_name = "LEX_TOK_FROM_KEYWORD_TYPE"
    log_type = PCEntry
    attr_name = "pc"
    struct_format = "B"
    idx_mapping = [TokEnum.R,  # 470
                   TokEnum.TRUE,  # 473
                   TokEnum.TRAILER,  # 474
                   TokEnum.FALSE,  # 477
                   TokEnum.NULL,  # 480
                   TokEnum.OBJ,  # 483
                   TokEnum.ENDOBJ,  # 486
                   TokEnum.ENDSTREAM,  # 487
                   TokEnum.STREAM,  # 490
                   TokEnum.STARTXREF,  # 491
                   TokEnum.XREF,  # 494
                   TokEnum.ERROR,  # 501
                   TokEnum.KEYWORD]  # 505
    len_idx = len(idx_mapping)
    token_mapping = [b"R", b"true", b"trailer", b"false", b"null", b"obj",
                     b"endobj", b"endstream", b"stream", b"startxref", b"xref"]
    len_tokens = len(token_mapping)
    initial_token_value = b""
    initial_token_type = TokEnum.KEYWORD

    @classmethod
    def setup(cls):
        cls.addrs = cls.addrs_of("token_from_keyword")
        cls.consume_key = cls.addrs_of("token_from_keyword_keyword")[0]
        cls.addrs.append(cls.consume_key)
        cls.read_addr = cls.addrs_of("token_keyword_val", 1)

    def reset(self):
        self.last_idx = None
        self.token_type = self.__class__.initial_token_type
        self.token_value = self.__class__.initial_token_value
        self.first_read = True

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, self.log_type):
            pc = getattr(log_entry, self.attr_name)
            if pc in self.addrs[:-1]:
                # the last addr in this list is a MemEntry
                self.last_idx = self.addrs.index(pc)
                self.token_type = self.idx_mapping[self.last_idx]
                if self.last_idx < self.len_tokens:
                    self.token_value = self.token_mapping[self.last_idx]
        elif is_kind(log_entry, MemEntry):
            if log_entry.pc == self.consume_key:
                self.last_idx = self.addrs.index(log_entry.pc)
                self.token_type = self.idx_mapping[self.last_idx]
            elif log_entry.pc == self.read_addr:
                if self.first_read:
                    # reset current token_value
                    self.token_value = b""
                    self.first_read = False
                # collect bytes read to figure out token value
                self.token_value += self.pack_val(log_entry.value)


class RepairObjFrame(MutoolPTFrame):
    sig_id_name = "REPAIR_OBJ"
    flag_addr_fn_name = "pdf_repair_obj"
    remove_when_flagged = False
    sig_baseclass = MutoolPTNewFrameSig

    def __init__(self, sig):
        super().__init__(sig, PT(PDFEnum.CONTAINER))

    def register_new_object(self, obj, pc, sig):
        if obj is not None:
            super().register_new_object(obj, pc, sig)


@dataclasses.dataclass
class XRefEntry():
    num: int = 0
    gen: int = 0
    ofs: int = 0
    type: str = ""

    def reset(self):
        self.num = 0
        self.gen = 0
        self.ofs = 0
        self.type = ""

    def to_pt(self):
        children = [PT(PDFEnum.INT, value=getattr(self, n))
                    for n in ["num", "gen", "ofs"]]
        children.append(PT(PDFEnum.KEYWORD,
                           value=self.type))
        return PT(PDFEnum.XREF_TABLE_ENTRY,
                  children=children)


class ParseOldXRefFrame(MutoolPTFrame):
    sig_id_name = "PARSE_OLD_XREF"
    flag_addr_fn_name = "pdf_read_old_xref"
    remove_when_flagged = False
    sig_baseclass = MutoolPTNewFrameSig
    pt_type = PDFEnum.XREF_TABLE
    xref_sigs = [f"OLD_XREF_ENTRY_{f}"
                 for f in ["OFFSET", "GEN", "TYPE", "NUM", "START", "LEN"]]

    @classmethod
    def setup(cls):
        cls.lex_addrs = cls.addrs_of("parse_xref_lex")
        cls.parse_trailer = cls.addrs_of("parse_xref_trailer")

    def __init__(self, sig):
        self.current_entry = XRefEntry()
        sigs = [self.manager.sig_from_id(getattr(SigID, f))
                for f in self.xref_sigs]
        pt = PT(self.pt_type)
        pt.add_context(ParseReason.create(self))
        pt.add_context(XRefTableInfo())
        self.trailer_dict = None
        super().__init__(sig, pt, pt_tracking_sigs=set(sigs))

    def register_token(self, tok, pc, reg_obj):
        if pc == self.lex_addrs[0]:
            self.add_pt_child(tok.to_pt())
        elif pc == self.lex_addrs[1]:
            self.last_token = tok
        else:
            # self.OOPS(tok, reg_obj)
            pass

    # def register_new_node(self, obj, reg_obj):
    #     pc = reg_obj.callstackentry.pc
    #     if pc in self.parse_trailer:
    #         if not self.last_token or \
    #            self.last_token.type != TokEnum.OPEN_DICT:
    #             self.OOPS(self.last_token, obj, reg_obj)
    #         obj._children = [self.last_token.to_pt()] + obj.children
    #         self.add_pt_child(obj)
    #         self.trailer_dict = obj
    #     else:
    #         obj.add_context(ParseReason.create(self, self.pt.index))
    #         self.do_register_pt(obj, True)

    def register_start_val(self, val):
        self.add_pt_child(PT(PDFEnum.INT, value=val))

    def register_len_val(self, val):
        self.add_pt_child(PT(PDFEnum.INT, value=val))

    def register_num_val(self, val):
        self.current_entry.num = val

    def register_gen_val(self, val):
        self.current_entry.gen = val

    def register_ofs_val(self, val):
        self.current_entry.ofs = val

    def register_type_val(self, val):
        self.current_entry.type = val
        self.add_pt_child(self.current_entry.to_pt())
        self.current_entry.reset()

    def on_pop(self, new_top):
        if self.trailer_dict:
            c = self.pt.get_context(XRefTableInfo)
            c.trailer_idx = self.trailer_dict.index
        super().on_pop(new_top)


class ParseNewXRefFrame(ParseOldXRefFrame):
    sig_id_name = "PARSE_NEW_XREF"
    flag_addr_fn_name = "pdf_read_new_xref"
    xref_sigs = [f"NEW_XREF_ENTRY_{f}"
                 for f in ["OFFSET", "GEN", "TYPE", "NUM"]]
    pt_type = PDFEnum.XREF_STREAM_TABLE


class XRefEntrySig(MutoolMomentSig):
    field_name = None
    struct_format = "i"
    attr_name = "pc"
    parent_frame_class = ParseOldXRefFrame
    log_type = MemEntry
    remove_when_flagged = False

    def flag(self):
        getattr(self.parent_frame, f"register_{self.field_name}_val")(
            self.unpack_val(self.flagged_entry.value)
        )


class OldXrefEntryStart(XRefEntrySig):
    sig_id_name = "OLD_XREF_ENTRY_START"
    flag_addr_name = "parse_xref_start"
    field_name = "start"


class OldXrefEntryLen(XRefEntrySig):
    sig_id_name = "OLD_XREF_ENTRY_LEN"
    flag_addr_name = "parse_xref_len"
    field_name = "len"


class OldXrefEntryNum(XRefEntrySig):
    sig_id_name = "OLD_XREF_ENTRY_NUM"
    flag_addr_name = "parse_xref_entry_num"
    field_name = "num"


class OldXrefEntryOffset(XRefEntrySig):
    sig_id_name = "OLD_XREF_ENTRY_OFFSET"
    field_name = "ofs"
    flag_addr_name = "parse_xref_entry_offset"


class OldXrefEntryGen(XRefEntrySig):
    sig_id_name = "OLD_XREF_ENTRY_GEN"
    flag_addr_name = "parse_xref_entry_gen"
    field_name = "gen"


class OldXrefEntryType(XRefEntrySig):
    sig_id_name = "OLD_XREF_ENTRY_TYPE"
    flag_addr_name = "parse_xref_entry_type"
    struct_format = "B"

    def flag(self):
        self.parent_frame.register_type_val(
            self.pack_val(self.flagged_entry.value)
        )


class NewXRefEntrySig(XRefEntrySig):
    parent_frame_class = ParseNewXRefFrame


class NewXrefEntryNum(NewXRefEntrySig):
    sig_id_name = "NEW_XREF_ENTRY_NUM"
    flag_addr_name = "parse_new_xref_entry_num"
    field_name = "num"


class NewXrefEntryOffset(NewXRefEntrySig):
    sig_id_name = "NEW_XREF_ENTRY_OFFSET"
    field_name = "ofs"
    flag_addr_name = "parse_new_xref_entry_ofs"


class NewXrefEntryGen(NewXRefEntrySig):
    sig_id_name = "NEW_XREF_ENTRY_GEN"
    flag_addr_name = "parse_new_xref_entry_gen"
    field_name = "gen"


class NewXrefEntryType(NewXRefEntrySig):
    sig_id_name = "NEW_XREF_ENTRY_TYPE"
    flag_addr_name = "parse_new_xref_entry_type"
    struct_format = "B"

    def flag(self):
        self.parent_frame.register_type_val(
            self.pack_val(self.flagged_entry.value)
        )


class RepairXRefFrame(MutoolPTFrame):
    sig_id_name = "REPAIR_XREF"
    flag_addr_fn_name = "pdf_repair_xref"
    remove_when_flagged = False
    sig_baseclass = MutoolPTNewFrameSig

    @dataclasses.dataclass
    class XRefEntry():
        num: int = 0
        gen: int = 0
        ofs: int = 0
        stm_ofs: int = 0
        stm_len: int = 0
        type: int = "n"

    def __init__(self, sig):
        self.xref_list = {}
        self.xref_list_entries = {}
        self.new_xref_table = {}
        self.num = None
        self.gen = None
        self.numofs = None
        self.stm_ofs = None
        self.stm_len = None
        self.listlen = None
        self.last_token = None
        self.tokens = []
        self.reset_taint()
        self.entry_idx = 0
        # self.parsed_objs = []
        self.trailer_obj = None

        sigs = set(
            [self.manager.sig_from_id(i) for i in
             [SigID.REPAIR_XREF_ENTRY_IDX,
              SigID.REPAIR_XREF_ENTRY_NUM,
              SigID.REPAIR_XREF_ENTRY_GEN,
              SigID.REPAIR_XREF_ENTRY_OFS,
              SigID.REPAIR_XREF_ENTRY_TOK,
              SigID.REPAIR_XREF_ENTRY_TOK_TYPE,
              SigID.REPAIR_XREF_ENTRY_STM_OFS,
              SigID.REPAIR_XREF_ENTRY_STM_LEN,
              SigID.REPAIR_XREF_REPAIR_OBJ,
              SigID.REPAIR_XREF_OBJ_TOK_TYPE,
              SigID.REPAIR_XREF_TOK_EOF,
              SigID.REPAIR_XREF_SHIFT,
              SigID.REPAIR_XREF_SHIFT_GEN_VAL,
              SigID.REPAIR_XREF_LIST_APPEND,
              SigID.LEX_BYTE, SigID.REPAIR_OBJ
              ]]
             )
        # sigs.add(self.manager.sig_from_id(SigID.CALL_TRACE))
        self._register_pt = True
        pt = PT(PDFEnum.RECONSTRUCTED_XREF_TABLE)
        pt.add_context(ParseReason.create(self))
        pt.add_context(XRefTableInfo())
        super().__init__(sig, pt=pt, pt_tracking_sigs=sigs)

    def register_token_repair(self, tok, pc, reg_sig):
        # may be called by RepairXrefTokType, RepairXRefTokTypeRepair sigs
        tok.add_taint(self.taint_tree, self.first_taint)
        self.reset_taint()
        self.last_token = tok
        self.tokens.append(tok)

    def register_token(self, tok, pc, reg_obj):
        self.OOPS(self, "did not expect register_token", "called by",
                  reg_obj, "%x" % pc,
                  self.manager.ml.binfo.get_segment_at(pc),
                  "registering", tok)

    def reset_taint(self):
        self.taint_tree = it.IntervalTree()
        self.first_taint = None

    def do_register_pt_reason(self, obj):
        obj.add_context(ParseReason.create(self, self.pt.index))
        self.do_register_pt(obj, True)

    # def register_new_node(self, obj, reg_obj):
    #     pc = reg_obj.callstackentry.pc
    #     if isinstance(reg_obj, RepairObjFrame) or \
    #        isinstance(reg_obj, ParseIndObjFrame):
    #         self.do_register_pt_reason(obj)
    #     else:
    #         self.register_new_object(obj, pc, reg_obj.flagged_signature)

    def register_pt_node(self, obj, reg_obj):
        self.do_register_pt_reason(self.do_pt_check(obj, reg_obj))

    def register_new_object(self, obj, pc, sig):
        if sig.sig_id_val in [SigID.NEW_INT, SigID.NEW_REFERENCE] or \
           obj is None:
            pass
        elif sig.sig_id_val == SigID.CACHE_OBJ:
            self.do_register_pt_reason(obj)
        else:
            self.OOPS(f"Didn't expect an object to be registered {sig}/{obj}",
                      self.last_token)

    def on_pop(self, new_top):
        for i in sorted(self.new_xref_table.keys()):
            children = [c.to_pt() for c in self.xref_list_entries[i][0:2]] + \
                [PT(PDFEnum.INT64, value=self.xref_list_entries[i][2])]
            self.pt.add_child(PT(PDFEnum.XREF_TABLE_ENTRY,
                                 children=children))
        # for c in self.parsed_objs:
        #     self.do_register_pt(c, True)
        # print(self.xref_list)
        # print(self.xref_list_entries)
        # print(self.new_xref_table)
        # print(self.pt.orphans)
        # print(self.pt)
        if self.trailer_obj:
            cxt = self.pt.get_context(XRefTableInfo)
            cxt.trailer_idx = self.trailer_obj.index
        if self.pt:
            self.do_register_pt(self.pt)
        super().on_pop(new_top)

    def register_lex_byte(self, value):
        pass

    def register_lex_multi_bytes(self, values):
        pass

    def register_tok_eof(self):
        self.last_token.type = TokEnum.EOF

    def register_taint(self, taint, first_taint):
        if self.first_taint is None:
            self.first_taint = first_taint
        self.taint_tree |= taint

    def reset_list_entry(self):
        if self.gen is not None:
            pt = PT(PDFEnum.XREF_TABLE_ENTRY)
            children = [self.gen.to_pt()]
            if self.num:
                children = [self.num.to_pt()] + children
            pt.add_context(ParseReason.create(self, self.pt.index))
            self.pt.add_orphan(pt)
        self.num = None
        self.gen = None

    def register_list_entry(self, index):
        # may be called by RepairXRefListAppend sig
        children = [self.num.to_pt(), self.gen.to_pt(),
                    PT(PDFEnum.INT, self.numofs)]
        self.xref_list[index] = PT(PDFEnum.XREF_TABLE_ENTRY,
                                   children=children)
        self.xref_list_entries[index] = (self.num, self.gen, self.numofs,
                                         self.stm_ofs, self.stm_len)

    def register_shift_int(self, ofs):
        # may be called by RepairXRefShift sig
        self.num = self.gen
        self.gen = self.last_token
        self.numofs = ofs

    def register_gen_val(self, val):
        # may be called by RepairXRefShiftGenVal sig
        self.gen.value = val

    def register_entry(self, field, val):
        # may be called by RepairXRefSig sig
        if field == "idx":
            self.entry_idx = val
        else:
            if self.entry_idx not in self.new_xref_table:
                self.new_xref_table[self.entry_idx] = self.XRefEntry()
            setattr(self.new_xref_table[self.entry_idx], field, val)


class RepairXRefSig(MutoolMomentSig):
    log_type = MemEntry
    attr_name = "pc"
    flag_addr_name = "repair_xref_entry"
    parent_frame_class = RepairXRefFrame
    remove_when_flagged = False
    struct_format = "i"
    field_name = None

    def _do_flag(self, log_entry):
        super()._do_flag(log_entry)
        self.parent_frame.register_entry(self.field_name,
                                         self.unpack_val(log_entry.value))


class RepairXRefReset(MutoolMomentSig):
    sig_id_name = "REPAIR_XREF_RESET"
    log_type = PCEntry
    attr_name = "pc"
    parent_frame_class = RepairXRefFrame
    remove_when_flagged = False
    flag_addr_name = "repair_xref_reset"

    def flag(self):
        self.parent_frame.reset_list_entry()


class RepairXRefShift(MutoolMomentSig):
    sig_id_name = "REPAIR_XREF_SHIFT"
    log_type = MemEntry
    attr_name = "pc"
    parent_frame_class = RepairXRefFrame
    remove_when_flagged = False
    flag_addr_name = "repair_xref_shift_int"
    struct_format = "l"

    def flag(self):
        self.parent_frame.register_shift_int(
            self.unpack_val(self.flagged_entry.value)
        )


class RepairXRefShiftGenVal(MutoolMomentSig):
    sig_id_name = "REPAIR_XREF_SHIFT_GEN_VAL"
    log_type = MemEntry
    attr_name = "pc"
    parent_frame_class = RepairXRefFrame
    remove_when_flagged = False
    flag_addr_name = "repair_xref_shift_gen_val"
    struct_format = "i"

    def flag(self):
        self.parent_frame.register_gen_val(
            self.unpack_val(self.flagged_entry.value)
        )


class RepairXRefEntryIdx(RepairXRefSig):
    sig_id_name = "REPAIR_XREF_ENTRY_IDX"
    flag_addr_idx = 0
    field_name = "idx"


class RepairXRefEntryNum(RepairXRefSig):
    sig_id_name = "REPAIR_XREF_ENTRY_NUM"
    flag_addr_idx = 3
    field_name = "num"


class RepairXRefEntryGen(RepairXRefSig):
    sig_id_name = "REPAIR_XREF_ENTRY_GEN"
    flag_addr_idx = 2
    field_name = "gen"


class RepairXRefEntryOfs(RepairXRefSig):
    sig_id_name = "REPAIR_XREF_ENTRY_OFS"
    flag_addr_idx = 1
    field_name = "ofs"


class RepairXRefEntryStmOfs(RepairXRefSig):
    sig_id_name = "REPAIR_XREF_ENTRY_STM_OFS"
    flag_addr_idx = 4
    field_name = "stm_ofs"


class RepairXRefTokType(MutoolMomentSig):
    log_type = MemEntry
    sig_id_name = "REPAIR_XREF_ENTRY_TOK_TYPE"
    attr_name = "pc"
    flag_addr_name = "repair_xref_tok"
    parent_frame_class = RepairXRefFrame
    remove_when_flagged = False
    struct_format = "i"

    def flag(self):
        self.parent_frame.register_token_repair(
            MuLexObj(TokEnum(self.unpack_val(self.flagged_entry.value))),
            self.flagged_entry.pc,
            self
        )


class RepairXRefTokTypeRepair(MutoolMomentSig):
    log_type = MemEntry
    sig_id_name = "REPAIR_XREF_OBJ_TOK_TYPE"
    attr_name = "pc"
    flag_addr_name = "repair_xref_tok_obj_repair"
    parent_frame_class = RepairXRefFrame
    remove_when_flagged = False
    struct_format = "i"

    def flag(self):
        self.parent_frame.register_token_repair(
            MuLexObj(TokEnum(self.unpack_val(self.flagged_entry.value))),
            self.flagged_entry.pc,
            self
        )


class RepairXRefTok(MutoolMomentSig):
    sig_id_name = "REPAIR_XREF_ENTRY_TOK"
    flag_addr_fn_name = "pdf_lex_no_string"
    log_type = MemEntry
    attr_name = "pc"
    parent_frame_class = RepairXRefFrame
    remove_when_flagged = False
    struct_format = "i"
    field_name = None

    def flag(self):
        self.parent_frame.reset_taint()


class RepairXRefListAppend(MutoolMomentSig):
    sig_id_name = "REPAIR_XREF_LIST_APPEND"
    flag_addr_name = "repair_xref_list_index"
    log_type = MemEntry
    attr_name = "pc"
    parent_frame_class = RepairXRefFrame
    remove_when_flagged = False
    struct_format = "i"
    field_name = None

    def flag(self):
        self.parent_frame.register_list_entry(
            self.unpack_val(self.flagged_entry.value)
        )


class RepairXRefObj(MutoolMomentSig):
    sig_id_name = "REPAIR_XREF_REPAIR_OBJ"
    flag_addr_fn_name = "pdf_repair_obj"
    log_type = MemEntry
    attr_name = "pc"
    parent_frame_class = RepairXRefFrame
    remove_when_flagged = False
    struct_format = "i"
    field_name = None

    def flag(self):
        self.parent_frame.reset_taint()


class RepairXRefEntryStmLen(RepairXRefSig):
    sig_id_name = "REPAIR_XREF_ENTRY_STM_LEN"
    flag_addr_name = "repair_xref_stream_len"
    field_name = "stm_len"


class RepairXRefTokEof(MutoolMomentSig):
    log_type = MemEntry
    sig_id_name = "REPAIR_XREF_TOK_EOF"
    attr_name = "pc"
    flag_addr_name = "repair_xref_tok_eof"
    parent_frame_class = RepairXRefFrame
    remove_when_flagged = False

    def flag(self):
        self.parent_frame.register_tok_eof()


class ProcessStreamNum(MutoolMomentSig):
    log_type = MemEntry
    sig_id_name = "PROCESS_STREAM_NUM"
    attr_name = "pc"
    flag_addr_name = "process_stream_num"
    parent_frame_class = OpenContentsFrame
    remove_when_flagged = True
    struct_format = "i"

    def flag(self):
        self.parent_frame.register_num(
            self.unpack_val(self.flagged_entry.value)
        )


class ProcessStreamSig(MutoolMomentSig):
    sig_id_name = "STREAM_EVENTS"
    parent_frame_class = ProcessStreamFrame
    remove_when_flagged = False
    register_fn_name = None
    log_type = CallEntry
    attr_name = "target_addr"

    # address names that correspond to CallEntry->pc
    name_call_pc_regs = {
        "process_stream_drop_last_arg": "register_arg_pop",
        "process_stream_drop_args": "register_drop_args",
    }

    # address names that correspond to PCEntry->pc
    name_pc_pc_regs = {
        "process_stream_set_name": "register_set_name",
        "process_stream_push_stack": "register_push_stack",
        "process_stream_set_string": "register_set_string"
    }

    # function names/call targets (CallEntry->target_addr)
    fn_target_regs = {
        "pdf_clear_stack": "register_clear_stack",
        "pdf_process_keyword": "register_exec_op",
        "pdf_array_push_string": "register_push_args",
        "pdf_array_push_int": "register_push_args",
        "pdf_array_push_real": "register_push_args",
        "throw": "register_nested_exception",
        "pdf_load_hail_mary_font": "register_hail_mary_font"
    }

    @classmethod
    def setup(cls):
        cls.fn_registrar = {}

        def update_reg_list(name, is_fn, saved_name, reg_fn):
            addrs = cls.get_fn_abs_addr(name, lib=cls.lib_name) if is_fn else \
                cls.addrs_of(name)
            if not hasattr(cls, saved_name):
                setattr(cls, saved_name, set())
            getattr(cls, saved_name).update(addrs)
            for a in addrs:
                cls.fn_registrar[a] = reg_fn

        for (k, v) in cls.fn_target_regs.items():
            update_reg_list(k, True, "check_call_target_addrs", v)
        for (k, v) in cls.name_call_pc_regs.items():
            update_reg_list(k, False, "check_call_pcs", v)
        for (k, v) in cls.name_pc_pc_regs.items():
            update_reg_list(k, False, "check_pcs", v)

    def reset(self):
        self.flagged_address = None

    def do_log_entry(self, log_entry):
        if (is_kind(log_entry, CallEntry) and
            ((log_entry.call_kind == log_entry.CALL and
              log_entry.target_addr in self.check_call_target_addrs) or
             log_entry.pc in self.check_call_pcs)) or \
           (is_kind(log_entry, PCEntry) and
            log_entry.pc in self.check_pcs):
            self.flagged_address = log_entry.target_addr \
                if getattr(log_entry, "target_addr", None) in \
                   self.check_call_target_addrs else \
                   log_entry.pc
            self.do_flag(log_entry)

    def flag(self):
        getattr(self.parent_frame,
                self.fn_registrar[self.flagged_address])(self)
        self.flagged_address = None


# for xref table parsing: pdf_read_old_xref, pdf_read_new_xref
# also see pdf-repair.c for more parsing/fixup
# pdf_to_date for date parsing
# pdf_new_matrix, pdf_new_rect
