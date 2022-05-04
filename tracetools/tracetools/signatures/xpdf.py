# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from tracetools.signatures.xpdf_poppler import XpdfPopplerFrame, LexType, \
    LexObj, XpdfPopplerMomentSignature, \
    XpdfPopplerPTTracker as Tracker, \
    MakeStreamFrame as XpdfPopplerMakeStreamFrame, \
    NewParserMoment as XpdfPopplerNewParserMoment, \
    DictFrameReturn as XpdfPopplerDictFrameReturn, \
    XpdfPopplerPTMoment, \
    CopyStringMoment as XpdfPopplerCopyStringMoment, \
    GfxStreamSig as XpdfPopplerGfxStreamSig, \
    XRefConstructSigBase, FetchXRefInfo, \
    FetchFrame as XpdfPopplerFetchFrame, \
    GetObjFrame as XpdfPopplerGetObjFrame
from tracetools.signatures.pdf import PDFPT as PT
from tracetools.signatures.pdf import PDFEnum, XRefTableInfo
from tracetools.signatures.context import ParseReason
from tracetools.signatures.signatures import NewFrameMoment, SigID, \
    ReturnSignature, MomentSignature
from tracetools.log_entries import is_kind, MemEntry, CallEntry, PCEntry
from aenum import IntEnum, auto
from tracetools.signatures.versions import Version


class XpdfFrame(XpdfPopplerFrame):
    primary_binary = True
    supported_group_ids = ["xpdf"]


class XpdfMomentSignature(MomentSignature):
    primary_binary = True
    supported_group_ids = ["xpdf"]
    lib_name = None


class XpdfNewFrameMoment(NewFrameMoment, XpdfPopplerMomentSignature,
                         XpdfMomentSignature):
    pass


class FetchFrame(XpdfPopplerFetchFrame, XpdfFrame):
    fn_names = ["_ZN4XRef5fetchEiiP6Objecti"]

    def __init__(self, flagged_sig):
        self.cached = False
        self.failed = False
        super().__init__(flagged_sig)

    def register_cached_fetch(self):
        self.cached = True

    def register_fetch_fail(self):
        self.failed = True

    def on_push(self, new_top):
        super().on_push(new_top)
        for i in [SigID.XREF_FETCH_CACHED, SigID.XREF_FETCH_FAILED]:
            self.add_ghostsite_sig(self.manager.sig_from_id(i))

    def on_pop(self, new_top):
        super().on_pop(new_top)
        self.pt.get_context(FetchXRefInfo).cached = self.cached
        self.pt.get_context(FetchXRefInfo).fetch_failed = self.failed


class GetObjFrame(XpdfPopplerGetObjFrame, XpdfFrame):
    pass


class ParseXRefTableFrame(XpdfFrame):
    fn_names = ["_ZN4XRef13readXRefTableEPliP10XRefPosSet"]
    sig_id_name = "PARSE_XREF_TABLE"

    def __init__(self, flagged_sig):
        self._track_pt = True
        self._register_pt = True
        self.last_idx = None
        self.last_gen = None
        self.last_offset = None
        self.last_type = None
        pt = PT(PDFEnum.XREF_TABLE)
        pt.add_context(ParseReason.create(self))
        pt.add_context(XRefTableInfo())
        sigs = set([self.manager.sig_from_id(s) for s in
                    [SigID.PARSE_XREF_TABLE_GEN,
                     SigID.PARSE_XREF_TABLE_OFFSET,
                     SigID.PARSE_XREF_TABLE_TYPE,
                     SigID.PARSE_XREF_TABLE_IDX,
                     SigID.PARSE_XREF_TABLE_IDX_ALT,
                     SigID.PARSE_XREF_TABLE_ADD_ENTRY,
                     ]])
        self.taint_sig = self.manager.sig_from_id(SigID.TAINT_READ)
        sigs.add(self.taint_sig)
        super().__init__(flagged_sig, pt_tracking_sigs=sigs,
                         pt=pt)

    def register_idx(self, val):
        self.last_idx = PT(PDFEnum.INT, val)

    def register_gen(self, val):
        self.last_gen = PT(PDFEnum.INT, val)

    def register_offset(self, val):
        self.last_offset = PT(PDFEnum.INT, val)

    def register_type(self, val):
        self.last_type = PT(PDFEnum.CMD, val)

    def register_add_entry(self):
        children = []
        for f in ["idx", "gen", "offset", "type"]:
            children.append(getattr(self, f"last_{f}"))
        self.pt.add_child(PT(PDFEnum.XREF_TABLE_ENTRY,
                             children=children,
                             taint_tree=self.taint_sig.get_taint(),
                             first_taint=self.taint_sig.first_taint))
        self.reset()

    def reset(self):
        self.last_idx = None
        self.last_gen = None
        self.last_offset = None
        self.last_type = None
        self.taint_sig.reset()

    def register_ibm_bug(self):
        self.last_idx = 0
        self.last_offset = -1

    def register_pt_node(self, pt, from_obj):
        if isinstance(from_obj, GetObjFrame):
            if not pt.get_context(ParseReason):
                pt.add_context(ParseReason.create(self))
            self.do_register_pt(pt, True)
        else:
            self.OOPS("don't know how to handle pt registration from",
                      from_obj, pt)


class XpdfPTTracker(Tracker):
    tracker_name = "xpdf"
    additional_tracking_sigs = ["PARSE_XREF_TABLE"]
    frame_bases = [XpdfFrame]
    sig_bases = [XpdfMomentSignature]
    _old = Tracker.frame_bases
    Tracker.frame_bases = frame_bases
    LexerObjFrame = Tracker.do_register_subcls("LexerObjFrame")
    IntFrame = Tracker.do_register_subcls("IntFrame")
    NewParserFrame = Tracker.do_register_subcls("NewParserFrame")
    ArrayFrame = Tracker.do_register_subcls("ArrayFrame")
    DictFrame = Tracker.do_register_subcls("DictFrame")
    GfxStreamFrame = Tracker.do_register_subcls("GfxStreamFrame",
                                                attr={"fn_names":
                                                      ["_ZN3Gfx2goEi"]})
    ShiftObjFrame = Tracker.do_register_subcls("ShiftObjFrame",
                                               attr={"fn_names":
                                                     ["_ZN6Parser5shiftEv"]})
    ConstructXRefFrame = Tracker.do_register_subcls("ConstructXRefFrame",
                                                    attr={"fn_names":
                                                          ["_ZN4XRef13constructXRefEv"],
                                                          "reg_at_offset": False})

    Tracker.frame_bases = _old
    register_subcls = [
        ("ParserGetObj", sig_bases,
         {
            "push_frame_class": GetObjFrame,
            "fn_names": ["_ZN6Parser6getObjEP6ObjectiPh14CryptAlgorithmiiii"]
         }),
        ("GetParserObjId", sig_bases, {"parent_frame_class": GetObjFrame,
                                       "obj_id_offset": 56}),
        ("ShiftObjId", sig_bases, {"parser_id_offset": -56,
                                   "remove_when_flagged": False}),
        ("LexerGetObjCalled", sig_bases, {"fn_names": ["_ZN5Lexer6getObjEP6Object"],
                                          "push_frame_class": LexerObjFrame}),

        ("DictValueMoment", sig_bases, {}),
        ("DoubleObj", sig_bases, {}),
        ("BoolObj", sig_bases, {}),
        ("LexStrVal", sig_bases, {}),
        ("IntObj", sig_bases, {}),
        ("ObjFetchXRefNum", sig_bases, {"parent_frame_class": FetchFrame}),
        ("ObjFetchXRefGen", sig_bases, {"parent_frame_class": FetchFrame}),
        ("ObjInfoSig", sig_bases, {"struct_format": "l"}),
        ("NewDictMoment", sig_bases, {"push_frame_class": DictFrame,
                                      "parent_frame_class": DictFrame}),
        ("NewArrayMoment", sig_bases, {"push_frame_class": ArrayFrame,
                                       "parent_frame_class": ArrayFrame}),
        ("GetObjSimpleMoment", sig_bases, {"log_type": PCEntry}),
        ("GetObjIntMoment", sig_bases, {"push_frame_class": IntFrame,
                                        "log_type": PCEntry}),
        ("ErrorSig", sig_bases, {"parent_frame_class": GfxStreamFrame,
                                 "flag_addr_fn_name":
                                 "_Z5error13ErrorCategorylPKcz"}),
        ("XRefConstructNum", sig_bases, {"parent_frame_class":
                                         ConstructXRefFrame}),
        ("XRefConstructGen", sig_bases, {"parent_frame_class":
                                         ConstructXRefFrame}),
        ("XRefConstructOffset", sig_bases, {"parent_frame_class":
                                            ConstructXRefFrame}),
        ("XRefConstructId", sig_bases, {"parent_frame_class":
                                        ConstructXRefFrame}),

    ]


class NewParserMoment(XpdfNewFrameMoment, XpdfPopplerNewParserMoment):
    push_frame_class = XpdfPTTracker.NewParserFrame
    fn_names = ["_ZN6ParserC2EP4XRefP5Lexeri",
                "_ZN6ParserC1EP4XRefP5Lexeri"]

    def frame_args(self):
        return [self.where, self.container]

    class Where(IntEnum):
        UNKNOWN = 0
        OBJ_STREAM = auto()
        XREF_FETCH = auto()
        READ_XREF = auto()
        CONSTRUCT_XREF = auto()
        XREF_SUBSTREAM = auto()
        LINEARIZATION = auto()
        GFX_STREAM = auto()
        XREF_TRAILER = auto()

    def reset(self):
        self.where = None
        self.container = None

    @classmethod
    def setup(cls):
        cls.fetch_addr = cls.addrs_of("xref_fetch_new_parser")
        cls.obj_stream = cls.addrs_of("xref_obj_new_parser")
        cls.read_xref_start = cls.addrs_of("xref_read_start", 1)
        cls.read_xref_end = cls.addrs_of("xref_read_end", 1)
        cls.read_xref_table_start = cls.addrs_of("xref_read_table_start", 1)
        cls.read_xref_table_end = cls.addrs_of("xref_read_table_end", 1)
        cls.construct_xref_start = cls.addrs_of("construct_xref_start", 1)
        cls.construct_xref_end = cls.addrs_of("construct_xref_end", 1)
        cls.gfx_new = cls.addrs_of("gfx_display_new_parser")
        cls.linearization_new = cls.addrs_of("linearization_new_parser")

    def flag(self):
        # lookup address of caller
        callsite = self.manager.ml.stack.top()
        pc = callsite.pc

        def _in_range(start, end):
            return start <= pc and pc < end
        if pc in self.fetch_addr:
            self.where = self.Where.XREF_FETCH
        elif _in_range(self.read_xref_start, self.read_xref_end):
            self.where = self.Where.XREF_SUBSTREAM
        elif _in_range(self.read_xref_table_start, self.read_xref_table_end):
            self.where = self.Where.XREF_TRAILER
        elif _in_range(self.construct_xref_start, self.construct_xref_end):
            self.where = self.Where.CONSTRUCT_XREF
        elif pc in self.gfx_new:
            self.where = self.Where.GFX_STREAM
        elif pc in self.obj_stream:
            self.where = self.Where.OBJ_STREAM
        elif pc in self.linearization_new:
            self.where = self.Where.LINEARIZATION
        else:
            self.where = self.Where.UNKNOWN
        # now determine container type
        if self.where in [self.Where.XREF_FETCH]:
            self.container = PDFEnum.INDIRECT_OBJ
        elif self.where in [self.Where.OBJ_STREAM]:
            self.container = PDFEnum.STREAM_CONTENTS
        elif self.where in [self.Where.XREF_TRAILER,
                            self.Where.CONSTRUCT_XREF,
                            self.Where.LINEARIZATION,
                            self.Where.XREF_SUBSTREAM]:
            self.container = PDFEnum.CONTAINER
        elif self.where == self.Where.GFX_STREAM:
            self.container = PDFEnum.GFX_IMAGE_STREAM
        else:
            self.container = PDFEnum.UNKNOWN


class NewParserIdMoment(XpdfMomentSignature):
    sig_id_name = "NEW_PARSER_ID"
    log_type = MemEntry
    attr_name = "pc"
    remove_when_flagged = True
    flag_addr_name = "new_parser_id"
    parent_frame_class = XpdfPTTracker.NewParserFrame

    def reset(self):
        self.obj_id = None
        self.flagged = False

    def flag(self):
        self.obj_id = self.flagged_entry.addr
        self.parent_frame.register_parser_id(self.obj_id)


class XpdfPTMoment(XpdfPopplerPTMoment, XpdfMomentSignature):
    parent_frame_class = GetObjFrame


class ArrayFrameReturn(ReturnSignature, XpdfPTMoment):
    sig_id_name = "ARRAY_FRAME_RETURN"
    log_type = CallEntry
    attr_name = "pc"
    pt_container_type = PDFEnum.ARRAY_END
    expected_lex_objvalue = b"]"
    expected_lex_objtype = LexType.CMD
    parent_frame_class = XpdfPTTracker.ArrayFrame

    @classmethod
    def setup(cls):
        # virtpc = 0x2bb346  # Parser.cc:104, basic block when shift() called
        # eofvirtpc = 0x2bb31f  # Parser.cc:101, getPos()
        # recursionerror = 0x2bb61f  # Parser.cc:196 Object(objError)
        cls.check_values = cls.addrs_of("array_end")
        # cls.check_values = cls.addrs_of("int_frame_ret")
        cls.eof_value = cls.addrs_of("array_end_eof", 1)

    def reset(self):
        self.eof = False
        self.recursion_error = False

    def package_pt_obj(self, obj: LexObj) -> PT:
        if self.eof:
            return PT(PDFEnum.EOF)
        else:
            return super().package_pt_obj(obj)

    def get_lex_obj(self):
        return self.manager.shift_objs.obj1()

    def check_lex_obj(self, obj: LexObj) -> bool:
        if self.eof:
            return self._do_check("obj type", obj, LexType.EOF, "type")
        else:
            return self._do_check("obj type", obj, LexType.CMD, "type") and \
                self._do_check("obj value", obj, b"]", "value")

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, CallEntry) and \
           log_entry.pc == self.eof_value:
            self.eof = True
        super().do_log_entry(log_entry)


class MakeStreamFrame(XpdfPopplerMakeStreamFrame, XpdfFrame):
    fn_names = ["_ZN6Parser10makeStreamEP6ObjectPh14CryptAlgorithmiiii"]

    def on_pop(self, new_top):
        super().on_pop(new_top)
        new_top.register_pt_node(self.pt, self)


class CopyStringMoment(XpdfPopplerCopyStringMoment):
    sig_id_name = XpdfPopplerCopyStringMoment._sig_id_name
    supported_group_ids = ["xpdf"]

    @classmethod
    def setup(cls):
        cls.fn_starts = cls.get_fn_abs_addr("strcpy",
                                            anytype=True)
        cls.copystr_call_pcs = cls.addrs_of("copystr_call",
                                            lib_name=Version.primary_binary())
        cls.fn_read_addrs = cls.addrs_of("copystr_fn_read")
        cls.skip_read_addrs = cls.addrs_of("copystr_skip_read")
        cls.alt_read_addrs = cls.addrs_of("copystr_alt_read")


class IntFrameReturn(ReturnSignature, XpdfMomentSignature):
    primary_binary = True
    sig_id_name = "INT_FRAME_RETURN"
    remove_when_flagged = True

    @classmethod
    def setup(cls):
        cls.ref_addr = cls.addrs_of("int_frame_ref")
        cls.check_values = cls.addrs_of("int_frame_ret")
        cls.check_values.extend(cls.ref_addr)

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, PCEntry) or is_kind(log_entry, CallEntry):
            if log_entry.pc in self.ref_addr:
                self.is_reference = True
            if log_entry.pc in self.check_values:
                self.do_flag(log_entry)

    def reset(self):
        self.is_reference = False
        self.is_error = False


class DictKeyMoment(XpdfPTMoment):
    sig_id_name = "DICT_KEY"
    remove_when_flagged = True
    pt_container_type = PDFEnum.DICT_KEY
    parent_frame_class = XpdfPTTracker.DictFrame

    def __init__(self, key_obj=None):
        # when DICT_KEY is registered by DictFrame or by DICT_VALUE,
        # the DICT_KEY object is obj1, but it it is registered by
        # a DICT_KEY moment, which happens when there is an error
        # parsing the previous key, the key object is obj2() b/c
        # shift() is called after the dict key error moment happens
        # and before the next DICT_KEY moment
        super().__init__()
        self.first_lex_obj = key_obj if key_obj else self.first_lex_obj

    @classmethod
    def setup(cls):
        # self.dict_start_obj = dict_start_obj
        # virtpc = 0x2bb3f9  # Parser.cc:123
        # not_name_err = 0x2bb4c8  # Parser.cc:112 Parser::getPos()
        # other_err = 0x2bb61f  # Parser.cc:196 Object(objError)
        cls.dict_key = cls.addrs_of("dict_key", 1)
        cls.not_name_err_pc = cls.addrs_of("dict_key_not_name", 1)
        cls.check_values = [cls.dict_key, cls.not_name_err_pc]

    def reset(self):
        self.error = False
        self.not_name = False

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, PCEntry) and \
           self.dict_key == log_entry.pc:
            self.do_flag(log_entry)
        elif is_kind(log_entry, CallEntry) and \
             self.not_name_err_pc == log_entry.pc:
            self.not_name = True
            self.do_flag(log_entry)


class DictFrameReturn(XpdfPopplerDictFrameReturn, XpdfMomentSignature):
    primary_binary = True
    supported_group_ids = ["xpdf"]
    sig_id_name = XpdfPopplerDictFrameReturn._sig_id_name
    enable_sig_frame_class = GetObjFrame
    parent_frame_class = XpdfPTTracker.DictFrame

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, PCEntry) and log_entry.pc == self.check_value or \
           (is_kind(log_entry, CallEntry) and
            log_entry.call_kind is log_entry.CALL and log_entry.pc == self.eof_pc):
            self.do_flag(log_entry)


class GfxStreamSig(XpdfPopplerGfxStreamSig, XpdfMomentSignature):
    parent_frame_class = XpdfPTTracker.GfxStreamFrame

    @classmethod
    def setup(cls):
        for k in ["gfx_update_display", "gfx_command_aborted"]:
            if k in cls.reg_names:
                del cls.reg_names[k]
        super(GfxStreamSig, cls).setup()
        cls.abort_check = cls.addrs_of("gfx_command_check_aborted")
        cls.abort_check_done = cls.addrs_of("gfx_command_check_aborted_done")
        cls.not_aborted = cls.addrs_of("gfx_command_not_aborted")

    def reset(self):
        super().reset()
        self.checking_abort = False

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, PCEntry) and log_entry.pc in self.abort_check:
            self.checking_abort = True
        elif is_kind(log_entry, MemEntry) and \
             log_entry.pc in self.abort_check_done:
            if self.checking_abort:
                self.parent_frame.register_command_aborted(self)
            self.checking_abort = False
        elif self.checking_abort and is_kind(log_entry, MemEntry) and \
             log_entry.pc in self.not_aborted:
            self.checking_abort = False
        super().do_log_entry(log_entry)


class ParseXRefTableSig(XRefConstructSigBase, XpdfMomentSignature):
    parent_frame_class = ParseXRefTableFrame


class XRefTableFlagSig(ParseXRefTableSig):
    log_type = PCEntry
    attr_name = "pc"
    remove_when_flagged = False
    parent_flag_fn = None

    def flag(self):
        getattr(self.parent_frame, self.parent_flag_fn)()


class XRefTableOff(ParseXRefTableSig):
    sig_id_name = "PARSE_XREF_TABLE_OFFSET"
    flag_addr_name = "xref_table_off"
    entry_field = "offset"
    struct_format = "i"


class XRefTableGen(ParseXRefTableSig):
    sig_id_name = "PARSE_XREF_TABLE_GEN"
    flag_addr_name = "xref_table_gen"
    entry_field = "gen"
    struct_format = "i"


class XRefTableIdx(ParseXRefTableSig):
    sig_id_name = "PARSE_XREF_TABLE_IDX"
    flag_addr_name = "xref_table_entry_idx"
    entry_field = "idx"
    struct_format = "i"


class XRefTableEntryType(XpdfMomentSignature):
    sig_id_name = "PARSE_XREF_TABLE_TYPE"
    log_type = PCEntry
    attr_name = "pc"
    flag_addr_name = "xref_table_type"
    parent_frame_class = ParseXRefTableFrame
    remove_when_flagged = False

    def flag(self):
        typ = "n" if self.flagged_entry.pc == self.check_values[0] else "f"
        self.parent_frame.register_type(typ)


class XRefTableIdxAlt(XRefTableFlagSig):
    sig_id_name = "PARSE_XREF_TABLE_IDX_ALT"
    flag_addr_name = "xref_table_entry_idx_alt"
    parent_flag_fn = "register_ibm_bug"


class XRefTableAddEntry(XRefTableFlagSig):
    sig_id_name = "PARSE_XREF_TABLE_ADD_ENTRY"
    flag_addr_name = "xref_table_add_entry"
    parent_flag_fn = "register_add_entry"


class FetchFlagSig(XRefTableFlagSig):
    parent_frame_class = FetchFrame


class CachedFetchSig(FetchFlagSig):
    sig_id_name = "XREF_FETCH_CACHED"
    flag_addr_name = "xref_fetch_cache"
    parent_flag_fn = "register_cached_fetch"


class FailedFetchSig(FetchFlagSig):
    sig_id_name = "XREF_FETCH_FAILED"
    flag_addr_name = "xref_fetch_failed"
    parent_flag_fn = "register_fetch_fail"
