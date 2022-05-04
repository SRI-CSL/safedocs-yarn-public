# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from tracetools.signatures.xpdf_poppler import XpdfPopplerFrame, LexType, \
    LexObj, XpdfPopplerMomentSignature, XpdfPopplerValueSignature, \
    XpdfPopplerPTTracker as Tracker, \
    LexerObjFrame as XpdfPopplerLexerObjFrame, \
    MakeStreamFrame as XpdfPopplerMakeStreamFrame, \
    NewParserMoment as XpdfPopplerNewParserMoment, \
    XpdfPopplerPTMoment, \
    GfxStreamSig as XpdfPopplerGfxStreamSig, \
    XRefConstructSigBase

from tracetools.signatures.pdf import PDFPT as PT
from tracetools.signatures.pdf import PDFEnum
from tracetools.signatures.signatures import ReturnSignature, \
    NewFrameMoment, SigID
from tracetools.signatures.versions import Version
from tracetools.log_entries import is_kind, MemEntry, CallEntry, PCEntry
from aenum import IntEnum, auto
from tracetools.signatures.context import DataContext, ParseReason
import dataclasses


class PopplerFrame(XpdfPopplerFrame):
    lib_name = "libpoppler.so.94"


class LexerObjFrame(XpdfPopplerLexerObjFrame, PopplerFrame):

    @classmethod
    def setup(cls):
        cls.callpcs = [cls.addrs_of("lexergetobj%d" % i, 1)
                       for i in range(1, 4)]
        cls.lib_start = Version.lib_starts(cls.lib_name, 1)


class MakeStreamFrame(XpdfPopplerMakeStreamFrame, PopplerFrame):
    fn_names = ["_ZN6Parser10makeStreamEO6ObjectPh14CryptAlgorithmiiiib"]

    def on_pop(self, new_top):
        super(MakeStreamFrame, self).on_pop(new_top)
        if self.shift_count < 2:
            self.OOPS("Shift should have been called at least 2 times",
                      f"but was only called {self.shift_count} time(s)")
        elif self.shift_count == 2:
            print("Note: endstream() missing from stream or incorrect "
                  "stream length, this is a fixup")
        # todo: if `make_stream_set_length` address/flag reached
        # this means that poppler substituted calculated length into
        # stream's dictionary
        new_top.register_pt_node(self.pt, self)


class XrefStmEntryType(IntEnum):
    FREE = 0
    UNCOMPRESSED = auto()
    COMPRESSED = auto()
    NONE = auto()


class ReadXRefStreamFrame(PopplerFrame):
    sig_id_name = "READ_XREF_STREAM"
    log_type = CallEntry
    attr_name = "target_addr"
    fn_names = ["_ZN4XRef21readXRefStreamSectionEP6StreamPKiii"]
    entry_type_idx = [XrefStmEntryType.FREE,
                      XrefStmEntryType.UNCOMPRESSED,
                      XrefStmEntryType.COMPRESSED]

    @classmethod
    def setup(cls):
        cls.gen_addrs = cls.addrs_of("xref_stm_section_gen")

    def __init__(self, flagged_sig):
        sigs = set([self.manager.sig_from_id(s) for s in
                    [SigID.XREF_STREAM_ENTRY_NUM,
                     SigID.XREF_STREAM_ENTRY_GEN,
                     SigID.XREF_STREAM_ENTRY_OFFSET]])
        self.num = None
        self.gen = None
        self.type = None
        self.offset = None
        pt = PT(PDFEnum.XREF_STREAM_TABLE)
        pt.add_context(ParseReason.create(self))
        super(ReadXRefStreamFrame, self).__init__(
            flagged_sig, pt_tracking_sigs=sigs, pt=pt,
        )

    def register_num(self, val, pc):
        self.num = val

    def register_gen(self, val, pc):
        self.gen = val
        self.type = int(self.entry_type_idx[self.gen_addrs.index(pc)])
        children = [PT(PDFEnum.INT, value=getattr(self, n))
                    for n in ["num", "gen", "offset", "type"]]
        self.add_pt_child(
            PT(PDFEnum.XREF_TABLE_ENTRY, children=children)
        )

    def register_offset(self, val, pc):
        self.offset = val

    def on_pop(self, new_top):
        self.do_register_pt(self.pt)
        super(ReadXRefStreamFrame, self).on_pop(new_top)

    def debug_string(self):
        return super(ReadXRefStreamFrame, self).debug_string() + \
            f"\nnum: {self.num}, gen: {self.gen}, offset: " + \
            f"{self.offset}, type: {self.type}"


class PopplerMomentSignature(XpdfPopplerMomentSignature):
    lib_name = "libpoppler.so.94"


class PopplerValueSignature(XpdfPopplerValueSignature, PopplerMomentSignature):
    pass


class PopplerPTTracker(Tracker):
    tracker_name = "poppler"
    _name = "tracetools.signatures.poppler"
    sig_bases = [PopplerMomentSignature]
    frame_bases = [PopplerFrame]
    _old = Tracker.frame_bases
    Tracker.frame_bases = frame_bases
    ArrayFrame = Tracker.do_register_subcls("ArrayFrame")
    DictFrame = Tracker.do_register_subcls("DictFrame")
    IntFrame = Tracker.do_register_subcls("IntFrame")
    GetObjFrame = Tracker.do_register_subcls("GetObjFrame")
    NewParserFrame = Tracker.do_register_subcls("NewParserFrame")
    GfxStreamFrame = Tracker.do_register_subcls("GfxStreamFrame",
                                                attr={"fn_names":
                                                      ["_ZN3Gfx2goEb"]})
    ShiftObjFrame = Tracker.do_register_subcls("ShiftObjFrame",
                                               attr={"fn_names":
                                                     ["_ZN6Parser5shiftEi",
                                                      "_ZN6Parser5shiftEPKci"]})
    FetchFrame = Tracker.do_register_subcls("FetchFrame",
                                            attr={"fn_names":
                                                  ["_ZN4XRef5fetchEiii"]})
    ConstructXRefFrame = Tracker.do_register_subcls("ConstructXRefFrame",
                                                    attr={"fn_names":
                                                          ["_ZN4XRef13constructXRefEPbb"]})
    Tracker.frame_bases = _old
    register_subcls = [
        ("ParserGetObj", sig_bases,
         {
            "push_frame_class": GetObjFrame,
            "fn_names": ["_ZN6Parser6getObjEbPh14CryptAlgorithmiiiib"]
         }),
        ("GetParserObjId", sig_bases, {"parent_frame_class": GetObjFrame}),
        ("ShiftObjId", sig_bases, {}),
        ("LexerGetObjCalled", sig_bases, {"fn_names": ["_ZN5Lexer6getObjEi",
                                                       "_ZN5Lexer6getObjEPKci"]}),
        ("GetObjSimpleMoment", sig_bases, {}),
        ("GetObjIntMoment", sig_bases, {"push_frame_class": IntFrame}),

        ("DictValueMoment", sig_bases, {}),
        ("DoubleObj", sig_bases, {}),
        ("BoolObj", sig_bases, {}),
        ("LexStrVal", sig_bases, {}),
        ("IntObj", sig_bases, {}),
        ("ObjInfoSig", sig_bases, {}),
        ("NewDictMoment", sig_bases, {"push_frame_class": DictFrame,
                                      "parent_frame_class": DictFrame}),
        ("NewArrayMoment", sig_bases, {"push_frame_class": ArrayFrame,
                                       "parent_frame_class": ArrayFrame}),
        ("DictFrameReturn", sig_bases, {"enable_sig_frame_class": GetObjFrame,
                                        "parent_frame_class": DictFrame}),
        ("CopyStringMoment", [], {"caller_lib_name": "libpoppler.so.94",
                                  "additional_libs": ["libpoppler.so.94"],
                                  "supported_group_ids": ["poppler"]}),
        ("ObjFetchXRefGen", sig_bases, {"parent_frame_class": FetchFrame}),
        ("ObjFetchXRefNum", sig_bases, {"parent_frame_class": FetchFrame}),
        ("ErrorSig", sig_bases, {"parent_frame_class": GfxStreamFrame,
                                 "flag_addr_fn_name":
                                 "_Z5error13ErrorCategoryxPKcz"}),
        ("XRefConstructNum", sig_bases, {"parent_frame_class":
                                         ConstructXRefFrame}),
        ("XRefConstructGen", sig_bases, {"parent_frame_class":
                                         ConstructXRefFrame}),
        ("XRefConstructOffset", sig_bases, {"parent_frame_class":
                                            ConstructXRefFrame}),
        ("XRefConstructId", sig_bases, {"parent_frame_class":
                                        ConstructXRefFrame}),

    ]


class PopplerNewFrameMoment(PopplerMomentSignature, NewFrameMoment):
    pass


class PopplerPTMoment(XpdfPopplerPTMoment, PopplerMomentSignature):
    parent_frame_class = PopplerPTTracker.GetObjFrame


class RecursionErrorMoment(PopplerPTMoment):
    sig_id_name = "RECURSION_ERROR"
    log_type = CallEntry
    attr_name = "pc"
    remove_when_flagged = True

    def get_lex_obj(self):
        return LexObj(LexType.ERROR)

    @classmethod
    def setup(cls):
        # rec_virtpc = 0x2bb20e  # Parser.cc:88, Object::Object()
        cls.rec_value = cls.addrs_of("recursion_error", 1)
        cls.check_values = [cls.rec_value]


class ArrayFrameReturn(ReturnSignature, PopplerPTMoment):
    sig_id_name = "ARRAY_FRAME_RETURN"
    log_type = CallEntry
    attr_name = "pc"
    pt_container_type = PDFEnum.ARRAY_END
    expected_lex_objvalue = b"]"
    expected_lex_objtype = LexType.CMD
    parent_frame_class = PopplerPTTracker.ArrayFrame

    @classmethod
    def setup(cls):
        # virtpc = 0x2bb346  # Parser.cc:104, basic block when shift() called
        # eofvirtpc = 0x2bb31f  # Parser.cc:101, getPos()
        # recursionerror = 0x2bb61f  # Parser.cc:196 Object(objError)
        cls.check_value = cls.addrs_of("array_end", 1)
        cls.eof_value = cls.addrs_of("array_end_eof", 1)
        cls.rec_error_pc = cls.addrs_of("array_end_recursion_error", 1)
        cls.check_values = [cls.eof_value, cls.rec_error_pc]

    def reset(self):
        self.eof = False
        self.recursion_error = False

    def package_pt_obj(self, obj: LexObj) -> PT:
        if self.recursion_error:
            return PT(PDFEnum.ERROR)
        elif self.eof:
            return PT(PDFEnum.EOF)
        else:
            return super(ArrayFrameReturn, self).package_pt_obj(obj)

    def get_lex_obj(self):
        return self.manager.shift_objs.obj1()

    def check_lex_obj(self, obj: LexObj) -> bool:
        if self.eof:
            return self._do_check("obj type", obj, LexType.EOF, "type")
        elif not self.recursion_error:
            return self._do_check("obj type", obj, LexType.CMD, "type") and \
                self._do_check("obj value", obj, b"]", "value")
        else:
            # nothing to enforce if there was a recursion error
            return True

    def do_log_entry(self, log_entry):
        if (is_kind(log_entry, PCEntry) and
           log_entry.pc == self.check_value) or \
           (is_kind(log_entry, CallEntry) and
            log_entry.pc in self.check_values):
            if log_entry.pc == self.eof_value:
                self.eof = True
            elif log_entry.pc == self.rec_error_pc:
                self.recursion_error = True
            self.do_flag(log_entry)


class DictKeyMoment(PopplerPTMoment):
    sig_id_name = "DICT_KEY"
    remove_when_flagged = True
    pt_container_type = PDFEnum.DICT_KEY
    parent_frame_class = PopplerPTTracker.DictFrame

    def __init__(self, key_obj=None):
        # when DICT_KEY is registered by DictFrame or by DICT_VALUE,
        # the DICT_KEY object is obj1, but it it is registered by
        # a DICT_KEY moment, which happens when there is an error
        # parsing the previous key, the key object is obj2() b/c
        # shift() is called after the dict key error moment happens
        # and before the next DICT_KEY moment
        super(DictKeyMoment, self).__init__()
        self.first_lex_obj = key_obj if key_obj else self.first_lex_obj

    @classmethod
    def setup(cls):
        # self.dict_start_obj = dict_start_obj
        # virtpc = 0x2bb3f9  # Parser.cc:123
        # not_name_err = 0x2bb4c8  # Parser.cc:112 Parser::getPos()
        # other_err = 0x2bb61f  # Parser.cc:196 Object(objError)
        cls.dict_key = cls.addrs_of("dict_key", 1)
        cls.not_name_err_pc = cls.addrs_of("dict_key_not_name", 1)
        cls.other_err_pc = cls.addrs_of("dict_key_other_err", 1)
        cls.check_values = [cls.dict_key, cls.not_name_err_pc,
                            cls.other_err_pc]

    def reset(self):
        self.error = False
        self.not_name = False

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, PCEntry) and \
           self.dict_key == log_entry.pc:
            self.do_flag(log_entry)
        elif is_kind(log_entry, CallEntry):
            if self.not_name_err_pc == log_entry.pc:
                self.not_name = True
                self.do_flag(log_entry)
            elif self.other_err_pc == log_entry.pc:
                self.error = True
                self.do_flag(log_entry)

    def package_pt_obj(self, obj):
        self.pt_container_type = PDFEnum.DICT_KEY_ERROR \
            if self.error or self.not_name else PDFEnum.DICT_KEY
        return super(DictKeyMoment, self).package_pt_obj(obj)

    def flag_enable_sigs(self):
        if self.not_name:
            next_sig = self.manager.sig_from_id(SigID.DICT_KEY,
                                                self.manager.shift_objs.obj2())
        elif not self.error:
            next_sig = self.manager.sig_from_id(SigID.DICT_VALUE)
        if next_sig:
            self.parent_sig_enable_frame.add_ghostsite_sig(next_sig)


class Int64Obj(PopplerValueSignature):
    sig_id_name = "INT64_VAL"
    flag_addr_name = "obj_int64_val"


class NewParserXrefID(PopplerValueSignature):
    sig_id_name = "NEW_PARSER_XREF_ID"
    parent_frame_class = PopplerPTTracker.NewParserFrame
    flag_addr_name = "lexer_xref_id"
    remove_when_flagged = False
    log_type = MemEntry
    attr_name = "pc"
    struct_format = "Q"

    def flag(self):
        self.parent_frame.register_xref_id(
            self.unpack_val(self.flagged_entry.value)
        )


# not really using this for anything at the moment,
# but i'm curious as to whether poppler creates
# multiple XRef instances/XRef copies
class NewXrefID(PopplerMomentSignature):
    sig_id_name = "NEW_XREF"
    flag_addr_name = "new_xref_id"
    remove_when_flagged = False
    log_type = MemEntry
    attr_name = "pc"

    @dataclasses.dataclass(repr=False)
    class XRefInfo(DataContext):
        xref_id: str
        stack_str: str

    def reset(self):
        self.all_objs = []

    def flag(self):
        # addr is address of XRef->capacity field
        # print("New XRef at %x" % self.flagged_entry.addr - 24)
        self.all_objs.append(
            self.XRefInfo("%x" % (self.flagged_entry.addr - 24),
                          str(self.manager.ml.stack))
        )


class NewParserMoment(XpdfPopplerNewParserMoment):
    lib_name = "libpoppler.so.94"
    push_frame_class = PopplerPTTracker.NewParserFrame
    fn_names = ["_ZN6ParserC1EP4XRefP6Streamb",
                "_ZN6ParserC1EP4XRefP6Objectb",
                "_ZN6ParserC2EP4XRefP6Streamb",
                "_ZN6ParserC2EP4XRefP6Objectb"]

    class Where(IntEnum):
        UNKNOWN = 0
        PARSE_ENTRY = auto()
        OBJ_STREAM_0 = auto()
        OBJ_STREAM_1 = auto()
        READ_XREF = auto()
        XREF_FETCH = auto()
        CONSTRUCT_XREF = auto()
        LINEARIZATION = auto()
        GFX_STREAM = auto()
        HINTS = auto()

    @classmethod
    def setup(cls):
        cls.parse_entry_start = cls.addrs_of("xref_parse_entry_start", 1)
        cls.parse_entry_end = cls.addrs_of("xref_parse_entry_end", 1)
        cls.obj_stream = cls.addrs_of("xref_obj_new_parser")
        cls.read_xref_start = cls.addrs_of("xref_read_start", 1)
        cls.read_xref_end = cls.addrs_of("xref_read_end", 1)
        cls.xref_fetch_start = cls.addrs_of("xref_fetch_start", 1)
        cls.xref_fetch_end = cls.addrs_of("xref_fetch_end", 1)
        cls.xref_fetch_obj = cls.addrs_of("xref_fetch", 1)
        cls.construct_xref_start = cls.addrs_of("construct_xref_start", 1)
        cls.construct_xref_end = cls.addrs_of("construct_xref_end", 1)
        cls.linearization_start = cls.addrs_of("linearization_start", 1)
        cls.linearization_end = cls.addrs_of("linearization_end", 1)
        cls.hints_new = cls.addrs_of("hint_new_parser", 1)
        cls.gfx_new = cls.addrs_of("gfx_display_new_parser", 1)

    def flag(self):
        # lookup address of caller
        callsite = self.manager.ml.stack.top()
        pc = callsite.pc

        def _in_range(start, end):
            return start <= pc and pc < end
        if _in_range(self.parse_entry_start, self.parse_entry_end):
            self.where = self.Where.PARSE_ENTRY
        elif _in_range(self.read_xref_start, self.read_xref_end):
            self.where = self.Where.READ_XREF
        elif _in_range(self.construct_xref_start, self.construct_xref_end):
            self.where = self.Where.CONSTRUCT_XREF
        elif pc == self.obj_stream[0]:
            self.where = self.Where.OBJ_STREAM_0
        elif pc == self.obj_stream[1]:
            self.where = self.Where.OBJ_STREAM_1
        elif _in_range(self.linearization_start, self.linearization_end):
            self.where = self.Where.LINEARIZATION
        elif _in_range(self.xref_fetch_start, self.xref_fetch_end):
            self.where = self.Where.XREF_FETCH
        elif pc == self.gfx_new:
            self.where = self.Where.GFX_STREAM
        elif pc == self.hints_new:
            self.where == self.Where.HINTS
        else:
            self.where = self.Where.UNKNOWN
        # now determine container type
        if self.where in [self.Where.LINEARIZATION, self.Where.HINTS,
                          self.Where.XREF_FETCH]:
            self.container = PDFEnum.INDIRECT_OBJ
        elif self.where in [self.Where.OBJ_STREAM_0, self.Where.OBJ_STREAM_1]:
            self.container = PDFEnum.STREAM_CONTENTS
        elif self.where == self.Where.PARSE_ENTRY:
            self.container = PDFEnum.XREF_OBJ
        elif self.where == self.Where.CONSTRUCT_XREF:
            self.container = PDFEnum.CONTAINER
        elif self.where == self.Where.GFX_STREAM:
            self.container = PDFEnum.GFX_IMAGE_STREAM
        elif self.where == self.Where.READ_XREF:
            self.container = PDFEnum.XREF_TABLE
        else:
            self.container = PDFEnum.UNKNOWN


class NewParserIdMoment(PopplerMomentSignature):
    sig_id_name = "NEW_PARSER_ID"
    log_type = MemEntry
    attr_name = "pc"
    remove_when_flagged = True
    parent_frame_class = PopplerPTTracker.NewParserFrame

    @classmethod
    def setup(cls):
        # cls.new_parser_stream_id = cls.addrs_of("new_parser_stream_id", 1)
        # cls.new_parser_obj_id = cls.addrs_of("new_parser_obj_id", 1)
        cls.new_parser_stream_id_2 = cls.addrs_of("new_parser_stream_id_2", 1)
        cls.new_parser_obj_id_2 = cls.addrs_of("new_parser_obj_id_2", 1)
        # cls.check_pcs = [cls.new_parser_stream_id, cls.new_parser_obj_id]
        cls.check_values = [cls.new_parser_stream_id_2,
                            cls.new_parser_obj_id_2]

    def reset(self):
        self.obj_id = None
        self.flagged = False

    def flag(self):
        # we generally use inlineImg as the parser ID (but here we use
        # allowStreams because it is accessed before lexer.getObj) ,
        # so add the difference between the offsets of the two
        # instance fields
        if self.flagged_entry.typ == self.flagged_entry.READ:
            self.obj_id = self.flagged_entry.value + 0xe0
        else:
            # some versions of poppler are hooked differently
            self.obj_id = self.flagged_entry.addr
        self.parent_frame.register_parser_id(self.obj_id)


class GetObjError(PopplerMomentSignature):
    sig_id_name = "GET_OBJ_ERROR"
    remove_when_flagged = True

    @classmethod
    def setup(cls):
        cls.check_values = cls.addrs_of("array_end_recursion_error")

    def flag(self):
        self.parent_frame.set_pt_as(PDFEnum.ERROR)


class IntFrameReturn(ReturnSignature, PopplerMomentSignature):
    sig_id_name = "INT_FRAME_RETURN"
    remove_when_flagged = True
    log_type = CallEntry
    attr_name = "pc"
    flag_addr_name = "int_frame_ret"

    @classmethod
    def setup(cls):
        cls.check_values = cls.addrs_of("int_frame_ret")

    def reset(self):
        self.is_reference = False
        self.is_error = False

    def flag(self):
        idx = self.check_values.index(self.flagged_entry.pc)
        self.is_reference = idx == 0
        self.is_error = idx == 2


class XRefStmSig(XRefConstructSigBase, PopplerMomentSignature):
    parent_frame_class = ReadXRefStreamFrame

    def flag(self):
        getattr(self.parent_frame, f"register_{self.entry_field}")(
            self.unpack_val(self.flagged_entry.value), self.flagged_entry.pc
        )


class XrefStreamOffset(XRefStmSig):
    sig_id_name = "XREF_STREAM_ENTRY_OFFSET"
    flag_addr_name = "xref_stm_section_offset"
    entry_field = "offset"
    struct_format = "Q"


class XrefStreamGen(XRefStmSig):
    sig_id_name = "XREF_STREAM_ENTRY_GEN"
    flag_addr_name = "xref_stm_section_gen"
    entry_field = "gen"
    struct_format = "Q"


class XrefStreamNum(XRefStmSig):
    sig_id_name = "XREF_STREAM_ENTRY_NUM"
    flag_addr_name = "xref_stm_section_idx2"
    entry_field = "num"
    struct_format = "i"


class GfxStreamSig(XpdfPopplerGfxStreamSig, PopplerMomentSignature):
    parent_frame_class = PopplerPTTracker.GfxStreamFrame
    reg_names = XpdfPopplerGfxStreamSig.reg_names
    reg_names["gfx_update_display"] = "register_update_display"
    reg_names["gfx_command_aborted"] = "register_command_aborted",



# embedded CMap/CIDFont parsing -- see also CharCodeToUnicode::parseCMap1, CharCodeToUnicode.cc
