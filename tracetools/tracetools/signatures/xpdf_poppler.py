# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from tracetools.signatures.utils import return_pc_from_call_pc
from tracetools.signatures.ghoststack import PTStackOverlayEntry
from tracetools.signatures.pdf import PDFPT as PT
from tracetools.signatures.pdf import PDFLexObj, PDFEnum, PDFPTMoment, \
    ProcessStreamInfo, XRefTableInfo
from tracetools.signatures.utils import OOPS
from tracetools.signatures.evaluator import SigPTEval
from tracetools.signatures.utils import SigEvalException
from tracetools.signatures.signatures import MomentSignature, \
    ReturnSignature, NewFrameMoment, SigID
from tracetools.log_entries import is_kind, MemEntry, CallEntry, PCEntry, \
    FileWriteEntry
from aenum import IntEnum, auto
from tracetools.signatures.libc import LibcMomentSignature
from tracetools.signatures.context import DataContext, ParseReason
import dataclasses
import typing


# Do not change this enum

class LexType(IntEnum):
    BOOL = 0
    INT = auto()
    REAL = auto()
    STRING = auto()
    NAME = auto()
    NULL = auto()
    ARRAY = auto()
    DICT = auto()
    STREAM = auto()
    REF = auto()
    CMD = auto()
    ERROR = auto()
    EOF = auto()
    NONE = auto()
    INT64 = auto()
    DEAD = auto()
    UNKNOWN = auto()


class LexObj(PDFLexObj):
    type_enum = LexType


class ShiftObjException(Exception):
    pass


class ParserObjContainer():
    _debug = False
    _max_size = 5

    def __init__(self):
        self._active_id = None
        self._shift_objs = {}
        self._num_shifts = {}
        self._parser_kind = {}
        self._pts = {}
        self._current_pts = {}
        self._pt_stack = {}
        self._track_pt = {}
        self._prev_id = None
        self._xref_ids = {}
        self._active_container = []

    @property
    def shift_objs(self):
        return self._active_container

    def old_obj(self, i):
        if i >= len(self.shift_objs):
            return None
        else:
            return self.shift_objs[-1*i]

    def obj1(self):
        return self.shift_objs[-2]

    def obj2(self):
        return self.shift_objs[-1]

    def _get_set(self, dict_name, obj_id, set_val=None):
        obj_id = self._active_id if obj_id is None else obj_id
        if set_val is not None:
            getattr(self, dict_name)[obj_id] = set_val
        return getattr(self, dict_name)[obj_id]

    def parser_kind(self, obj_id=None):
        return self._get_set("_parser_kind", obj_id)

    def track_pt(self, track=None, obj_id=None):
        return self._get_set("_track_pt", obj_id, track)

    def parser_pt(self, obj_id=None, root=False):
        return self._get_set("_pts" if root else "_current_pts",
                             obj_id)

    def append_pt_child(self, pt, obj_id=None):
        self._get_set("_current_pts", obj_id).add_child(pt)

    def push_pt(self, pt, obj_id=None):
        self.append_pt_child(pt, obj_id)
        self._get_set("_current_pts", obj_id, pt)
        self._get_set("_pt_stack", obj_id).append(pt)

    def pop_pt(self, obj_id=None):
        pt = self._get_set("_pt_stack", obj_id).pop()
        self._get_set("_current_pts", obj_id,
                      self._get_set("_pt_stack", obj_id)[-1])
        return pt

    def register_new_parser(self, obj_id, kind, pt_root, track_pt, xref_id):
        if obj_id in self._pts:
            # then an old parser id is being reused,
            # delete existing information
            for i in ["_pts", "_current_pts",
                      "_pt_stack", "_shift_objs",
                      "_num_shifts", "_parser_kind",
                      "_track_pt", "_xref_ids"]:
                del getattr(self, i)[obj_id]
        # self.set_active_id(obj_id)
        self._get_container(obj_id)
        self._parser_kind[obj_id] = kind
        self._pts[obj_id] = pt_root
        self._current_pts[obj_id] = pt_root
        self._pt_stack[obj_id] = [pt_root]
        self._track_pt[obj_id] = track_pt
        self._num_shifts[obj_id] = 0
        self._xref_ids[obj_id] = xref_id

    def shift(self, obj, obj_id=None, increment_shifts=True):
        if not isinstance(obj, LexObj):
            OOPS(ShiftObjException, "Trying to shift non-LexObj", type(obj),
                 obj)
        if obj.type == LexType.ARRAY:
            OOPS(ShiftObjException, "shifting array", obj)
        obj_id = self._active_id if obj_id is None else \
            self.set_active_id(obj_id)
        self._active_container.append(obj)
        if increment_shifts:
            self._num_shifts[obj_id] += 1
        num_active = len(self._active_container)
        if not self._debug and num_active > self._max_size:
            for _ in range(num_active - self._max_size):
                # pop oldest entries from beginning of list (queue)
                self._active_container.pop(0)

    def set_active_id(self, obj_id):
        if obj_id != self._active_id:
            self._prev_id = self._active_id
            self._active_id = obj_id
        self._active_container = self._get_container(self._active_id)
        return self._active_id

    def __repr__(self):
        return "%s" % [s for s in self.shift_objs]

    def num_shifts(self, obj_id=None):
        obj_id = self._active_id if obj_id is None else obj_id
        return self._num_shifts.get(obj_id, 0)

    def _get_container(self, obj_id):
        c = self._shift_objs.get(obj_id, None)
        if c is None:
            self._shift_objs[obj_id] = []
            c = self._shift_objs.get(obj_id)
            self._num_shifts[obj_id] = 0
        return c


class XpdfPopplerFrame(PTStackOverlayEntry):
    primary_pt = False

    def on_push(self, old_top):
        super(XpdfPopplerFrame, self).on_push(old_top)
        self.prev_callstackentry = None
        self._check("CALLED")
        # save previous callstack entry for debugging purposes, to make sure
        # ghoststack and callstack don't get out-of-sync
        self.prev_callstackentry = None if len(self.manager.ml.stack.stack) < 2 \
            else self.manager.ml.stack.stack[-2]

    def on_push_from_top(self, new_top):
        super().on_push_from_top(new_top)
        #self.__parser_obj_id = self.manager.shift_objs._active_id

    def on_pop_to_top(self, old_top):
        super().on_pop_to_top(old_top)
        #if self.__parser_obj_id:
        #    self.manager.shift_objs.set_active_id(self.__parser_obj_id)

    def on_pop(self, new_top):
        self._check("RETURNED")
        super(XpdfPopplerFrame, self).on_pop(new_top)

    def _check(self, s):
        # a bunch of sanity checks to make sure the ghoststack is consistent
        # with the actual callstack.  Have had some issues due to logging not
        # getting reenabled when it should have which cause other
        # hard-to-debug pt-tracking inconsistencies
        if not self.track_pt:
            return

        if self.flagged_signature.fn_names and not self.manager.exiting:
            stack = self.manager.ghoststack_overlay(self.__class__)
            callstack = [f for f in self.manager.ml.stack
                         if any([n in f.fn.symbol.name
                                 for n in self.flagged_signature.fn_names])]
            callstack_len = sum([(1 + f.recursive_count) for f in
                                 callstack])
            if len(stack) != callstack_len:
                self.OOPS(
                    "There seems to be an inconsistency "
                    "between the callstack and the ghoststack.  This may "
                    "be due to problems with the YARN/memtrace log, or "
                    f"it could be something else entirely. {s} {self}" + "\n" +
                    f"There are {len(stack)} ghoststack entries that "
                    f"correspond to {callstack_len} entries on the actual "
                    "callstack\n", f"Ghoststack: {stack}" + "\n" +
                    f"Callstack: {callstack}" + "\n"
                )

    def register_fetch(self, obj, fetch_frame):
        pass


class XpdfPopplerMomentSignature(MomentSignature):
    sig_id_name = None

    def OOPS(self, *msg):
        OOPS(SigEvalException, *msg, "\n",
             "Signature:", str(self), "\n",
             "Evaluator information:", self.manager.debug_string())


class XpdfPopplerValueSignature(XpdfPopplerMomentSignature):
    log_type = MemEntry
    attr_name = "pc"
    struct_format = "q"
    flag_addr_idx = 0

    def reset(self):
        self.value = None

    def _flag(self, log_entry):
        super(XpdfPopplerValueSignature, self)._flag(log_entry)
        self.value = self.unpack_val(self.flagged_entry.raw_value)


class ShiftObjFrame(XpdfPopplerFrame):
    sig_id_name = "PARSER_SHIFT_CALLED"
    remove_when_flagged = False
    # push_frame_class = ShiftObjFrame
    log_type = CallEntry
    attr_name = "target_addr"
    sig_reg_if_no_subclass = True

    def __init__(self, flagged_sig):
        self.obj2 = None
        self.obj1_type = None
        self.inlineImg_val = None
        self.parser_id = None
        self.obj_setters = []
        # only enable tracking if tracking is enabled for parser
        # object currently being processed
        sigs = set([self.manager.sig_from_id(getattr(SigID, s)) for s in
                    ["SHIFT_OBJ_ID", "LEXER_GET_OBJ_CALLED"]
                    if hasattr(SigID, s)])
        super(ShiftObjFrame, self).__init__(flagged_sig,
                                            pt_tracking_sigs=sigs)

    def on_push(self, old_top):
        super(ShiftObjFrame, self).on_push(old_top)
        if old_top is None:
            self.OOPS(
                      "ShiftObjFrame should never be the only "
                      "stack entry, something went wrong."
            )

    def register_parser_info(self, inlineImg_val, parser_id):
        self.inlineImg_val = inlineImg_val
        self.parser_id = parser_id
        self.track_pt = self.manager.shift_objs.track_pt(obj_id=parser_id)

    def register_lex_obj(self, obj):
        if self.obj2 is not None:
            self.OOPS(
                      "ShiftObjFrame already has a registered",
                      "object and doesn't expect any more objects to be",
                      "regisered, something went wrong.",
                      f"Current obj: {self.obj},",
                      f"new obj: {obj}"
            )
        self.obj2 = obj

    def on_push_from_top(self, new_top):
        super(ShiftObjFrame, self).on_push_from_top(new_top)
        if not (isinstance(new_top, LexerObjFrame)):
            self.OOPS(
                      "ShiftObjFrame only ever expects to",
                      "call LexerObjFrame instances, but it has invoked a ",
                      f"{type(new_top)} frame ({new_top})."
                      )

    def on_pop(self, new_top):
        super(ShiftObjFrame, self).on_pop(new_top)
        if self.inlineImg_val is None:
            self.OOPS("We should have determined the value of",
                      "inlineImg by now, but we havent. The signature",
                      "that determines this value must not have been flagged")
        if self.obj2 is None and self.inlineImg_val == 0:
            self.OOPS("A new object should have been registered since",
                      "inlineImg == 0")
        if self.inlineImg_val > 0:
            # Lexer::getObj not called, then new obj is
            # just set to NULL by shift()
            self.obj2 = LexObj(LexType.NULL)
        if isinstance(new_top, MakeStreamFrame) or \
           isinstance(new_top, IntFrame) or \
           isinstance(new_top, GetObjFrame):
            new_top.register_lex_obj(self.obj2)
        else:
            # get top GetObjFrame
            getobj = self.manager.stack_top(GetObjFrame)
            if getobj:
                getobj.register_lex_obj(self.obj2)
        # the objects have been shifted by GetObjFrame.register_lex_obj

    def on_pop_to_top(self, old_top):
        super().on_pop_to_top(old_top)
        if self.parser_id is not None:
            self.manager.shift_objs.set_active_id(self.parser_id)


class IntFrame(XpdfPopplerFrame):

    def __init__(self, flagged_sig):
        self._track_pt = True
        self.objs = []
        self.obj1 = self.manager.shift_objs.obj1()
        self.obj2 = self.manager.shift_objs.obj2()
        sigs = set([self.manager.sig_from_id(getattr(SigID, i)) for i in
                    ["PARSER_SHIFT_CALLED"]
                    if hasattr(SigID, i)])
        super(IntFrame, self).__init__(flagged_sig, pt_tracking_sigs=sigs,
                                       return_sig=SigID.INT_FRAME_RETURN)

    def register_lex_obj(self, obj):
        self.objs.append(obj)
        getobj_frame = self.manager.stack_top(GetObjFrame)
        if getobj_frame is None:
            self.OOPS(f"{self} should be on top of GetObjFrame")
        getobj_frame.register_lex_obj(obj)

    def register_new_object(self, obj_type, reg_obj):
        self.manager.stack_top(GetObjFrame).register_new_object(obj_type,
                                                                reg_obj)

    def on_push_from_top(self, new_top):
        if not isinstance(new_top, ShiftObjFrame):
            self.OOPS("this shouldn't happen to int frame", self, new_top)
        super().on_push_from_top(new_top)

    def on_pop(self, new_top):
        if not self.objs:
            self.OOPS(
                      "No shift()/new lexed objects",
                      "registered to Int frame, something must have gone "
                      "awry"
            )
        if self.return_sig.is_reference or self.return_sig.is_error:
            pt = PT(PDFEnum.REF) if not self.return_sig.is_error else \
                PT(PDFEnum.NONE)
            contents = [self.obj1.to_pt(),
                        self.obj2.to_pt(),
                        self.objs[0].to_pt()]
            for a in contents:
                pt.add_child(a)
            pt.value = b" ".join([c.value if isinstance(c.value, bytes) else
                                  bytes(str(c.value), "utf-8")
                                  for c in contents])
        else:
            pt = self.obj1.to_pt()
        self.manager.stack_top(XpdfPopplerFrame).register_pt_node(pt, self)
        super(IntFrame, self).on_pop(new_top)


class NewParserFrame(XpdfPopplerFrame):
    def __init__(self, sig, where, container):
        sig.reset()
        self.parser_id = None
        self.objs = []
        self.where = where
        self.container = container
        self.xref_id = None
        self.lex_obj_sig = self.manager.sig_from_id(SigID.LEXER_GET_OBJ_CALLED)
        sigs = [self.manager.sig_from_id(getattr(SigID, s)) for s in
                ["NEW_PARSER_ID", "NEW_PARSER_XREF_ID"]
                if hasattr(SigID, s)]
        sigs.append(self.lex_obj_sig)
        super(NewParserFrame, self).__init__(sig, pt_tracking_sigs=set(sigs))

    # not really using this for anything at the moment,
    # but i'm curious as to whether poppler creates
    # multiple XRef instances/XRef copies
    def register_xref_id(self, xref_id):
        if self.xref_id is not None and xref_id != self.xref_id:
            self.OOPS("Didn't expect a new xref table to be created.",
                      "It may be work taking a closer look.")
        self.xref_id = xref_id

    def register_lex_obj(self, obj):
        self.objs.append(obj)
        if len(self.objs) < 2:
            self.lex_obj_sig.reset()
        elif len(self.objs) > 2:
            self.OOPS("More than 2 objects were registered with new Parser()",
                      "frame, this shouldn't happen")

    def register_parser_id(self, parser_id):
        self.parser_id = parser_id
        pt = PT(self.container)
        pt.add_context(ParseReason.create(self))
        self.manager.shift_objs.register_new_parser(parser_id,
                                                    self.where, pt,
                                                    True,
                                                    self.xref_id)
        self.manager.shift_objs.set_active_id(parser_id)

    # def on_push(self, old_top):
    #     super(NewParserFrame, self).on_push(old_top)

    def on_pop_to_top(self, old_top):
        super().on_pop_to_top(old_top)
        if self.parser_id is not None:
            self.manager.shift_objs.set_active_id(self.parser_id)

    def on_pop(self, new_top):
        if len(self.objs) != 2:
            self.OOPS("Exactly 2 objects should have been registered,",
                      f"instead {len(self.objs)} were: {self.objs}")
        if self.parser_id is None:
            self.OOPS("Parser id should hve been determined by now")
        self.manager.shift_objs.set_active_id(self.parser_id)
        for o in self.objs:
            self.manager.shift_objs.shift(o)
        super(NewParserFrame, self).on_pop(new_top)


class MakeStreamFrame(XpdfPopplerFrame):
    sig_id_name = "MAKE_STREAM_CALLED"
    remove_when_flagged = True
    log_type = CallEntry
    attr_name = "target_addr"
    fn_names = ["_ZN6Parser10makeStreamEO6ObjectPh14CryptAlgorithmiiiib"]
    sig_reg_if_no_subclass = True

    def __init__(self, flagged_sig, pt_tracking_sigs=None):
        self._register_pt = True
        self.shift_count = 0
        self.parser_id = None
        pt = PT(PDFEnum.CONTAINER)
        pt.add_child(self.manager.shift_objs.obj2().to_pt())
        pt.add_context(ParseReason.create(self))
        sigs = set([self.manager.sig_from_id(s) for s in
                    [SigID.PARSER_SHIFT_CALLED]])
        sigs |= set(pt_tracking_sigs) if pt_tracking_sigs else set()
        if hasattr(SigID, "DICT_KEY"):
            [s.disable() for s in
             self.manager.signatures.active_sigs_by_id(SigID.DICT_KEY)]
        super(MakeStreamFrame, self).__init__(flagged_sig,
                                              pt_tracking_sigs=sigs,
                                              pt=pt)

    def register_lex_obj(self, obj):
        self.shift_count += 1
        if self.shift_count == 2:
            self.pt.add_child(self.manager.shift_objs.obj1().to_pt())
        elif self.shift_count > 3:
            self.OOPS("Did not expect more than 3 calls to shift",
                      "but a subsequent call registered: {obj}")
        getobj_frame = self.manager.stack_top(GetObjFrame)
        if getobj_frame is None:
            self.OOPS(f"{self} should be on top of GetObjFrame")
        getobj_frame.register_lex_obj(obj)

    def register_pt_node(self, obj, from_obj):
        self.OOPS("ShiftObjFrame did not expect an pt node to be registered",
                  f"by {from_obj}: {obj}")

    def on_pop_to_top(self, old_top):
        super(MakeStreamFrame, self).on_pop_to_top(old_top)
        self.manager.shift_objs.set_active_id(self.parser_id)

    def on_push(self, old_top):
        super(MakeStreamFrame, self).on_push(old_top)
        if not isinstance(old_top, GetObjFrame):
            self.OOPS("MakeStreamFrame should only be pushed on top a",
                      "GetObjFrame, but instead is being pushed on top",
                      f"of {old_top}")
        self.parser_id = old_top.parser_obj_id
        self.manager.shift_objs.set_active_id(self.parser_id)


class GetObjFrame(XpdfPopplerFrame):
    primary_pt = True

    def __init__(self, sig, call_container, stack_info):
        self.inlineimg = None
        self.lex_obj_sig = self.manager.sig_from_id(SigID.LEXER_GET_OBJ_CALLED)
        self.call_container = call_container
        self._track_pt = True
        self._parser_obj_id = None
        self.new_parser = False
        self.setup_done = False
        self.prev_top = self.manager.stack_top(GetObjFrame)
        self.sigs_on_return = []
        self.obj = None
        self.obj_ids = {}
        self.pt_begin = None
        self.obj_info_sig = self.manager.sig_from_id(SigID.OBJ_INFO)
        # self.cache_id = None
        sigs = set([self.manager.sig_from_id(i) for i in
                    [SigID.PARSER_SHIFT_CALLED, SigID.PARSER_OBJ_ID]])
        sigs.add(self.obj_info_sig)
        super(GetObjFrame, self).__init__(sig, pt_tracking_sigs=sigs,
                                          stack_info=stack_info)

    def setup_from_parser_id(self, obj_id, inlineimg):
        self.setup_done = True
        self.parser_obj_id = obj_id
        n = self.manager.shift_objs.num_shifts()

        self.new_parser = self.manager.shift_objs.num_shifts() == 2

        # if pt tracking was previously disabled for current
        # parser obj, make sure it remains disabled.  Also
        # disable it if it was disabled for frame top
        self.track_pt = self.manager.shift_objs.track_pt()
        self.track_pt &= self.prev_top.track_pt if self.prev_top else \
            self.track_pt
        if self.manager.shift_objs.num_shifts() < 2:
            self.OOPS("There should have been at least 2 objects registered",
                      "to object container by now but there are",
                      self.manager.shift_objs.num_shifts())

        # finally check if we are only tracking unique objects &&
        # this is getobj call is the first to process the current
        # parser object && the object being parsed is already in
        # the cache
        self.pt_begin = self.manager.shift_objs.obj1().first_taint
        # self.cache_id = self.manager.cache_id(self.pt_begin)
        if self.manager.unique_objs_only and self.new_parser and \
           self.manager_has_cached_pt(self.pt_begin):
            self.track_pt = False

        # if we aren't tracking the pt, we are done
        if not self.track_pt:
            # make sure parser object manager knows that tracking is disabled
            # for current parser object
            self.manager.shift_objs.track_pt(False)
            # remove PARSER_GET_OBJ_CALLED/NEW_PARSER sig until frame
            # has returned so that we don't trigger any other
            # PT-tracking sigs/frames for this parser instance/getObj
            # call
            self.manager.disable_tracking()
            return
        self.inlineimg = inlineimg
        self.getobj_count = 2 if inlineimg == 2 else 0
        if self.getobj_count > 0:
            self.add_ghostsite_sig(self.lex_obj_sig)
        else:
            self._add_object_sigs()
        self._pt = self.manager.shift_objs.parser_pt()

    @property
    def register_pt_with_manager(self):
        return self.new_parser

    @property
    def cache_id(self):
        if self.pt_begin is None:
            return None
        else:
            return self.calculate_cache_id(self.pt_begin)

    @property
    def parser_obj_id(self):
        return self._parser_obj_id

    @parser_obj_id.setter
    def parser_obj_id(self, obj_id):
        self._parser_obj_id = obj_id
        self.manager.shift_objs.set_active_id(obj_id)

    def _add_object_sigs(self):
        if not self.track_pt:
            return
        # these signatures should only be initialized after inlineImg == 0
        # (after lexer.getObj() resets contents of buf1/buf2 if it occurs)
        sigs = [self.manager.sig_from_id(getattr(SigID, s))
                for s in ["NEW_ARRAY", "NEW_DICT",
                          "SIMPLE_OBJ",
                          "INT", "RECURSION_ERROR"]
                if hasattr(SigID, s)]
        self.add_ghostsite_sig_group(sigs)

    def register_lex_obj(self, obj, lexerobj=False):
        if self.parser_obj_id is None:
            self.OOPS("Parser id should hve been determined by now")

        self.manager.shift_objs.set_active_id(self.parser_obj_id)
        self.manager.shift_objs.shift(obj, increment_shifts=not lexerobj)
        if lexerobj:
            self.getobj_count -= 1
            if self.getobj_count > 0:
                self.lex_obj_sig.reset()
            elif self.getobj_count == 0:
                self.remove_ghostsite_sig(self.lex_obj_sig)
                self._add_object_sigs()
            else:
                self.OOPS("Lexer::getObj called too many times")

    def register_pt_node(self, child, from_obj):
        if isinstance(from_obj, MakeStreamFrame):
            if self.obj is None or not self.obj.type == PDFEnum.DICT:
                self.OOPS("Currently registered obj is None or not a dict:",
                          self.obj, f"registering: {child} from {from_obj}")
            pt = PT(PDFEnum.STREAM, children=[self.obj] + child.children)
            self.obj = pt
        elif self.obj is not None:
            self.OOPS("already have an obj registered",
                      f"have: {self.obj}, being regisered: {child}",
                      f"registering entity: {from_obj},",
                      f"self {self}")
        else:
            if not isinstance(from_obj, MomentSignature):
                child.context = self.pt.context
            self.obj = child
        # set pt so that user hooks can inspect them
        self._pt = self.obj

    def on_pop(self, new_top):
        if not self.setup_done:
            self.OOPS("Parser ID setup should have bene performed by now")
        if self.obj is None and self.obj_info_sig.type == LexType.STRING:
            # value extraction for encrypted strings not yet implemented
            self.obj = PT(typ=PDFEnum.ENCRYPTED_STRING)
        if not self.track_pt:
            # re-insert getObj/new parser sigs
            self.manager.enable_tracking()
        elif not self.obj:
            self.OOPS("Don't know what obj was parsed")
        else:
            if not new_top:
                if self.call_container:
                    self.manager.shift_objs.push_pt(self.call_container)
                self.manager.shift_objs.append_pt_child(self.obj)
                if self.call_container:
                    self.manager.shift_objs.pop_pt()
                self._pt = self.manager.shift_objs.parser_pt()
            else:
                self._pt = self.obj

            if new_top and new_top.track_pt and \
               not (isinstance(new_top, NewParserFrame)
                    or
                    isinstance(new_top, MakeStreamFrame)):
                new_top.register_pt_node(self.pt, self)
            if self.new_parser and self.manager.unique_objs_only:
                # if this the first getObj call to this parser object, add the
                # root pt node to the pt cache
                self.cache_pt_with_manager(self.pt)
        super(GetObjFrame, self).on_pop(new_top)

    def on_pop_to_top(self, old_top):
        super().on_pop_to_top(old_top)
        if self.parser_obj_id is None:
            self.OOPS("Parser ID should have been determined by now")
        else:
            self.manager.shift_objs.set_active_id(self.parser_obj_id)


class LexerObjFrame(XpdfPopplerFrame):

    def __init__(self, flagged_sig, pt_tracking_sigs=None):
        self.obj = LexObj(LexType.UNKNOWN)
        # These value sigs are able to extract the value of
        # value-containing constructed objects.  Most work by reading
        # the object's value when read by the Object's
        # constructor. STRING, NAME, and CMD values are estimated
        # based on memcpy/strcpy performed during object construction
        # (for NAME/CMD objcets) within the Lexer::getObj call
        # before the constructor is called (for STRING objects)
        cpystr = self.manager.sig_from_id(SigID.LIBC_STRCPY)
        self.val_sigs = {
            LexType.BOOL: self.manager.sig_from_id(SigID.BOOL_VAL),
            LexType.INT: self.manager.sig_from_id(SigID.INT_VAL),
            LexType.REAL: self.manager.sig_from_id(SigID.DOUBLE_VAL),
            LexType.STRING: self.manager.sig_from_id(SigID.LEX_STRING_VAL),
            # self.manager.sig_from_id(SigID.LIBC_MEMCPY),
            LexType.NAME: cpystr,
            LexType.CMD: cpystr,
        }
        if hasattr(SigID, "INT64_VAL"):
            self.val_sigs[LexType.INT64] = self.manager.sig_from_id(
                SigID.INT64_VAL
            )
        self.obj_info_sig = self.manager.sig_from_id(SigID.OBJ_INFO)
        sigs = [self.obj_info_sig] + list(self.val_sigs.values())
        # # However OBJ_TYPE signature cannot distinguish between
        # # NAME/CMD as well as between various error object types
        # # NULL/ERROR/EOF due to how the Object() constructors are
        # # implemented (Lexer::getObj does not parse NONE or DEAD
        # # objects) STR_OBJ_TYPE_VAL can distinguish between NAME and
        # # CMD objects by reading the constructed object's type in the
        # # Object(ObjType, const char *) constructor use to make such
        # # objects OBJ_TYPE_VAL can distinguish between NULL/ERROR/EOF
        # # by reading the constructed object's type when it is
        # # constructed using Object(ObjType)
        # self.val_info_sigs = {
        #     4: self.manager.sig_from_id(SigID.STR_OBJ_TYPE_VAL),
        #     5: self.manager.sig_from_id(SigID.OBJ_TYPE_VAL)
        # }
        # this signature tracks first-order taint reads during the getObj call

        self.taint_sig = self.manager.sig_from_id(SigID.TAINT_READ)
        sigs.append(self.taint_sig)
        sigs += list(pt_tracking_sigs) if pt_tracking_sigs else []
        super(LexerObjFrame, self).__init__(flagged_sig,
                                            pt_tracking_sigs=set(sigs))

    @property
    def track_pt(self):
        return True

    def on_pop(self, new_top):
        super(LexerObjFrame, self).on_pop(new_top)
        # # first look up information on parsed object's type
        # val_info_sig = self.val_info_sigs.get(self.objtype_sig.obj_type)
        # # if this signature wasn't able to uniquely identify the object
        # # type then one of the self.val_info_sigs should contain then
        # # needed information
        # obj_type_val = val_info_sig.value if val_info_sig else \
        #     self.objtype_sig.obj_type
        obj_type_val = self.obj_info_sig.type
        if obj_type_val is None:
            self.OOPS(
                      "We should have determined the "
                      "lexed object's type, something must have gone awry."
            )
        obj_type = LexType(obj_type_val)
        self.obj.type = obj_type
        sig = self.val_sigs.get(obj_type)
        if sig:
            self.obj.value = sig.value

        self.obj.add_taint(self.get_taint(), self.first_taint)
        if isinstance(new_top, ShiftObjFrame) or \
           isinstance(new_top, NewParserFrame):
            new_top.register_lex_obj(self.obj)
        elif isinstance(new_top, GetObjFrame):
            new_top.register_lex_obj(self.obj, lexerobj=True)

    def get_taint(self):
        return self.taint_sig.get_taint()

    @property
    def first_taint(self):
        return self.taint_sig.first_taint


class NewParserMoment(NewFrameMoment):
    sig_id_name = "NEW_PARSER"
    log_type = CallEntry
    attr_name = "target_addr"
    push_frame_class = NewParserFrame
    sig_reg_if_no_subclass = True

    def frame_args(self):
        return [self.where, self.container]

    def reset(self):
        self.where = None
        self.container = None


class XpdfPopplerPTTracker(SigPTEval):
    register_sig = []
    register_frame = []
    register_new_frame_sig = []
    sig_bases = [XpdfPopplerMomentSignature]
    frame_bases = [XpdfPopplerFrame]
    new_frame_sig_bases = [NewFrameMoment]
    additional_tracking_sigs = []

    @classmethod
    def do_register_item(cls, sig_cls_name, subclss, attr=None):
        attr = attr if attr else {}
        # def populate(c):
        #     c.update(attr)
        # t = types.new_class(sig_cls_name, tuple(subclss), exec_body=populate)
        t = type(sig_cls_name, tuple(subclss), attr)
        cls.dynamic_classes.append(t)
        return t

    @classmethod
    def do_register_subcls(cls, clsname, subclasses=None, attr=None):
        attr = attr if attr else {}
        supercls = globals()[clsname]
        if subclasses is None:
            typ = "sig" if not issubclass(supercls, PTStackOverlayEntry) \
                else "frame"
            subclasses = getattr(cls, f"{typ}_bases")
        if hasattr(supercls, "_sig_id_name"):
            attr["sig_id_name"] = supercls._sig_id_name
        return cls.do_register_item(clsname, [supercls] + subclasses, attr)

    @classmethod
    def setup(cls):
        for n in ["frame", "sig", "new_frame_sig"]:
            for (name, attr) in getattr(cls, f"register_{n}"):
                cls.do_register_item(name, getattr(cls, f"{n}_bases"), attr)

        for (clsname, subclasses, attrs) in cls.register_subcls:
            cls.do_register_subcls(clsname, subclasses, attrs)

    def __init__(self, memtrace_log, unique_objects_only: bool,
                 print_image_ops: bool = False, output_stream=None,
                 **kwargs):
        LexObj.print_taint = PT.print_taint
        LexObj.print_first_taint_only = PT.print_first_taint_only
        LexObj.type_enum = LexType
        self.print_image_ops = print_image_ops
        self.output_stream = output_stream
        super(XpdfPopplerPTTracker, self).__init__(memtrace_log,
                                                   unique_objects_only,
                                                   **kwargs)
        # we don't know the type of the first two shift objs
        # which are initially populated outside a getObj call
        self.shift_objs = ParserObjContainer()
        self.tracking_sigs = [self.sig_from_id(getattr(SigID, s)) for s in
                              ["PARSER_GET_OBJ_CALLED",
                               "NEW_PARSER", "NEW_XREF",
                               "ERROR_MSG", "FETCH_CALLED",
                               "READ_XREF_STREAM",
                               "PROCESS_GFX_STREAM",
                               "CONSTRUCT_XREF_CALLED"] +
                              self.additional_tracking_sigs
                              if hasattr(SigID, s)]
        self.enable_tracking()

    def enable_tracking(self):
        [self.add_sig(s) for s in self.tracking_sigs]

    def disable_tracking(self):
        [s.disable() for s in self.tracking_sigs]

    def recursion_depth(self):
        return self.ghoststack_depth(GetObjFrame)

    def callback_MEM_READ(self, signature):
        print("read %x [%s] %s (%x)" % (signature.virtpc,
                                        signature.seg.basename,
                                        signature.value,
                                        signature.flagged_entry.addr))

    def callback_CALL_TRACE(self, signature):
        print([(c, "%x:%s" % (c.virtpc, c.pc_seg.basename))
               for c in self.ml.stack])

    def debug_string(self):
        parser_id = self.shift_objs._active_id
        prev_parser_id = self.shift_objs._prev_id
        parser_id = parser_id if parser_id else 0
        prev_parser_id = prev_parser_id if prev_parser_id else 0
        prev_shift_objs = self.shift_objs._shift_objs.get(prev_parser_id, None)
        return f"At log index: {self.ml.log_count}, current parser " + \
            "id: %x, " % parser_id + \
            "previous parser id: %x " % prev_parser_id + \
            f"current shift_objs: {self.shift_objs}, " + \
            f"previous shift_objs: {prev_shift_objs}, " + \
            f"\ncurrent stack: {self.ml.stack.detail_string()}" + \
            "\n" + "current ghoststack: " + \
            str([(c, c.callstackentry.callsite_id, c.flagged_log_index)
                 for c in self.ghoststack]) + "\n" + \
                     f"result info: {self.ml.ri.result_info}\n"


class ParserGetObj(NewFrameMoment):
    _sig_id_name = "PARSER_GET_OBJ_CALLED"
    push_frame_class = GetObjFrame
    log_type = CallEntry
    attr_name = "target_addr"

    @classmethod
    def setup(cls):
        cls.xref_fetch_objs = cls.addrs_of("xref_fetch_obj")
        cls.xref_table = cls.addrs_of("xref_table_getobj")

    def frame_args(self):
        return [self.call_container, self.stack_info]

    def reset(self):
        self.call_container = None
        self.stack_info = None

    def flag(self):
        caller = self.manager.ml.stack.top()
        idx = len(self.manager.ml.stack.stack)
        if idx > 1:
            prev = self.manager.ml.stack.stack[-2]
            idx -= 1
            caller = prev if "_ZN6Parser6getObjEi" in prev.fn.name else caller
        self.stack_info = self.manager.callstack_summary(idx)
        if caller.pc in [self.xref_table[-1], self.xref_fetch_objs[-1]]:
            self.call_container = PT(PDFEnum.CONTAINER)


class LexerGetObjCalled(NewFrameMoment):
    _sig_id_name = "LEXER_GET_OBJ_CALLED"
    log_type = CallEntry
    attr_name = "target_addr"
    push_frame_class = LexerObjFrame
    remove_when_flagged = False


class GetParserObjId(MomentSignature):
    _sig_id_name = "PARSER_OBJ_ID"
    log_type = MemEntry
    attr_name = "pc"
    remove_when_flagged = True
    parent_frame_class = GetObjFrame
    obj_id_offset = 0
    struct_format = "i"

    @classmethod
    def setup(cls):
        # first linein Parser::getObj() where inlineImg is read
        # we use the address of inlineImg as our shift obj id
        # as there is a one-to-one corrspondence between
        # these and Parser objects
        cls.check_values = cls.addrs_of("parser_obj_id")

    def reset(self):
        self.obj_id = None
        self.new_shift_objs = False

    def flag(self):
        self.obj_id = self.flagged_entry.addr - self.obj_id_offset
        self.value = self.unpack_val(self.flagged_entry.value)
        self.new_shift_objs = (self.value == 2)
        self.parent_frame.setup_from_parser_id(
            self.obj_id,
            self.value
        )


class ObjInfoSig(MomentSignature):
    _sig_id_name = "OBJ_INFO"
    flag_addr_name = "obj_construct_id"
    log_type = MemEntry
    attr_name = "pc"
    struct_format = "i"
    remove_when_flagged = False
    parent_frame_class = XpdfPopplerFrame

    def reset(self):
        self.type = None

    def flag(self):
        self.type = LexType(self.unpack_val(self.flagged_entry.value))


class ShiftObjId(XpdfPopplerMomentSignature):
    _sig_id_name = "SHIFT_OBJ_ID"
    log_type = MemEntry
    attr_name = "pc"
    remove_when_flagged = True
    parser_id_offset = 0
    struct_format = "q"
    parent_frame_class = ShiftObjFrame

    @classmethod
    def setup(cls):
        cls.check_values = cls.addrs_of("shift_inlineImg")

    def reset(self):
        self.inlineImg_val = None
        self.parser_id = None

    def flag(self):
        self.parser_id = self.flagged_entry.addr + self.parser_id_offset
        self.inlineImg_val = self.unpack_val(self.flagged_entry.value)
        self.parent_frame.register_parser_info(
            self.inlineImg_val, self.parser_id
        )


class XpdfPopplerPTMoment(PDFPTMoment):
    parent_frame_class = GetObjFrame

    def __init__(self):
        # first object is usually obj1()
        super(XpdfPopplerPTMoment, self).__init__(
            self.manager.shift_objs.obj1()
        )

    def debug_string(self):
        top = self.manager.stack_bottom(self.parent_frame_class)
        pt = "" if not (top and top.pt) else f"\n{top.pt}"
        return super().debug_string() + "\n" + str(self.manager.shift_objs) + \
            pt


class ArrayFrame(XpdfPopplerFrame):
    sig_reg_if_no_subclass = True

    def __init__(self, flagged_sig):
        self._track_pt = True
        self.objs = []
        sigs = set([self.manager.sig_from_id(i) for i in
                    [SigID.PARSER_SHIFT_CALLED]])
        # sigs.add(self.manager.sig_from_id(SigID.FN_CALL_TRACE,
        #                                   self.manager.ml.stack.top().callsite_id))
        super(ArrayFrame, self).__init__(flagged_sig,
                                         return_sig=SigID.ARRAY_FRAME_RETURN,
                                         pt_tracking_sigs=sigs)

    def on_push(self, old_top):
        super().on_push(old_top)

    def register_pt_node(self, obj, from_obj):
        obj = PT(PDFEnum.ARRAY_ENTRY, children=[obj]) \
            if isinstance(from_obj, GetObjFrame) else obj
        self.objs.append(obj)

    def on_pop(self, new_top):
        if not isinstance(new_top, GetObjFrame):
            self.OOPS("Expected a GetObjFrame to replace me on stack")
        new_top.register_pt_node(PT(PDFEnum.ARRAY, children=self.objs),
                                 self)
        super().on_pop(new_top)


class NewArrayMoment(NewFrameMoment, XpdfPopplerPTMoment):
    _sig_id_name = "NEW_ARRAY"

    log_type = PCEntry
    attr_name = "pc"
    remove_when_flagged = True
    pt_container_type = PDFEnum.ARRAY_START
    expected_lex_objvalue = b"["
    expected_lex_objtype = LexType.CMD
    flag_addr_name = "array_start"


class IntObj(XpdfPopplerValueSignature):
    _sig_id_name = "INT_VAL"
    flag_addr_name = "obj_int_val"
    struct_format = "i"


class BoolObj(XpdfPopplerValueSignature):
    _sig_id_name = "BOOL_VAL"
    flag_addr_name = "obj_bool_val"
    struct_format = "B"


class DoubleObj(XpdfPopplerValueSignature):
    _sig_id_name = "DOUBLE_VAL"
    flag_addr_name = "obj_double_val"
    struct_format = "d"

    def flag(self):
        self.value = self.unpack_val(self.flagged_entry.value)


class LexStrVal(MomentSignature):
    _sig_id_name = "LEX_STRING_VAL"

    @classmethod
    def setup(cls):
        cls.check_values = cls.addrs_of("lex_string_val")

    def reset(self):
        self.value = b""

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, MemEntry) and \
             log_entry.pc in self.check_values:
            self.value += log_entry.value_bytes


class CopyStringMoment(LibcMomentSignature):
    # for libc strcpy that is invoked by copyString() which is called
    # by Object() while in Parser::shift is processing PDF command or
    # name objects
    _sig_id_name = "LIBC_STRCPY"
    struct_format = "Q"
    caller_lib_name = None

    @classmethod
    def setup(cls):
        # cls.struct = struct.Struct("Q")
        # Lexer.cc:453, Lexer.cc:455, Lexer.cc:
        # (calls to Object::Object(ObjType, char const*))
        # track any call from Lexer::getObj to this strcpy
        # lookup PLT entry for strcpy in libpoppler to detected
        # calls it makes to strcpy
        cls.fn_starts = cls.get_fn_abs_addr("strcpy",
                                            anytype=True)
        cls.copystr_call_pcs = cls.addrs_of("copystr_call",
                                            lib_name=cls.caller_lib_name)
        cls.fn_read_addrs = cls.addrs_of("copystr_fn_read")
        cls.skip_read_addrs = cls.addrs_of("copystr_skip_read")
        cls.alt_read_addrs = cls.addrs_of("copystr_alt_read")

    def reset(self):
        self.getobj_return = None
        self.read_count = 0
        self.read_value = b""
        self.return_addr = None
        self.skip = False
        self.value = None
        self.read_size = None
        # self.accesses = []
        self.copystr_return = None
        self.done = False

    def in_copystr(self):
        return self.copystr_return is not None

    def in_active_call(self):
        return self.in_copystr() and self.return_addr is not None

    def do_log_entry(self, log_entry):
        if not self.in_copystr() and \
           log_entry.pc in self.copystr_call_pcs:
            self.copystr_return = return_pc_from_call_pc(log_entry.pc)
        elif self.in_copystr() and is_kind(log_entry, CallEntry) and \
             log_entry.target_addr == self.copystr_return:
            self.copystr_return = None
        elif (not self.in_active_call()) and self.in_copystr() and \
             is_kind(log_entry, CallEntry) and \
             log_entry.call_kind == log_entry.CALL and \
             log_entry.target_addr in self.fn_starts:
            # only check for entry into this strcpy if from copyStr() call
            self.return_addr = return_pc_from_call_pc(log_entry.pc)
        elif self.in_active_call() and is_kind(log_entry, MemEntry) and \
             log_entry.typ is log_entry.READ:
            if log_entry.pc in self.fn_read_addrs or \
               (self.read_count > 0 and log_entry.pc in self.alt_read_addrs):
                # self.read_value += self.pack_val(log_entry.value)
                self.read_value += log_entry.value_bytes
                self.read_size = log_entry.size
                self.read_count += 1
            elif self.read_count == 0 and log_entry.pc in self.skip_read_addrs:
                self.skip = True
                self.read_count += 1
        elif is_kind(log_entry, CallEntry) and \
             log_entry.target_addr == self.return_addr:
            # sz = 8
            sz = self.read_size
            # if self.skip and self.read_count == 3:
            if self.read_count > 1:
                first = self.read_value[:sz]
                second = self.read_value[sz:]
                if b'\0' in second:
                    # then there may be some overlap between the strings
                    # to trim off
                    for i in range(1, sz):
                        if first[-1*i:] == second[:i]:
                            self.read_value = first + second[i:]
            try:
                zero = self.read_value.index(0)
                self.read_value = self.read_value[:zero]
            except ValueError:
                # self.read_value = b''
                pass
            self.return_addr = None
            self.done = True
            self.value = self.read_value
            self.do_flag(log_entry)


class GetObjIntMoment(NewFrameMoment):
    _sig_id_name = "INT"
    log_type = CallEntry
    attr_name = "pc"
    remove_when_flagged = True
    push_frame_class = IntFrame

    @classmethod
    def setup(cls):
        # virtpc = 0x2bb650  # Parser.cc:150, obj.GetInt()
        cls.check_values = cls.addrs_of("getobj_int")


class GetObjSimpleMoment(XpdfPopplerPTMoment):
    _sig_id_name = "SIMPLE_OBJ"
    log_type = CallEntry
    attr_name = "pc"
    remove_when_flagged = True

    def get_lex_obj(self):
        return self.manager.shift_objs.obj1()

    @classmethod
    def setup(cls):
        # virtpc = 0x2bb6ec  # Parser.cc:189, std::move
        cls.check_values = cls.addrs_of("simple_obj")


class DictFrame(XpdfPopplerFrame):
    sig_reg_if_no_subclass = True

    def __init__(self, flagged_sig):
        self._track_pt = True
        self.objs = []
        sigs = set([self.manager.sig_from_id(s) for s in
                    [SigID.PARSER_SHIFT_CALLED, SigID.DICT_KEY]])

        super(DictFrame, self).__init__(flagged_sig,
                                        return_sig=SigID.DICT_END,
                                        pt_tracking_sigs=sigs)

    def register_pt_node(self, obj, from_obj):
        obj = PT(PDFEnum.DICT_VALUE, children=[obj]) \
            if isinstance(from_obj, GetObjFrame) else obj
        self.objs.append(obj)

    def register_dict_value_error(self, from_obj):
        if len(self.objs) < 3 or self.objs[-1].type != PDFEnum.DICT_VALUE:
            self.OOPS("Registering a dict value error to a dict "
                      "without enough entries yet. There must be "
                      " at least the open dict symbol and "
                      "one key/value pair. Registered by:", from_obj,
                      "Current contents: ", self.objs)
        self.objs[-1].type = PDFEnum.DICT_VALUE_ERROR

    def on_pop(self, new_top):
        if not isinstance(new_top, GetObjFrame):
            self.OOPS("Expected a GetObjFrame to replace me on stack")
        new_top.register_pt_node(PT(PDFEnum.DICT, children=self.objs),
                                 self)
        super(DictFrame, self).on_pop(new_top)


class NewDictMoment(NewFrameMoment, XpdfPopplerPTMoment):
    _sig_id_name = "NEW_DICT"
    log_type = CallEntry
    attr_name = "pc"
    remove_when_flagged = True
    pt_container_type = PDFEnum.DICT_START
    expected_lex_objvalue = b"<<"
    expected_lex_objtype = LexType.CMD
    push_frame_class = DictFrame
    parent_frame_class = DictFrame

    def reset(self):
        self.shift_obj = None

    def get_lex_obj(self):
        return self.shift_obj

    @classmethod
    def setup(cls):
        # want to pick PC before shift()
        # shiftvirtpc = 0x2bb358  # Parser.cc:108, bb where shift() called
        cls.shift_pc = cls.addrs_of("dict_start_shift", 1)
        # virtpc = 0x2bb395  # Parser.cc:109, Object()
        cls.object_pc = cls.addrs_of("dict_start_obj", 1)

    def do_log_entry(self, log_entry):
        if is_kind(log_entry, PCEntry) and \
           log_entry.pc == self.shift_pc:
            self.shift_obj = self.manager.shift_objs.obj1()
        elif is_kind(log_entry, CallEntry) and \
             log_entry.pc == self.object_pc and self.shift_obj:
            self.do_flag(log_entry)


class DictValueMoment(MomentSignature):
    _sig_id_name = "DICT_VALUE"
    log_type = CallEntry
    attr_name = "pc"
    remove_when_flagged = True
    parent_frame_class = DictFrame
    enable_sigs = ["DICT_KEY"]

    @classmethod
    def setup(cls):
        # self.dict_start_obj = dict_start_obj
        # virtpc = 0x2bb455  # Parser.cc:127 when dictAdd() is called
        cls.dict_value = cls.addrs_of("dict_value", 1)
        # errorpc = 0x2bb551  # Parser.cc:125 breaks to line Parser.cc:120 where bu1:isEOF is called
        # cls._rec_error_pc = cls.addrs_of("dict_value_err")[0]
        # objerrorpc = 0x2bb44d  # Parser.cc:124 obj2.isError() is true, but (recursion + 1 >= recursionLimit) is false
        # recursionerror = 0x2bb61f # Parser.cc:196 Object(objError)
        cls.obj_error_pc = cls.addrs_of("dict_value_objerr", 1)
        cls.check_values = [cls.dict_value, cls.obj_error_pc]

    def reset(self):
        # self.recursion_error = False
        self.obj_error = False

    def flag(self):
        # if self.flagged_entry.pc = self.dict_value
        self.obj_error = self.flagged_entry.pc == self.obj_error_pc
        # if self.recursion_error or self.obj_error:
        if self.obj_error:
            # last PT child was what was returned by the call
            # to getObj to retrieve the dict value.
            if not self.parent_frame:
                self.OOPS(f"No parent dict frame for {self}, "
                          f"obj_error: {self.obj_error}")
            self.parent_frame.register_dict_value_error(self)
            # self.parent_frame.set_last_pt_child(PDFEnum.DICT_VALUE_ERROR)
            # inform the dict return signature that there was a value
            # error so that it knows that it shouldn't expect that
            # its last lexed object is a CMD(">>")
            self.parent_frame.return_sig.flag_value_error()


class DictFrameReturn(ReturnSignature, XpdfPopplerPTMoment):
    sig_id_name = None
    _sig_id_name = "DICT_END"
    log_type = CallEntry
    attr_name = "pc"
    pt_container_type = PDFEnum.DICT_END
    expected_lex_objvalue = b">>"
    remove_when_flagged = True
    expected_lex_objtype = LexType.CMD
    parent_frame_class = DictFrame
    enable_sig_frame_class = GetObjFrame
    enable_sigs = ["MAKE_STREAM_CALLED"]

    @classmethod
    def setup(cls):
        # cls.dict_start_obj = dict_start
        # virtpc = 0x2bb56c  # Parser.cc:136, call to isCmd
        # eof_pdf = 0x2bb5f0  # Parser.cc:131, Parser::getPos()
        cls.check_value = cls.addrs_of("dict_end", 1)
        cls.eof_pc = cls.addrs_of("dict_end_eof", 1)
        # cls.error_obj = cls.addrs_of("dict_key_other_err", 1)
        cls.check_values = [cls.check_value, cls.eof_pc]

    def reset(self):
        self.is_eof = False
        self.value_error = False

    def get_lex_obj(self):
        return self.manager.shift_objs.obj1()

    def flag(self):
        self.is_eof = self.flagged_entry.pc == self.eof_pc

    def flag_value_error(self):
        self.value_error = True

    def lex_obj_type_ok(self, obj):
        return True if (self.value_error or self.is_eof) else \
            super(DictFrameReturn, self).lex_obj_type_ok(obj)

    def lex_obj_value_ok(self, obj):
        return True if (self.value_error or self.is_eof) else \
            super(DictFrameReturn, self).lex_obj_value_ok(obj)


@dataclasses.dataclass(repr=False)
class GfxArgInfo(DataContext):
    skipped: bool = False
    leftover: bool = False


@dataclasses.dataclass(repr=False)
class GfxOpInfo(DataContext):
    args_idx: typing.List[int] = dataclasses.field(default_factory=list)
    update_display: bool = False
    aborted: bool = False
    error: bool = False
    error_text: typing.List[str] = dataclasses.field(default_factory=list)
    print_depth: typing.ClassVar[int] = 2

    @classmethod
    def create(cls, args):
        c = cls()
        c.set_args(args)
        return c

    def set_args(self, args):
        self.args_idx = [a.index for a in args]


class GfxStreamFrame(XpdfPopplerFrame):
    _sig_id_name = "PROCESS_GFX_STREAM"
    log_type = CallEntry
    attr_name = "target_addr"
    remove_when_flagged = False

    def __init__(self, flagged_sig):
        sigs = set([self.manager.sig_from_id(s) for s in
                    [SigID.GFX_STREAM_INFO]])
        self.args = []
        pt = PT(PDFEnum.GFX_IMAGE_STREAM)
        pt.add_context(ParseReason.create(self))
        super(GfxStreamFrame, self).__init__(
            flagged_sig, pt_tracking_sigs=sigs, pt=pt
        )
        self.pt.add_context(ProcessStreamInfo())

    def register_pt_node(self, node, from_obj):
        if node.type == PDFEnum.CMD and \
           self.manager.ml.stack.top() == self.callstackentry:
            node.add_context(GfxOpInfo.create(self.args))
        if isinstance(from_obj, GetObjFrame):
            node.add_context(ParseReason.create(self, self.pt.index))
        else:
            # not sure if this ever happens
            # node.add_context(ParseReason.create(self, self.pt.index))
            self.OOPS("untested register_pt_node from not getObj",
                      from_obj, node)
        super(GfxStreamFrame, self).register_pt_node(node, from_obj)

    def register_skip_arg(self, sig):
        last = self.pt.get_last_child()
        if last is None:
            self.OOPS("There should already be a parsed object")
        last.add_context(GfxArgInfo(True))

    def register_save_arg(self, sig):
        last = self.pt.get_last_child()
        if last is None:
            self.OOPS("There should already be a parsed object")
        last.add_context(GfxArgInfo(False))
        self.args.append(last)

    def register_leftover_args(self, sig):
        [a.add_context(GfxArgInfo(False, True))
         for a in self.args]

    def register_exec_op(self, sig):
        last = self.last_op()
        if last is None:
            self.OOPS("Couldn't find last operation", self.pt)
        self.args = []
        self.pt.get_context(ProcessStreamInfo).ops_idx.append(last.index)

    def register_aborted(self, sig):
        last = self.last_op()
        if last is None:
            self.OOPS("Couldn't find last operation", self.pt)
        cxt = last.get_context(GfxOpInfo)
        cxt.aborted = True

    def register_error(self, text, sig):
        last = self.last_op()
        if last:
            cxt = last.get_context(GfxOpInfo)
            cxt.error = True
            cxt.error_text = text

    def register_update_display(self, sig):
        last = self.last_op()
        if last:
            cxt = last.get_context(GfxOpInfo)
            cxt.update_display = True

    def last_op(self):
        last = self.pt.get_last_child()
        if last and last.type == PDFEnum.CMD:
            return last

    def on_pop(self, new_top):
        super(GfxStreamFrame, self).on_pop(new_top)
        self.do_register_pt(self.pt)
        if self.manager.print_image_ops:
            print("Image operations at ",
                  self.manager.ml.stack.detail_string(),
                  file=self.manager.output_stream)
            for op in self.pt.get_context(ProcessStreamInfo).ops():
                print("exec op", op, file=self.manager.output_stream)

    def register_fetch(self, obj, fetch_frame):
        last = self.last_op()
        if last:
            reason = obj.get_context(ParseReason)
            if reason is not None:
                reason.requester_pt_idx = last.index


class ErrorSig(XpdfPopplerMomentSignature):
    _sig_id_name = "ERROR_MSG"
    parent_frame_class = GfxStreamFrame
    log_type = CallEntry
    attr_name = "target_addr"

    def reset(self):
        self.error_call = None
        self.return_addr = None
        self.text = []

    def do_log_entry(self, log_entry):
        if self.error_call:
            if is_kind(log_entry, CallEntry) and \
               log_entry.target_addr == self.return_addr:
                self.do_flag(log_entry)
                self.reset()
            elif is_kind(log_entry, FileWriteEntry):
                self.text.append(
                    self.manager.ml.write_entry_log_bytes(log_entry)
                )
        elif is_kind(log_entry, CallEntry) and \
             log_entry.target_addr in self.check_values:

            self.error_call = len(self.manager.ml.stack.stack)
            self.return_addr = self.manager.ml.stack.top().ret

    def flag(self):
        if self.parent_frame:
            self.parent_frame.register_error(b"\n".join(self.text).decode("utf8",
                                                                          errors="replace"),
                                             self)


class GfxStreamSig(XpdfPopplerMomentSignature):
    sig_id_name = "GFX_STREAM_INFO"
    parent_frame_class = GfxStreamFrame
    register_fn_name = None
    remove_when_flagged = False
    attr_name = "pc"
    log_type = PCEntry
    sig_reg_if_no_subclass = True

    reg_names = {
        "gfx_save_arg": "register_save_arg",
        "gfx_skip_arg": "register_skip_arg",
        "gfx_leftover_args": "register_leftover_args",
        "_ZN3Gfx6execOpEP6ObjectS1_i": "register_exec_op",
    }

    @classmethod
    def setup(cls):
        cls.check_values = set()
        cls.addr_registrar = {}
        for (k, v) in cls.reg_names.items():
            addrs = cls.get_fn_abs_addr(k, lib=cls.lib_name) \
                if k.startswith("_") else cls.addrs_of(k)
            cls.check_values.update(addrs)
            for a in addrs:
                cls.addr_registrar[a] = v

    def flag(self):
        reg_fn = self.addr_registrar[self.flagged_entry.pc]
        getattr(self.parent_frame, reg_fn)(self)


class ConstructXRefFrame(XpdfPopplerFrame):
    sig_id_name = "CONSTRUCT_XREF_CALLED"
    remove_when_flagged = False
    log_type = CallEntry
    attr_name = "target_addr"
    sig_reg_if_no_subclass = True
    reg_at_offset = True

    class XRefEntry():
        def __init__(self):
            self.num = None  # although is implied by table index
            self.gen = None
            self.type = None
            self.offset = None

    def __init__(self, flagged_sig):
        self.token = None
        self.current_entry = []
        self.return_value = False
        self.root_entry = self.XRefEntry()
        self.trailer_dict = None
        self.trailer_dict_update = False
        # self.trailer_cache_id = None
        self._track_pt = True
        self._register_pt = True
        self.xref_id = None
        pt = PT(PDFEnum.RECONSTRUCTED_XREF_TABLE)
        pt.add_context(ParseReason.create(self))
        pt.add_context(XRefTableInfo())
        sigs = set([self.manager.sig_from_id(s) for s in
                    [SigID.SHIFT_OBJ_ID, SigID.XREF_CONSTRUCT_NUM,
                     SigID.XREF_CONSTRUCT_GEN, SigID.XREF_CONSTRUCT_OFFSET,
                     SigID.XREF_CONSTRUCT_ID]])
        self.taint_sig = self.manager.sig_from_id(SigID.TAINT_READ)
        self.reset()
        sigs.add(self.taint_sig)
        super(ConstructXRefFrame, self).__init__(flagged_sig,
                                                 pt_tracking_sigs=sigs,
                                                 pt=pt)

    def register_lex_obj(self, obj):
        pass

    def register_xref_id(self, xref_id):
        self.xref_id = xref_id

    def reset(self):
        self.taint_sig.reset()
        self.next_num = None
        self.next_gen = None
        self.next_offs = None

    def register_pt_node(self, obj, from_obj):
        self.trailer_dict = obj
        obj.add_context(ParseReason.create(self, self.pt.index))
        self.do_register_pt(obj, True)

    def register_num(self, val):
        if self.next_num is not None:
            children = [self.next_num]
            if self.next_gen is not None:
                children.append(self.next_gen)
            obj = PT(PDFEnum.XREF_TABLE_ENTRY,
                     children=children,
                     taint_tree=self.taint_sig.get_taint(),
                     first_taint=self.taint_sig.first_taint)
            obj.add_context(ParseReason.create(self, self.pt.index))
            self.pt.add_orphan(obj)
            self.taint_sig.reset()
        self.next_num = PT(PDFEnum.INT, val)
        self.next_gen = None

    def register_gen(self, val):
        self.next_gen = PT(PDFEnum.INT, val)
        if not self.reg_at_offset:
            self.pt.add_child(PT(PDFEnum.XREF_TABLE_ENTRY,
                                 children=[self.next_num,
                                           self.next_gen,
                                           self.next_offs],
                                 taint_tree=self.taint_sig.get_taint(),
                                 first_taint=self.taint_sig.first_taint))
            self.reset()

    def register_offset(self, val):
        if self.reg_at_offset:
            self.pt.add_child(PT(PDFEnum.XREF_TABLE_ENTRY,
                                 children=[self.next_num,
                                           self.next_gen,
                                           PT(PDFEnum.INT, val)],
                                 taint_tree=self.taint_sig.get_taint(),
                                 first_taint=self.taint_sig.first_taint))
            self.reset()
        else:
            self.next_offs = PT(PDFEnum.INT, val)

    def on_pop(self, new_top):
        super(ConstructXRefFrame, self).on_pop(new_top)
        self.do_register_pt(self.pt)

    def on_push(self, old_top):
        super(ConstructXRefFrame, self).on_push(old_top)
        if old_top and old_top.pt:
            cxt = self.pt.get_context(ParseReason)
            cxt.requester_pt_idx = old_top.pt.index


class XRefConstructSigBase(XpdfPopplerMomentSignature):
    log_type = MemEntry
    attr_name = "pc"
    remove_when_flagged = False
    parent_frame_class = ConstructXRefFrame
    struct_format = "i"
    entry_field = None
    sig_reg_if_no_subclass = True

    def flag(self):
        getattr(self.parent_frame, f"register_{self.entry_field}")(
            self.unpack_val(self.flagged_entry.value)
        )


class XRefConstructId(XRefConstructSigBase):
    _sig_id_name = "XREF_CONSTRUCT_ID"
    flag_addr_name = "construct_xref_id"

    def flag(self):
        # addr is address of XRef->capacity field, which is 24 bytes
        # from begging of xref instance
        self.parent_frame.register_xref_id(self.flagged_entry.addr - 24)


class XRefConstructOffset(XRefConstructSigBase):
    _sig_id_name = "XREF_CONSTRUCT_OFFSET"
    flag_addr_name = "xref_construct_obj_entry_offset"
    struct_format = "i"
    entry_field = "offset"


class XRefConstructNum(XRefConstructSigBase):
    _sig_id_name = "XREF_CONSTRUCT_NUM"
    flag_addr_name = "xref_construct_num_val_write"
    entry_field = "num"


class XRefConstructGen(XRefConstructSigBase):
    _sig_id_name = "XREF_CONSTRUCT_GEN"
    flag_addr_name = "xref_construct_gen_val_write"
    entry_field = "gen"


@dataclasses.dataclass(repr=False)
class FetchXRefInfo(DataContext):
    num: int
    gen: int
    fetch_failed: bool = False
    cached: bool = False


class FetchFrame(XpdfPopplerFrame):
    sig_id_name = "FETCH_CALLED"
    log_type = CallEntry
    attr_name = "target_addr"
    fn_names = ["_ZN4XRef5fetchEiii"]
    sig_reg_if_no_subclass = True

    def __init__(self, flagged_sig):
        self._register_pt = True
        self._track_pt = True
        pt = PT(PDFEnum.INDIRECT_OBJ)
        pt.add_context(ParseReason.create(self))
        sigs = set([self.manager.sig_from_id(i) for i in
                    [SigID.OBJ_FETCH_XREF_NUM, SigID.OBJ_FETCH_XREF_GEN]])

        self.num = None
        self.gen = None
        super(FetchFrame, self).__init__(flagged_sig,
                                         pt_tracking_sigs=sigs,
                                         pt=pt)

    def register_pt_node(self, obj, from_obj):
        self.pt.add_child(obj)

    def register_xref_num(self, num, from_obj):
        self.num = num

    def register_xref_gen(self, gen, from_obj):
        self.gen = gen

    def on_pop(self, new_top):
        self.pt.add_context(FetchXRefInfo(self.num, self.gen,
                                          self.pt.get_last_child() is None))
        super(FetchFrame, self).on_pop(new_top)
        self.do_register_pt(self.pt)
        top = self.manager.stack_top(XpdfPopplerFrame)
        if top:
            top.register_fetch(self.pt, self)


class ObjFetchXRefNum(XpdfPopplerMomentSignature):
    _sig_id_name = "OBJ_FETCH_XREF_NUM"
    flag_addr_name = "xref_xref_fetch_ref_num1"
    log_type = MemEntry
    attr_name = "pc"
    struct_format = "i"
    parent_frame_class = FetchFrame

    def flag(self):
        self.parent_frame.register_xref_num(
            self.unpack_val(self.flagged_entry.value), self
        )


class ObjFetchXRefGen(XpdfPopplerMomentSignature):
    _sig_id_name = "OBJ_FETCH_XREF_GEN"
    flag_addr_name = "xref_xref_fetch_ref_gen1"
    log_type = MemEntry
    attr_name = "pc"
    struct_format = "i"
    parent_frame_class = FetchFrame

    def flag(self):
        self.parent_frame.register_xref_gen(
            self.unpack_val(self.flagged_entry.value), self
        )
