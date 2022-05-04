# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
# regular enum doesnt work well with pypy3 so use aenum
from aenum import auto
import json
from tracetools.pt import PTEnum, PT, PTException, ParseObj
from tracetools.signatures.utils import OOPS
from tracetools.signatures.signatures import MalformTrackerSig, PTMoment
from tracetools.signatures.lex_obj import LexObj
from tracetools.signatures.context import DataContext
import dataclasses
import typing


# Do not change the order of item in this enum
# it needs to match the enum values poppler
# uses in its Object() class.  However, it is ok
# to append items after the UNKNOWN item
class PDFEnum(PTEnum):
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
    CONTAINER = auto()
    UNKNOWN_CONTAINER = auto()
    ROOT = auto()
    DICT_KEY = auto()
    DICT_KEY_ERROR = auto()
    DICT_VALUE = auto()
    DICT_VALUE_ERROR = auto()
    ARRAY_START = auto()
    ARRAY_ENTRY = auto()
    ARRAY_END = auto()

    DICT_START = auto()
    DICT_END = auto()
    ERROR_OBJ = auto()

    STREAM_START = auto()
    STREAM_CONTENTS = auto()
    STREAM_END = auto()
    STREAM_ERR = auto()

    GFX = auto()
    GFX_IMAGE_STREAM = auto()

    XREF_OBJ = auto()
    XREF_TABLE = auto()
    XREF_STREAM_TABLE = auto()
    XREF_TABLE_ENTRY = auto()
    XREF_CHECK = auto()  # when getObj is called to check what kind of xref table

    EXPR_START = auto()
    EXPR_END = auto()

    INDIRECT_OBJ = auto()
    KEYWORD = auto()

    RECONSTRUCTED_XREF_TABLE = auto()
    ENCRYPTED_STRING = auto()

class PDFPTException(PTException):
    pass


class PDFMalformTrackerSig(MalformTrackerSig):
    pass


class DuplicateKeyMalform(PDFMalformTrackerSig):
    sig_id_name = "DUPLICATE_KEY"
    sig_name = "Duplicate dictionary key"


class NullValuesMalform(PDFMalformTrackerSig):
    sig_id_name = "NULL_VALUES"
    sig_name = "Null dictionary value"


class EmptyDictMalform(PDFMalformTrackerSig):
    sig_id_name = "EMPTY_DICT"
    sig_name = "Empty dictionary"


class DeeplyNestedDictMalform(PDFMalformTrackerSig):
    sig_id_name = "DEEPLY_NESTED_DICT"
    sig_name = "Deeply nested dictionary"


class MissingDictEndMalform(PDFMalformTrackerSig):
    sig_id_name = "DICT_MISSING_END"
    sig_name = "Missing dictionary end symbol"


class MissingDictBeginMalform(PDFMalformTrackerSig):
    sig_id_name = "DICT_MISSING_START"
    sig_name = "Missing dictionary start symbol"


class NullIRMalform(PDFMalformTrackerSig):
    sig_id_name = "DICT_NULL_IR"
    sig_name = "Dictionary w/ null IR"
    results_file = "dict-irs.out"

    def reset(self):
        self.dict_irs = set()

    def extract_dict_irs(self, pt):
        kids = pt.children
        if pt.type == PDFEnum.REF:
            self.dict_irs.add(pt.value)
        elif pt.type == PDFEnum.DICT_VALUE and len(kids) == 1:
            self.extract_dict_irs(kids[0])
        elif len(kids) > 3:  # no chance it is a dictionary otherwise
            # skip traversing if not a dictionary
            if kids[0].type == PDFEnum.DICT_START:
                for i in kids:
                    if i.type == PDFEnum.DICT_VALUE:
                        self.extract_dict_irs(i)

    def update(self, pt):
        if pt.type in [PDFEnum.ROOT, PDFEnum.XREF_OBJ]:
            self.extract_dict_irs(pt)

    def on_exit(self, save=True):
        super(NullIRMalform, self).on_exit(save)
        encoder = json.JSONEncoder()
        if save:
            self.manager.ri.import_file(self.results_file, True,
                                        encoder.encode(list(self.dict_irs))
                                        + "\n")


class RandomTypeMalform(PDFMalformTrackerSig):
    sig_id_name = "DICT_RANDOM_TYPE"
    sig_name = "Random dictionary type"
    results_file = "dict-types.out"

    def reset(self):
        self.dict_info = []

    class DictInfoEncoder(json.JSONEncoder):
        def de(self, s):
            if isinstance(s, bytes):
                return s.decode(errors="replace")
            else:
                return s

        def default(self, obj):
            key = self.de(obj.key)
            if obj.value:
                return {key: self.de(obj.value)}
            else:
                return {key: [self.default(c)
                              for c in obj.contents]}

    class DictInfo():
        def __init__(self, key, value=None):
            if key is None:
                # make the key an empty string instead
                key = b''
            self.key = key.decode(errors="replace") \
                if isinstance(key, bytes) else key
            self.value = value.decode(errors="replace") \
                if isinstance(value, bytes) else value
            self.contents = []

        def __eq__(self, o):
            return str(self) == str(o)

        def is_empty(self):
            return self.value is None and not self.contents

        def add_child(self, info):
            if self.value is not None:
                raise PDFPTException("We cannot set contents when the value is "
                                      "already set %s (contents: %s)" %
                                      (str(self), str(info)))
            if isinstance(info, RandomTypeMalform.DictInfo) and \
               info.is_empty() or info is None:
                return
            self.contents.append(info)

        def __repr__(self):
            if self.contents:
                return f"({self.key}:[" + \
                    " ,".join([str(c) for c in self.contents]) \
                    + "])"
            else:
                return f"({self.key}:{self.value})"

    def pt_to_dict_info(self, pt, key=b""):
        kids = pt.children
        info = RandomTypeMalform.DictInfo(key)
        if kids and kids[0].type == PDFEnum.DICT_START:
            # for each key/value pair, last key is 2 entries before DICT_END
            at_key = True
            key = None
            value = None
            for i in range(1, len(kids)-1):  # skip DICT_START
                if at_key:
                    key = kids[i]
                    value = None
                    if key.type == PDFEnum.DICT_END:
                        # we are done
                        break
                    elif key.type == PDFEnum.DICT_KEY_ERROR:
                        # try again
                        continue
                else:
                    value = kids[i]
                at_key = not at_key
                # process found pair
                if (key is not None) and (value is not None) and key.children \
                   and key.children[0].type == PDFEnum.NAME:
                    if (not len(key.children) == 1) and \
                       key.children[0].type == PDFEnum.NAME:
                        OOPS(PDFPTException,
                             "found a key who doesn't contain "
                             "exactly 1 child NAME: %s" % key)
                    key_name = key.children[0].value
                    # if just 1 child of the value, check if it's a name
                    # and add key with value if value is name, or just
                    # add key alone
                    if len(value.children) == 1:
                        child = value.children[0]
                        if child.type == PDFEnum.NAME:
                            c = RandomTypeMalform.DictInfo(key_name,
                                                           child.value)
                        else:
                            # just add key_name
                            c = RandomTypeMalform.DictInfo(key_name, b'')
                        info.add_child(c)
                    elif len(value.children) > 1:
                        # recurse if there is a nested dict, ignore
                        # and dicts nested in an array for now
                        if value.children[0].type == PDFEnum.DICT_START:
                            info.add_child(self.pt_to_dict_info(value,
                                                                key_name))
                    # reset
                    key = None
                    value = None
        return info if not info.is_empty() else None

    def update(self, pt):
        if pt.type in [PDFEnum.ROOT, PDFEnum.XREF_OBJ]:
            info = self.pt_to_dict_info(pt)
            if info and info not in self.dict_info:
                self.dict_info.append(info)

    def on_exit(self, save):
        super(RandomTypeMalform, self).on_exit(save)
        j = RandomTypeMalform.DictInfoEncoder().encode(list(self.dict_info))
        self.manager.ri.import_file(self.results_file, True, j + "\n")


class PDFPT(PT):
    type_enum = PDFEnum
    childless_types = [PDFEnum(i)
                       for i in range(PDFEnum.BOOL, PDFEnum.ARRAY)] + \
                           [PDFEnum(i) for i in range(PDFEnum.EOF,
                                                      PDFEnum.UNKNOWN)] + \
                           [PDFEnum.KEYWORD]

    def _type_str(self):
        if self.type == PDFEnum.ROOT:
            return "ROOT"
        elif self.type == PDFEnum.CONTAINER:
            return "OBJ"
        else:
            return super(PDFPT, self)._type_str()

    def _offset_str(self, print_taint=False):
        if self.type in [PDFEnum.ROOT, PDFEnum.CONTAINER]:
            return ""
        return super(PDFPT, self)._offset_str(print_taint)

    @classmethod
    def count_type_in_PT(cls, typ, value, tree):
        if (tree.type == typ) or \
           ((tree.type == PDFEnum.CMD) and tree.value == value):
            count = 1
        else:
            count = 0
        return count + sum([cls.count_type_in_PT(typ, value, c)
                            for c in tree.children])


class PDFLexObj(LexObj):
    type_enum = PDFEnum
    pt_class = PDFPT


class PDFPTMoment(PTMoment):
    pt_class = PDFPT

    def obj_val_eq(v1, v2):
        return v1.decode("utf-8", errors="replace").lower() == \
            v2.decode("utf-8", errors="replace").lower()


@dataclasses.dataclass(repr=False)
class ProcessStreamInfo(DataContext):
    ops_idx: typing.List[int] = dataclasses.field(default_factory=list)
    object_idx: int = None

    def ops(self):
        return [ParseObj.db_lookup(i) for i in self.ops_idx]


@dataclasses.dataclass(repr=False)
class XRefTableInfo(DataContext):
    trailer_idx: int = None
