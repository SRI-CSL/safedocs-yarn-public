# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from tracetools.pt import EmptyPTEnum, PT
from tracetools.signatures.parse_obj import ParseObj


class LexObj(ParseObj):
    type_enum = EmptyPTEnum
    pt_class = PT

    @classmethod
    def lex_type_to_pt_type(cls, typ):
        return cls.pt_class.type_enum(typ)

    def to_pt(self, pt_typ=None):
        typ = pt_typ if pt_typ else self.lex_type_to_pt_type(self.type)
        return self.pt_class(typ, self.value,
                             self.get_taint(), self.first_taint,
                             context=self.context)
