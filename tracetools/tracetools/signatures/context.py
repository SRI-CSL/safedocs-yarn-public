# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import dataclasses
from tracetools.signatures.parse_obj import ParseObj
import typing


@dataclasses.dataclass(repr=False)
class DataContext():
    print_depth: typing.ClassVar[int] = 0

    def field_value(self, field):
        name = field.name
        value = getattr(self, name, None)
        if name.endswith("_idx"):
            if value is None:
                idx_value = None
            elif isinstance(value, list):  # resolve idxs in list
                idx_value = [v for v in [ParseObj.db_lookup(i) for i in value]
                             if v]
            else:  # resolve single index
                idx_value = ParseObj.db_lookup(value)

            idx_value = [] \
                if field.default_factory == list and idx_value is None \
                   else idx_value
        return value

    def field_repr(self, field, print_all=False):
        value = self.field_value(field)
        name = field.name
        # value = getattr(self, name)
        if name.endswith("_idx"):
            # if value is None:
            #     idx_value = None
            # elif isinstance(value, list):  # resolve idxs in list
            #     idx_value = [v for v in [ParseObj.db_lookup(i) for i in value]
            #                  if v]
            # else:  # resolve single index
            #     idx_value = ParseObj.db_lookup(value)
            try:
                if isinstance(value, list):
                    value_str = [v.__repr__(flattened=True,
                                            depth=self.__class__.print_depth,
                                            no_context=True)
                                 for v in value]
                elif value is None:
                    value_str = "[]" if field.default_factory == list \
                        else "None"
                else:
                    value_str = value.__repr__(flattened=True,
                                               depth=self.__class__.print_depth,
                                               no_context=True)
                name = name[:-1*len("_idx")]
            except Exception:
                # if we fail to lookup object corresponding to index
                value_str = str(value)
            if value is None:
                return f"{name}_idx={value_str}" if print_all else ""
        elif not print_all and self._is_default_value(field, value):
            return ""
        else:
            value_str = str(value)
        return f"{name}={value_str}"

    def __repr__(self, print_all=False):
        # only print interesting values
        contents = ", ".join(filter(lambda x: x,
                                    [self.field_repr(field, print_all)
                                     for field in dataclasses.fields(self)]))
        return f"{self.__class__.__name__}({contents})" if contents else ""

    def _is_default_value(self, field, value):
        # if is not dict/list and value is default or
        # if is dict/list and is empty
        return (isinstance(field.default_factory, dataclasses._MISSING_TYPE)
                and value == field.default) or \
            (not isinstance(field.default_factory, dataclasses._MISSING_TYPE)
             and not value)

    def merge(self, other):
        # merge other's field values if not null or not default
        for field in dataclasses.fields(self):
            value = getattr(other, field.name)
            if not other._is_default_value(field, value):
                setattr(self, field.name, value)

    def to_dict(self):
        # getattr(self, field.name, None)
        return {field.name: self.field_value(field)
                for field in dataclasses.fields(self)}

    @classmethod
    def from_dict(cls, j):
        return cls(**{f.name: j.get(f.name, None)
                      for f in dataclasses.fields(cls)})


@dataclasses.dataclass(repr=False)
class ParseReason(DataContext):
    callstack: str
    requester_pt_idx: int = None
    registered: dataclasses.InitVar[bool] = False

    @classmethod
    def create(cls,  from_obj, idx=None, manager=False):
        o = from_obj if manager else from_obj.manager
        return cls(o.ml.stack.detail_string(), idx)

    def merge(self, other):
        # don't change callstack or registered
        if other.requester_pt_idx is not None:
            self.requester_pt_idx = other.requester_pt_idx

    def __repr__(self, print_all=False, callstack=False):
        # don't include callstack by default
        contents = ", ".join(filter(lambda x: x,
                                    [self.field_repr(f, print_all)
                                     for f in dataclasses.fields(self)
                                     if f.name != "callstack" or callstack]))
        return f"{self.__class__.__name__}({contents})" if contents else ""
