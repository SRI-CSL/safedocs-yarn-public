# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import logging
import cxxfilt
import re


raise_exception = False


def OOPS(e, *message):
    global raise_exception
    line = message if isinstance(message, str) \
        else " ".join([str(m) for m in message])
    if raise_exception:
        raise e(line)
    else:
        logging.error(line)


class Demangler():
    _demangle_cache = {}
    strip_re = re.compile("^([\W\w]+?)(_[\d]+)?$")

    @classmethod
    def demangle(cls, name):
        res = cls.strip_re.match(name)
        name = res.group(1) if res else name
        v = cls._demangle_cache.get(name)
        if v is None:
            try:
                d = cxxfilt.demangle(name)
            except cxxfilt.InvalidName:
                d = name
            v = cls._demangle_cache[name] = d
        return v

    @classmethod
    def demangle_names(cls, names):
        return [cls.demangle(n) for n in names]


def return_pc_from_call_pc(pc):
    return pc + 5


class BinaryInfoException(Exception):
    pass


class SigException(Exception):
    pass


class SigEvalException(Exception):
    pass
