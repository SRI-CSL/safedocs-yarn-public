# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import struct
from tracetools.signatures.signatures import MomentSignature
from tracetools import log_entries


class LibcMomentSignature(MomentSignature):
    lib_name = "libc-2.31.so"
    sig_id_name = None


class MemccpyMoment(LibcMomentSignature):
    sig_id_name = "LIBC_MEMCPY"
    remove_when_flagged = True

    @classmethod
    def setup(cls):
        cls.struct = struct.Struct("=Q")
        cls.fn_read_addrs_0 = cls.addrs_of("strcpy_read_0")
        cls.fn_read_addrs_1 = cls.addrs_of("strcpy_read_1")
        cls.fn_read_addrs_alt_0 = cls.addrs_of("strcpy_read_alt_0")
        cls.fn_read_addrs_alt_1 = cls.addrs_of("strcpy_read_alt_1")
        cls.fn_read_addrs_alt_2_0 = cls.addrs_of("strcpy_read_alt_2_0")
        cls.fn_read_addrs_alt_2_1 = cls.addrs_of("strcpy_read_alt_2_1")
        cls.fn_read_addrs_alt_3_0 = cls.addrs_of("strcpy_read_alt_3_0")
        cls.fn_read_addrs_alt_3_1 = cls.addrs_of("strcpy_read_alt_3_1")
        cls.fn_read_addrs_word_0 = cls.addrs_of("strcpy_read_word_0")
        cls.fn_read_addrs_word_1 = cls.addrs_of("strcpy_read_word_1")

        cls.fn_read_addrs_half_0 = cls.addrs_of("strcpy_read_half_0")
        cls.fn_read_addrs_half_1 = cls.addrs_of("strcpy_read_half_1")
        cls.fn_starts = cls.addrs_of("strcpy_start")
        cls.fn_ends = cls.addrs_of("strcpy_end")

    def reset(self):
        self.value = None
        self.read_count = 0
        self.read_value = b""
        self.alt_value = b""
        # self.accesses = []
        self.read_type_alt = True
        self.read_started = False
        self.read_size = 8

    def flag(self):
        self.value = self.read_value
        # print("got value", self.read_value)

    def do_log_entry(self, log_entry):
        # there may be multiple copies of libc loaded
        # so find the base addr for the currently active one
        if (not self.read_started) and \
             log_entries.is_kind(log_entry, log_entries.MemEntry) and \
             log_entry.typ is log_entry.READ:
            # print("read", log_entry.value_bytes,
            #       log_entry,
            #       f"read: {self.read_value}",
            #       f"alt: {self.alt_value}",
            #       ["%x" % (log_entry.pc - s) for s in self.lib_start])

            if log_entry.pc in self.fn_read_addrs_0 + self.fn_read_addrs_1 + \
               self.fn_read_addrs_alt_0 + self.fn_read_addrs_alt_1 + \
               self.fn_read_addrs_alt_2_0 + self.fn_read_addrs_alt_2_1 + \
               self.fn_read_addrs_alt_3_0 + self.fn_read_addrs_alt_3_1 + \
               self.fn_read_addrs_word_0 + self.fn_read_addrs_word_1 + \
               self.fn_read_addrs_half_0 + self.fn_read_addrs_half_1:
                # print("read started")
                self.read_started = True
            if log_entry.pc in self.fn_read_addrs_half_1:
                self.read_size = 2
        if self.read_started:
            if log_entries.is_kind(log_entry, log_entries.MemEntry) and \
               log_entry.typ is log_entry.READ:
                # print("read", log_entry.value_bytes,
                #       log_entry,
                #       f"read: {self.read_value}",
                #       f"alt: {self.alt_value}",
                #       ["%x" % (log_entry.pc - s) for s in self.lib_start])
                if log_entry.pc in self.fn_read_addrs_0 + \
                   self.fn_read_addrs_alt_0 + \
                   self.fn_read_addrs_alt_2_0 + \
                   self.fn_read_addrs_alt_3_0 + \
                   self.fn_read_addrs_word_0 + \
                   self.fn_read_addrs_half_0:
                    self.read_count += 1
                    self.alt_value += log_entry.value_bytes
                elif log_entry.pc in self.fn_read_addrs_1 + \
                     self.fn_read_addrs_alt_1 + \
                     self.fn_read_addrs_alt_2_1 + \
                     self.fn_read_addrs_alt_3_1 + \
                     self.fn_read_addrs_word_1 + \
                     self.fn_read_addrs_half_1:
                    self.read_count += 1
                    self.read_value += log_entry.value_bytes
                else:
                    if self.alt_value:
                        if self.read_size == 2:
                            self.read_value = self.read_value + \
                                self.alt_value[1:2]
                            self.do_flag(log_entry)
                            return
                        if self.read_value == self.alt_value:
                            try:
                                zero = self.read_value.index(0)
                                self.read_value = self.read_value[:zero]
                            except ValueError:
                                pass
                            self.do_flag(log_entry)
                            return
                        found_match = False
                        if len(self.read_value) > len(self.alt_value):
                            prefix = self.read_value[:(-1*len(self.alt_value))]
                            suffix = self.read_value[(-1*len(self.alt_value)):]
                        else:
                            prefix = b""
                            suffix = self.read_value
                        for i in range(0, len(suffix)):
                            # when we find the matching prefix of alt
                            if self.alt_value[:(-1*i)] == suffix[i:]:
                                # build up actual string
                                found_match = True
                                suffix += self.alt_value[-1*i:]
                                break
                        if found_match:
                            self.read_value = prefix + suffix
                        else:
                            self.read_value += self.alt_value
                        try:
                            zero = self.read_value.index(0)
                            self.read_value = self.read_value[:zero]
                        except ValueError:
                            pass
                    # print("got", self.read_value)
                    self.do_flag(log_entry)
