#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
"""Example code that makes use of address caches, signatures, and
signature evaluation -- prints out object number indirect objects
fetched within/by mutool

"""
import sys
from tracetools import yarn_args
from tracetools.signatures.versions import VersionManager
from tracetools.signatures.signatures import MomentSignature, SigID

from tracetools.signatures.evaluator import SigEval
from tracetools import log_entries


class FetchSig(MomentSignature):
    """ Signature that is flagged when pdf_cache_obj num is read"""
    sig_id_name = "MU_FETCH"  # unique identifer for signature, will
                              # be registered with SignatureManager
                              # under this name can can be referenced
                              # using: SigID.MU_FETCH

    # definitions that help determine when this signature should be "flagged"
    log_type = log_entries.MemEntry  # type of log entry that should
                                     # be checked
    attr_name = "pc"  # name of log entry attribute that we are
                      # checking the value of
    lib_name = "mutool"  # name of parser under for which this
                         # signature is defined (based on information
                         # contained in signature definition json)
    flag_addr_name = "pdf_cache_obj_num"  # address cache name
                                          # containing absolute
                                          # addresses we are searching for ---
    # if log_entry is an instance of log_entries.MemEntry and getattr(log_entry, "pc") in
    #            [absolute addresses corresponding to "pdf_cache_obj_num"]: then
    #     self.flagged_entry = log_entry (log_entry is saved as self.flagged_entry)
    #     self.flag()  (self.flag() is called)

    def flag(self):
        """ This is called when flagging conditions are met """
        print("Fetching object", self.flagged_entry.unpack_signed_int())


class CacheNumTracker(SigEval):
    """ SigEval class manages signature creation and invocation"""
    def __init__(self, args):
        """ :param args: parsed YARN command line arguments
              (returned by (yarn_args.YarnArgParser().parse_args())
        """
        # initiate VersionManager for results_obj corresponding
        # to what was passed as argument to `-R` on command line,
        # tell it to load the address cache
        manager = VersionManager(args.results_obj, from_cache=True)
        parse_log = manager.create_parselog(args)
        # allow parent classes' __init__ to prepare itself to iterate
        # through result's trace log
        super().__init__(parse_log)
        # enable install the MU_FETCH signature (defined above in
        # FetchSig class)
        self.add_sig(self.sig_from_id(SigID.MU_FETCH))


if __name__ == "__main__":
    # instantiate YARN argument parser which handles parsing passed
    # test results path
    parser = yarn_args.YarnArgParser("print nubmer of fetched objects")

    # instantiate class that will perform test result log analysis,
    # passing it results from `parse_args`
    tracker = CacheNumTracker(parser.parse_args(sys.argv[1:]))

    # process log
    tracker.run()

    # cleanup
    tracker.close()
