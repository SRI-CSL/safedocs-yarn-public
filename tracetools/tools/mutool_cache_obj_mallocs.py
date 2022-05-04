#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
"""Example code that prints malloced addrs nested within call to pdf_cache_obj
-- using ghoststack frames and signatures

"""
import sys
from tracetools import yarn_args
from tracetools.signatures.versions import VersionManager
from tracetools.signatures.signatures import MomentSignature, SigID
from tracetools.signatures.ghoststack import StackOverlayEntry
from tracetools.signatures.evaluator import SigEval
from tracetools import log_entries


class GetObjFrame(StackOverlayEntry):
    """ Ghoststack frame that corresponds to active pdf_cache_object call,
    This gets pushed to stack when function specified by flag_addr_fn_name is
    called and popped when function finally returns.
    """
    lib_name = "mutool"
    sig_id_name = "CACHE_OBJ"  # unique identifer for signature that causes
                               # GetObjFrame ghoststack from to be pushed onto
                               # stack. Corresponding signature will
                               # be registered with SignatureManager
                               # under this name can can be referenced
                               # using: SigID.CACHE_OBJ

    flag_addr_fn_name = "pdf_cache_object"  # symbol name of function that
                                            # when called, causes instance
                                            # of this stack frame to be
                                            # pushed onto ghoststack
    call_count = 0  # keep class-wide count to pdf_cache_obj, starting at 0

    def __init__(self, sig):
        self.malloc_addrs = []
        # when an instance of this frame is pushed to the top of the
        # ghoststack or is otherwise at the top of the ghoststack
        # enable the MU_MALLOC signature, disable this signature
        # when this stack frame is not at the top of the ghostack
        # --- this is done by adding an instance of the MU_MALLOC signature
        # to ghostsite_sigs set
        sigs = set([self.manager.sig_from_id(SigID.MU_MALLOC)])
        super().__init__(sig, ghostsite_sigs=sigs)

    def on_push(self, old_top):
        self.__class__.call_count += 1
        super().on_push(old_top)

    def on_pop(self, new_top):
        # this is called when pdf_cache_object returns
        print(f"pdf_cache_obj call #{self.call_count} had "
              f"{len(self.malloc_addrs)} nested malloc calls:",
              [f"{addr:x}" for addr in self.malloc_addrs])
        super().on_pop(new_top)

    def register_malloc(self, addr):
        self.malloc_addrs.append(addr)


class MallocSig(MomentSignature):
    """ Signature that is flagged when memory is allocated """
    sig_id_name = "MU_MALLOC"  # unique identifer for signature, will
                               # be registered with SignatureManager
                               # under this name can can be referenced
                               # using: SigID.MU_MALLOC

    # definitions that help determine when this signature should be "flagged"
    log_type = log_entries.MallocEntry  # type of log entry that should
                                        # be checked
    attr_name = "kind_meta"  # name of log entry attribute that we are
    check_values = [log_entries.MallocEntry.MALLOC]  # only flag signature if
                                                     # log entry's kind_meta
                                                     # value indicates memory was
                                                     # allocated (and not freed)
    # if log_entry is an instance of log_entries.MallocEntry and
    #     getattr(log_entry, "kind_meta") == log_entries.MallocEntry.MALLOC: then
    #     self.flagged_entry = log_entry (log_entry is saved as self.flagged_entry)
    #     self.flag()  (self.flag() is called)

    parent_frame_class = GetObjFrame

    def flag(self):
        """ This is called when flagging conditions are met """
        # self.parent_frame contains the top-most ghoststack
        # frame that is an instance of self.parent_frame_class
        # (which is GetObjFrame in this case)
        self.parent_frame.register_malloc(self.flagged_entry.malloc_addr)


class CacheMallocTracker(SigEval):
    """ SigEval class manages signature creation and invocation"""
    def __init__(self, args):
        """ :param args: parsed YARN command line arguments
              (returned by (yarn_args.YarnArgParser().parse_args())
        """
        # initiate VersionManager for results_obj corresponding
        # to what was passed as argument to `-R` on command line,
        # tell it to load the address cache
        manager = VersionManager(args.results_obj, from_cache=True)
        # use instance of VersionManager to instantiate a
        # tracetools.parse_log.MemtraceLog given parsed command-line
        # arguments
        parse_log  = manager.create_parselog(args)
        # allow parent classes' __init__ to prepare itself to iterate
        # through result's trace log
        super().__init__(parse_log)
        # install the CACHE_OBJ signature (defined above in
        # GetObjFrame class that causes GetObjFrame to be pushed
        # to ghostack)
        self.add_sig(self.sig_from_id(SigID.CACHE_OBJ))


if __name__ == "__main__":
    # instantiate YARN argument parser which handles parsing passed
    # test results path
    parser = yarn_args.YarnArgParser("print # mallocs w/in call to pdf_cache_obj")

    # instantiate class that will perform test result log analysis,
    # passing it results from `parse_args`
    tracker = CacheMallocTracker(parser.parse_args(sys.argv[1:]))

    # process log
    tracker.run()

    # cleanup
    tracker.close()
