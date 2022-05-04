# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
from tracetools.signatures.signatures import SigID, NewFrameMoment, \
    PTMoment
from tracetools.signatures.versions import Version
from tracetools.signatures.utils import SigEvalException, OOPS
from tracetools.signatures.context import ParseReason
from tracetools import log_entries


new_frame_factory_next_id = 0


class StackOverlayEntry():
    sig_id_name = None
    log_type = log_entries.CallEntry
    attr_name = "target_addr"
    flag_addr_fn_name = None
    flag_addr_fn = None
    sig_class_name = None
    sig_baseclass = NewFrameMoment
    remove_when_flagged = False
    struct_format = None
    exception_class = SigEvalException
    fn_names = []
    subattr_value = None
    __setup_done = False

    # @classmethod
    # def sig_frame_args(cls):
    #     def frame_args(self):
    #         return None
    #     return frame_args

    # @classmethod
    # def sig_setup(framecls, cls):
    #     def setup():
    #         pass
    #     return setup

    manager = None
    parse_log = None
    lib_name = None
    primary_binary = None
    supported_group_ids = []
    add_child_on_pop = True

    @classmethod
    def create_new_frame_sig(cls):
        global new_frame_factory_next_id
        attr = {k: getattr(cls, k) for k in ["sig_id_name",
                                             "remove_when_flagged",
                                             "log_type", "fn_names",
                                             "supported_group_ids",
                                             "primary_binary",
                                             "lib_name",
                                             "sig_reg_if_no_subclass",
                                             "struct_format",
                                             "attr_name",
                                             "subattr_value",
                                             "flag_addr_fn_name",
                                             "flag_addr_fn"]}
        if hasattr(cls, "subattr_name"):
            attr["subattr_name"] = cls.subattr_name

        attr["push_frame_class"] = cls
        if not cls.sig_class_name:
            sig_class_name = f"DynamicNewFrameSig{new_frame_factory_next_id}"
            new_frame_factory_next_id += 1
        newcls = type(sig_class_name, (cls.sig_baseclass,), attr)
        sig_setup = getattr(cls, "sig_setup", None)
        if sig_setup:
            newcls.setup = cls.sig_setup(newcls)
        for i in ["flag", "frame_args", "reset"]:
            attr = getattr(cls, f"sig_{i}", None)
            if attr:
                setattr(newcls, i, attr())
        return newcls

    def __repr__(self):
        n = str(type(self)).split("'")[1].split(".")[-1]
        return f"FRAME[{n}:{id(self)}]"

    @classmethod
    def addrs_of(cls, name, num=None):
        return Version.get(cls.lib_name).addrs_of(name, num)

    @classmethod
    def setup_frame_classes(cls, manager, parselog, sig_registrar, fcls=None,
                            dynamic_classes=None):
        fcls = fcls if fcls else cls
        if fcls.primary_binary is True and \
           Version.group_id in fcls.supported_group_ids:
            fcls.lib_name = Version.primary_binary()
        if (fcls.lib_name is None and not fcls.primary_binary) or \
           Version.has_lib_info(fcls.lib_name):
            fcls.setup_class(manager, parselog, sig_registrar)
        for sub in fcls.__subclasses__():
            if not sub.__setup_done or sub.__subclasses__():
                cls.setup_frame_classes(manager, parselog, sig_registrar, sub)
                sub.__setup_done = True
        if not dynamic_classes:
            dynamic_classes = []
        for sub in [f for f in dynamic_classes if issubclass(f, cls)]:
            if not sub.__setup_done:
                cls.setup_frame_classes(manager, parselog, sig_registrar, sub)
                sub.__setup_done = True

    @classmethod
    def setup_class(cls, manager, parse_log, sig_registrar):
        cls.manager = manager
        cls.parse_log = parse_log
        has_lib_info = Version.has_lib_info(cls.lib_name)
        if not hasattr(cls, "sig_reg_if_no_subclass"):
            cls.sig_reg_if_no_subclass = False
        cls.lib_starts = Version.lib_starts(cls.lib_name) \
            if cls.lib_name and has_lib_info else []

        if cls.sig_id_name and (not cls.sig_reg_if_no_subclass or
                                (cls.sig_reg_if_no_subclass and
                                 not cls.__subclasses__())):
            sigcls = cls.create_new_frame_sig()
            sig_registrar.setup_sig_classes(manager, parse_log, sigcls)

        cls.setup()

    @classmethod
    def setup(cls):
        pass

    def __init__(self, flagged_signature, ghostsite_sigs=None, return_sig=None,
                 stack_info=None):
        self.user_data = None
        self.flagged_signature = flagged_signature
        self.flagged_log_index = self.flagged_signature.flagged_entry.log_index
        self.callstackentry = self.manager.ml.stack.top()
        self.callstackentry_idx = len(self.manager.ml.stack.stack) - 1
        self.stack_info = stack_info if stack_info is not None else \
            self.manager.callstack_summary()
        self.return_addr = self.callstackentry.ret
        if return_sig is None:
            return_sig = self.manager.sig_from_id(SigID.RETURN,
                                                  self._on_return_sig,
                                                  self.return_addr)

        else:
            return_sig = self.manager.sig_from_id(return_sig,
                                                  self._on_return_sig)
        return_sig._parent_frame = self
        self.return_sig = return_sig
        self.ghostsite_sigs = ghostsite_sigs if ghostsite_sigs else set()
        self.ghostsite_sigs.add(return_sig)

    def _on_return_sig(self, signature):
        # pop this frame and anything that may sit above it
        self.manager.pop_stack(self)

    @property
    def sigs(self):
        return list(self.ghostsite_sigs)

    def add_ghostsite_sig(self, sig):
        self.ghostsite_sigs.add(sig)
        if self.manager.ghoststack.top() == self:
            self.manager.add_sig(sig)

    def add_ghostsite_sig_group(self, sigs):
        self.ghostsite_sigs.update(sigs)
        return self.manager.add_sig_group(sigs,
                                          self.manager.stack_top() == self)

    def remove_ghostsite_sig(self, sig):
        self.ghostsite_sigs.discard(sig)
        if self.manager.stack_top() == self:
            self.manager.remove_sig(sig, self.ghostsite_sigs.discard)

    def disable_frame(self):
        [self.manager.signatures._disable_sig(s)
         for s in self.ghostsite_sigs]

    def enable_frame(self):
        [self.manager.signatures._enable_sig(s)
         for s in self.ghostsite_sigs]

    def on_pop(self, new_top):
        """ called when finally popped of stack, after pop """
        for s in list(self.ghostsite_sigs):
            self.manager.remove_sig(s)
        # self.ghostsite_sites = set()

    def on_push(self, old_top):
        """ called when first pushed on stack, after push """
        self.enable_frame()

    def on_pop_to_top(self, old_top):
        """ called when resurfaces to top of stack, after pop """
        self.enable_frame()

    def on_push_from_top(self, new_top):
        """ called when is replaced as stack top due to push, after push """
        self.disable_frame()

    def OOPS(self, *message):
        OOPS(self.exception_class, *message, "\n",
             f"Frame information: {self.debug_string()}",
             "\n",
             f"Evaluator information: {self.manager.debug_string()}")

    @property
    def on_top(self):
        return self.manager.stack_top() == self

    def debug_string(self):
        return f"{self} ID: {self.callstackentry.callsite_id}/" + \
            str(self.flagged_log_index) + " " + \
            f"callsite sigs: {self.ghostsite_sigs}"


class PTStackOverlayEntry(StackOverlayEntry):
    primary_pt = True

    def __init__(self, flagged_signature, ghostsite_sigs=None,
                 pt_tracking_sigs=None, return_sig=None,
                 stack_info=None, pt=None):
        if pt and not pt.get_context(ParseReason):
            pt.add_context(ParseReason.create(self))
        self._pt = pt
        pt_tracking_sigs = pt_tracking_sigs if pt_tracking_sigs else set()
        self.pt_tracking_sigs = pt_tracking_sigs
        self._register_pt = getattr(self, "_register_pt", False)
        self.prev_top = getattr(self, "prev_top",
                                self.manager.stack_top(PTStackOverlayEntry))
        self._track_pt = getattr(self, "_track_pt",
                                 self.prev_top.track_pt
                                 if self.prev_top else True)
        if isinstance(flagged_signature, PTMoment):
            # register first object from it with self
            flagged_signature.handle_lex_obj(self)
        super(PTStackOverlayEntry, self).__init__(flagged_signature,
                                                  ghostsite_sigs,
                                                  return_sig, stack_info)

    def debug_string(self):
        return super(PTStackOverlayEntry, self).debug_string() + \
            f" pt tracking sigs: {self.pt_tracking_sigs}"

    @property
    def register_pt_with_manager(self):
        return self._register_pt

    @property
    def track_pt(self):
        return self._track_pt

    @track_pt.setter
    def track_pt(self, track: bool):
        if not self._track_pt and track:
            # if we switch from not tracking to tracking
            self._enable_pt_tracking_sigs(True)
        elif not track and self._track_pt:
            # if we switch from tracking to not tracking
            self._disable_pt_tracking_sigs(True)
        self._track_pt = track

    @property
    def pt(self):
        return self._pt

    def add_pt_child(self, child):
        self.pt.add_child(child)

    def register_pt_node(self, child, reg_obj):
        if self.track_pt:
            self.add_pt_child(child)

    def get_pt_children(self):
        if self._pt:
            return self._pt.children
        else:
            return []

    def get_last_pt_child(self):
        if self._pt:
            return self._pt.get_last_child()

    def set_last_pt_child(self, typ, value=None, taint=None,
                          first_taint=None):
        if self.track_pt:
            self._pt.set_last_child(typ, value, taint, first_taint)

    def set_pt_type(self, typ):
        if self.track_pt:
            self._pt.set_type(typ)

    def _enable_pt_tracking_sigs(self, update_manager=False):
        self.ghostsite_sigs |= self.pt_tracking_sigs
        if update_manager and self.on_top:  # update manager sigs if on top
            [self.manager.add_sig(s) for s in self.pt_tracking_sigs]

    def _disable_pt_tracking_sigs(self, update_manager=False):
        self.ghostsite_sigs -= self.pt_tracking_sigs
        if update_manager and self.on_top:  # update manager sigs if on top
            [self.manager.remove_sig(s) for s in self.pt_tracking_sigs]

    def _add_sigs_to_sets(self, sigs, pt_tracking):
        if pt_tracking:
            self.pt_tracking_sigs.update(sigs)
        if (pt_tracking and self.track_pt) or (not pt_tracking):
            self.ghostsite_sigs.update(sigs)

    def add_ghostsite_sig_group(self, sigs, pt_tracker=True):
        self._add_sigs_to_sets(sigs, pt_tracker)
        return self.manager.add_sig_group(sigs,
                                          self.manager.stack_top() == self)

    def add_ghostsite_sig(self, sig, pt_tracker=True):
        self._add_sigs_to_sets(set([sig]), pt_tracker)
        return self.manager.add_sig(sig, self.manager.stack_top() == self)

    def remove_ghostsite_sig(self, sig):
        def remove(s):
            self.ghostsite_sigs.discard(s)
            self.pt_tracking_sigs.discard(s)
        remove(sig)
        if self.manager.stack_top() == self:
            self.manager.remove_sig(sig, remove)

    def do_register_pt(self, pt, current_stack=False):
        stack = self.stack_info if not current_stack else \
            self.manager.callstack_summary()
        self.manager.register_pt(pt, stack)

    def on_pop(self, new_top):
        super(PTStackOverlayEntry, self).on_pop(new_top)
        if new_top is None and self.track_pt and \
           self.register_pt_with_manager:
            self.do_register_pt(self.pt)

    def disable_frame(self):
        super(PTStackOverlayEntry, self).disable_frame()
        self._disable_pt_tracking_sigs()
        self.ghostsite_sigs -= self.pt_tracking_sigs

    def enable_frame(self):
        if self.track_pt:
            self._enable_pt_tracking_sigs()
        super(PTStackOverlayEntry, self).enable_frame()

    def calculate_cache_id(self, pt_begin):
        return self.manager.cache_id(pt_begin, self.stack_info)

    def manager_has_cached_pt(self, pt_begin):
        return self.manager.has_cached_pt(
            pt_begin,
            self.calculate_cache_id(pt_begin)
        )

    def cache_pt_with_manager(self, pt):
        first = self.calculate_cache_id(pt.first_taint)
        self.manager.cache_pt(pt, cache_id=first)

    @property
    def cache_id(self):
        if self.pt is None:
            return None
        else:
            return self.calculate_cache_id(self.pt.first_taint)
