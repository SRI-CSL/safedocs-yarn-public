# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import dataclasses
import os
import glob
import json
import hashlib
import logging
import re
import importlib
import inspect
from typing import List, Dict, Union, ClassVar
from tracetools import parse_log
from tracetools.signatures.addr_calculator import AddrCache
from tracetools.signatures.utils import BinaryInfoException
from tracetools.signatures.utils import Demangler


@dataclasses.dataclass
class VersionAddrInfo():
    kind: str = None
    subtype: str = None
    addresses: List[str] = dataclasses.field(default_factory=list)
    target: str = None
    field: str = None
    path: str = None
    lineno: int = None
    function: str = None
    offset: int = None
    ins_type: str = None
    active_addresses: List[int] = dataclasses.field(default_factory=list)
    required: bool = True

    @property
    def demangled_target(self):
        if self._demangled_target is None and self.target is not None:
            self._demangled_target = Demangler.demangle(self.target)
        return self._demangled_target

    @property
    def demangled_function(self):
        if self._demangled_function is None and self.function is not None:
            self._demangled_function = Demangler.demangle(self.function)
        return self._demangled_function

    def __post_init__(self):
        self.offset = self.offset if not isinstance(self.offset, str)\
            else int(self.offset, 0)
        self._demangled_target = None
        self._demangled_function = None

    @classmethod
    def from_dict(cls, d: dict, src_root: str, required: bool = True):
        cls_dict = {"required": required}
        for f in dataclasses.fields(cls):
            if f.name.startswith("_"):
                continue
            v = d.get(f.name)
            if f.type == str and v is not None:
                v = [i.strip() for i in v] if isinstance(v, list) else \
                    v.strip()
            elif f.type == int and isinstance(v, list):
                v = [int(i, 0) if isinstance(i, str) else i for i in v]
            if v is not None:
                cls_dict[f.name] = v
        path = cls_dict.get("path")
        if path is not None:
            if isinstance(path, list):
                path = [os.path.join(src_root, p) if p and src_root else p
                        for p in path]
            else:
                path = os.path.join(src_root, path) if path and src_root else \
                    path
            cls_dict["path"] = path
        return cls(**cls_dict)

    def select_index(self, idx):
        selected = []
        if idx < len(self.addresses):
            selected = self.addresses[idx]
            if not isinstance(selected, list):
                selected = [selected]
        self.set_active_addrs([int(s, 0) for s in selected])
        for field in ["lineno", "path", "offset", "subtype", "kind", "target",
                      "function", "ins_type", "field"]:
            contents = getattr(self, field)
            if isinstance(contents, list):
                setattr(self, field, contents[idx])

    def set_active_addrs(self, addrs):
        self.active_addresses = addrs


@dataclasses.dataclass
class NamedAddr():
    name: str
    addr: List[int]

    @classmethod
    def from_defn(cls, name: str, d: dict, addr_idx: int):
        all_addrs = d.get("addresses", [])
        if len(all_addrs) <= addr_idx:
            return None
        addrs = all_addrs[addr_idx]
        if not isinstance(addrs, list):
            addrs = [addrs]
        return NamedAddr(name, [int(a, 0) for a in addrs])


@dataclasses.dataclass
class BinaryHash():
    name: str
    sha256sum: str


@dataclasses.dataclass
class BinaryVersion():
    name: str
    addr_index: int
    src_root: str
    track_libraries: List[str] = dataclasses.field(default_factory=list)
    binaries: List[BinaryHash] = dataclasses.field(default_factory=list)
    longjmp_functions: List[str] = dataclasses.field(default_factory=list)

    @classmethod
    def create(cls, name: str, bin_hashes: List[str],
               tracked: List[str],
               src_root: str, addr_index: int, longjmp: List[str]):
        return cls(name, addr_index, src_root, tracked,
                   [BinaryHash(k, v) for (k, v) in bin_hashes.items()],
                   longjmp)

    def get_basename(self, sha256sum: str) -> str:
        for b in self.binaries:
            if b.sha256sum == sha256sum:
                return b.name

    def has_hash(self, sha256sum):
        return False if self.get_basename(sha256sum) is None else True


@dataclasses.dataclass
class LibSummary():
    name: str
    src_root: str
    additional_files: List[str] = dataclasses.field(default_factory=list)
    track: bool = False  # if true, library tracking should be enabled

    # for parselog addr name -> VersionAddrInfo
    addresses: Dict[str, VersionAddrInfo] = dataclasses.field(
        default_factory=dict
    )

    _arrayre_raw: ClassVar[str] = r":(\d+)$"
    _arrayre: ClassVar[re.Pattern] = re.compile(_arrayre_raw)

    def _is_addr_array(self, name: str):
        return True if self._arrayre.search(name) else False

    def add_addr_info(self, name: str, addr: int, from_cache: bool = False):
        if (not from_cache) or (addr.required or addr.active_addresses):
            self.addresses[name] = addr

    def addr_names(self):
        def extract_name(n):
            if self._is_addr_array(n):
                return n.rsplit(":", 1)[0]
            else:
                return n
        names = set()
        [names.add(extract_name(k)) for k in self.addresses.keys()]
        return list(names)

    def _get_array_entry_names(self, name: str) -> List[str]:
        namere = re.compile(name + self._arrayre_raw)
        return [k for k in self.addresses.keys() if namere.match(k)]

    def get_entry(self, name: str) -> Union[VersionAddrInfo,
                                            List[VersionAddrInfo]]:
        if name in self.addresses:
            return self.addresses[name]
        else:
            names = self._get_array_entry_names(name)
            # sort by "index"
            names.sort(key=lambda x: int(x.rsplit(":", 1)[1]))
            return [self.addresses[n] for n in names]

    def get_addr_dict(self) -> Dict[str, List[int]]:
        return {n: self.lookup_addrs(n) for n in self.addr_names()}

    def lookup_addrs(self, name: str) -> List[int]:
        e = self.get_entry(name)
        if not isinstance(e, list):
            return e.active_addresses
        else:
            # combine addresses as single array
            try:
                addrs = []
                for i in e:
                    addrs.extend(i.active_addresses)
                return addrs
            except IndexError:
                raise BinaryInfoException(
                    f"{self.name} found no address "
                    f"definitions in this version's addrs "
                    f"for {name}. Try recreating the addreses "
                    " cache (run with the -g option)"
                )


class VersionSummary():
    ANYLIB = "any"
    ALLLIB = "all"

    def __init__(self, versionmanager, hashes, from_cache=None):
        self.libs = {}  # lib name -> LibSummary
        self.tracked_libs = set()
        self.longjmp_fns = set()
        self.primary = None

        for versioninfo in versionmanager.all_versions:
            definition_order = versioninfo.addr_dict.get("definition_order",
                                                         [])
            additional_files = versioninfo.addr_dict.get("additional_files",
                                                         [])
            found_hash = False
            for (k, bv) in versioninfo.bin_versions.items():
                for h in hashes:
                    lib_name = bv.get_basename(h)
                    if not lib_name:
                        continue
                    if not found_hash:
                        found_hash = True
                        if versioninfo.primary:
                            if self.primary is not None:
                                raise BinaryInfoException(
                                    "Multiple primary ids found in parser"
                                    "definitions, will not be able to "
                                    "determine which parser signatures "
                                    "to load. primary parsers found: "
                                    f"{self.primary}, {versioninfo.primary}"
                                )
                            self.primary = versioninfo.group_id
                    if lib_name in self.libs:
                        lib_summary = self.libs[lib_name]
                    else:
                        lib_summary = LibSummary(lib_name, bv.src_root,
                                                 additional_files)
                    self.libs[lib_name] = lib_summary
                    self.tracked_libs.update(bv.track_libraries)
                    self.longjmp_fns.update(bv.longjmp_functions)
                    if lib_name in bv.track_libraries:
                        lib_summary.track = True
                    try:
                        addr_index = definition_order.index(k)
                    except ValueError:
                        addr_index = 0
                    cache = AddrCache.load_cache(from_cache, lib_name) \
                        if from_cache and AddrCache.has_cache(from_cache,
                                                              lib_name) \
                                                              else None

                    def setup_addrs(addrdicts, required):
                        for (a_name, a_val) in addrdicts.items():
                            a = VersionAddrInfo.from_dict(a_val,
                                                          lib_summary.src_root,
                                                          required)
                            addrs = cache.get(a_name) if cache else None
                            if addrs is not None:
                                a.set_active_addrs(addrs)
                            else:
                                a.select_index(addr_index)
                            lib_summary.add_addr_info(a_name, a, from_cache)

                    # add lib-specific addrs and optional addrs
                    setup_addrs(versioninfo.addr_dict.get(lib_name, {}), True)
                    setup_addrs(versioninfo.addr_dict.get(self.ANYLIB,
                                                          {}),
                                False)
                    setup_addrs(versioninfo.addr_dict.get(self.ALLLIB,
                                                          {}),
                                True)

    def get_tracked_libraries(self):
        return list(self.tracked_libs)

    def get_longjmp_functions(self):
        return list(self.longjmp_fns)

    def get_all_addrs(self):
        addrs = {}
        [addrs.update(lib.get_addr_dict()) for lib in self.libs.values()]
        return addrs


class VersionInfo():
    def __init__(self, json_path: str):
        self.json_path = json_path
        with open(json_path, "r") as f:
            try:
                j = json.load(f)
            except json.decoder.JSONDecodeError as e:
                logging.error(f"JSON parsing error found in {json_path}")
                raise e
        self.group_id = j.get("group_id", "")
        self.primary = j.get("primary", False)
        track_libraries = j.get("track_libraries", {})
        longjmp_functions = j.get("longjmp_functions", {})
        self.addr_dict = j.get("addresses", {})
        definition_order = self.addr_dict.get("definition_order", [])
        src_roots = self.addr_dict.get("build_src_root", [])
        self.bin_versions = {}
        for (k, v) in j.get("binary_versions", {}).items():
            tracked = track_libraries.get(k, [])
            longjmp = longjmp_functions.get(k, [])
            try:
                addr_index = definition_order.index(k)
            except ValueError:
                addr_index = 0
            src_root = src_roots[addr_index] \
                if len(src_roots) > addr_index else ""
            self.bin_versions[k] = BinaryVersion.create(k, v, tracked,
                                                        src_root,
                                                        addr_index,
                                                        longjmp)


class LibAddrs():
    def __init__(self, libname, bin_info, addrs):
        self._name = libname
        self._bin_info = bin_info
        self._addrs = addrs
        self._lib_starts = None
        self._lib_copies = None

    @property
    def lib_starts(self):
        if self._lib_starts is None:
            self._lib_starts = self._bin_info.abs_addrs_of_lib(self._name)
            self._lib_copies = len(self._lib_starts)
        return self._lib_starts

    @property
    def lib_regions(self):
        return self._bin_info.lib_regions(self._name)

    def addrs_of(self, name, num_expected=None, absolute=True):
        addrs = self._addrs[name]
        if not addrs or any([a is None for a in addrs]):
            raise BinaryInfoException(f"Issue looking up addrs "
                                      f"for {self._name}:{name}, found "
                                      + str(addrs))

        if absolute:
            addrs = [a + s for a in addrs
                     for s in self.lib_starts]
        if num_expected is not None and len(addrs) != num_expected:
            raise BinaryInfoException(f"expected only {num_expected} results "
                                      f"for {self._name}:{name} but found "
                                      f" {len(addrs)}")
        if num_expected == 1:
            return addrs[0]
        else:
            return addrs


class Version():
    version_data = {}
    bin_info = None
    group_id = None

    @classmethod
    def get(self, libname):
        v = self.version_data.get(libname)
        if v is None:
            raise BinaryInfoException("Version information for library "
                                      f"{libname} does not exist")
        return v

    @classmethod
    def lib_starts(cls, libname, num_expected=None):
        v = cls.get(libname)
        starts = v.lib_starts
        if num_expected is not None and len(starts) != num_expected:
            raise BinaryInfoException(f"Did not find exactly {num_expected} "
                                      f"lib starts for {libname}, "
                                      f"found {len(starts)}")

        return starts[0] if num_expected == 1 else starts

    @classmethod
    def get_fn_abs_addr(cls, name, anytype=False, lib=None,
                        num_expected=None):
        fns = cls.bin_info.get_fn_info_from_name(name, anytype, lib)
        res = list(set([cls.bin_info._virt_to_abs(f.start, seg)
                        for (f, seg) in fns]))
        if num_expected is not None and len(res) != num_expected:
            raise BinaryInfoException(f"Did not find exactly {num_expected} "
                                      "function named "
                                      f"'{name}' (found: {res})")
        if num_expected == 1:
            return res[0]
        return res

    @classmethod
    def get_fn_abs_and_plt_addrs(cls, name, lib):
        res = set()
        for kind in [True, False]:
            fns = cls.bin_info.get_fn_info_from_name(name, kind, lib)
            res.update([cls.bin_info._virt_to_abs(f.start, seg)
                        for (f, seg) in fns])
        return res

    @classmethod
    def setup(cls, bin_info, group_id):
        cls.bin_info = bin_info
        cls.group_id = group_id

    @classmethod
    def has_lib_info(cls, name: str) -> bool:
        try:
            cls.get(name)
            return True
        except BinaryInfoException:
            return False

    @classmethod
    def primary_binary(cls) -> str:
        return cls.bin_info.binary_name

    @classmethod
    def setup_lib(cls, lib_name, addrs: Dict[str, List[int]]):
        if lib_name in Version.version_data:
            raise BinaryInfoException(f"Library {lib_name} already defined")
        Version.version_data[lib_name] = LibAddrs(lib_name,
                                                  cls.bin_info, addrs)


class VersionManager():

    def __init__(self, results_info, from_cache=False,
                 version_dir=os.path.join(os.path.dirname(__file__),
                                          "definitions"),
                 hashes=None):
        self.ri = results_info
        self.all_versions = [VersionInfo(defn)
                             for defn in glob.glob(version_dir + "/*.json")]
        hashes = hashes if hashes else []
        self.hashes = self.calc_bin_hashes(results_info) \
            if results_info else hashes
        cache = results_info if from_cache else None
        self.summary = VersionSummary(self, self.hashes, cache)

    def get_tracked_libraries(self) -> List[str]:
        return self.summary.get_tracked_libraries()

    def get_longjmp_functions(self) -> List[str]:
        return self.summary.get_longjmp_functions()

    def get_parser_id(self) -> str:
        return self.summary.primary

    def create_parselog(self, yarn_args, **kwargs):
        missing_lib_caches = [lib for lib in self.summary.libs.keys()
                              if not AddrCache.has_cache(self.ri, lib)]
        if missing_lib_caches:
            logging.warning("Address version cache for these results have not "
                            "been createed yet for libraries: "
                            f"{', '.join(missing_lib_caches)}. Try rerunning "
                            "pt tracker with '-g' option to generate cache")
        for (name, val) in [('track_callstack', True),
                            ('track_file_ops', True)]:
            kwargs[name] = kwargs.get(name, val)
        kwargs['track_libraries'] = self.get_tracked_libraries() + \
            kwargs.get('track_libraries', [])
        kwargs["longjmp_functions"] = self.get_longjmp_functions() + \
            kwargs.get('longjmp_functions', [])

        ml = parse_log.MemtraceLog(yarn_args=yarn_args,
                                   res=self.ri,
                                   no_track_except=True,
                                   **kwargs)
        Version.setup(ml.binfo, self.summary.primary)
        for (libname, l) in self.summary.libs.items():
            Version.setup_lib(libname, l.get_addr_dict())
        return ml

    @classmethod
    def calc_bin_hashes(cls, results_info) -> List[str]:
        bindir = os.path.join(results_info.r.parser_bins_dir)
        hashes = []
        for b in glob.glob(bindir + "/*"):
            h = hashlib.sha256()
            with open(b, "rb") as f:
                h.update(f.read())
            hashes.append(h.hexdigest())
        return hashes

    @classmethod
    def do_gen_bin_metadata(cls, results_info, force=False, debug_addrs=None):
        manager = VersionManager(results_info)
        debug_addrs = debug_addrs if debug_addrs else []
        for (libname, l) in manager.summary.libs.items():
            a = AddrCache(results_info, libname, l)
            a.create_cache(force, debug_addrs)
        return manager

    @classmethod
    def load_modules(cls, yarn_args, hashes=None, **kwargs):
        manager = cls(yarn_args.results_obj, hashes=hashes, **kwargs)
        parser_id = manager.get_parser_id()
        if parser_id is None:
            raise Exception("There are no known parser signature definitions "
                            "for these results")
        # load module defined for this parser id
        mod_path = "tracetools.signatures"
        try:
            mod = importlib.import_module(
                f"{mod_path}.{parser_id}"
            )
        except ModuleNotFoundError:
            raise Exception("No defined tracker for parser family: "
                            f"{parser_id}")
        sigeval_cls = importlib.import_module(f"{mod_path}.evaluator").SigEval
        tracker_cls = None

        # lookup tracker class (SigEval) defined in this parser's module
        for (name, c) in inspect.getmembers(mod):
            if inspect.isclass(c) and issubclass(c, sigeval_cls) and \
               inspect.getmodule(c) == mod:
                if tracker_cls is not None:
                    raise Exception("Multiple tracker (SigEval) classes in "
                                    f"module {mod.__file__}, don't know how "
                                    "to handle this issue. There should only "
                                    "be one per parser family definition: "
                                    f" {tracker_cls}, {c}")
                tracker_cls = c
        tracker_cls.setup()
        return (manager, tracker_cls)

    @classmethod
    def create_tracker(cls, yarn_args, unique_only: bool,
                       **kwargs):
        (manager, tracker_cls) = cls.load_modules(yarn_args,
                                                  from_cache=True)

        # TODO importing pt to set print_taint causes a circular import
        ml = manager.create_parselog(yarn_args, **kwargs)
        return tracker_cls(ml, unique_only, **kwargs)
