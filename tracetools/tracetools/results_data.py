# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import dataclasses
from typing import Dict, List, ClassVar
import os
import dbm
import shelve
import glob
import logging
import json


__version__ = "0.1"


class ResultsException(Exception):
    pass


class DataShelf():
    _PATH: ClassVar[str] = ""
    _DIR_PREFIX: ClassVar[str] = ""
    _DATA_DIR: ClassVar[str] = "data"
    _VERSION_KEY: ClassVar[str] = "version"
    # _shelf: dataclasses.InitVar[dict] = None
    _dir: dataclasses.InitVar[str] = None
    _NEW_PATH: ClassVar[str] = "info.out"
    # _changed: bool = True

    @classmethod
    def field_names(cls) -> List[str]:
        return [f.name for f in dataclasses.fields(cls)
                if not f.name.startswith("_")]

    @classmethod
    def INFO(cls):
        return cls._NEW_PATH

    @classmethod
    def db_path(cls, dir_path: str, new: bool = True) -> str:
        return os.path.realpath(
            os.path.join(dir_path, cls._NEW_PATH if new else cls._PATH)
        )

    @classmethod
    def has_old_db(cls, path: str) -> bool:
        try:
            cls._read_db_old(path)
            return True
        except dbm.error:
            return False

    @classmethod
    def convert_db(cls, db_dir: str, old_db: str, new_db: str):
        logging.warning("Converting from old db in %s to new version in %s",
                        old_db, new_db)
        old = cls._read_db_old(old_db)
        if not old:
            return False
        old.version = __version__
        old._dir = db_dir
        old.save()  # saves new version of db from instance
        return True

    @classmethod
    def _read_db_new(cls, db_path: str) -> dict:
        if not os.path.exists(db_path):
            return None
        with open(db_path, "r") as f:
            c = cls.from_dict(json.load(f))
        return c

    @classmethod
    def _read_db_old(cls, db_path: str) -> dict:
        s = shelve.open(db_path, flag="r")
        contents = dict(s)
        s.close()
        return cls.from_dict(contents)

    @classmethod
    def _read_db(cls, db_dir: str):
        db_path = cls.db_path(db_dir)
        old_db = cls.db_path(db_dir, new=False)
        if not os.path.exists(db_path):
            if cls.has_old_db(old_db):
                ok = cls.convert_db(db_dir, old_db, db_path)
                if not ok:
                    return None
            else:
                logging.error(f"Missing db info for {cls.__name__} at {db_dir}")
                return None
        return cls._read_db_new(db_path)

    @classmethod
    def from_db(cls, db_dir: str, db_contents: dict = None):
        db_dir = os.path.realpath(db_dir)
        c = cls.from_dict(db_contents) if db_contents \
            else cls._read_db(db_dir)
        if c is None:
            # if from_dict is None:
            return None
        c._dir = db_dir
        return c

    @classmethod
    def from_dict(cls, d: dict):
        fields = {f: d.get(f) for f in cls.field_names() if f in d}
        if "version" not in fields:
            fields["version"] = __version__
        return cls(**fields)

    @classmethod
    def iter_paths(cls, path: str):
        for db_dir in glob.glob(os.path.join(path, cls._DIR_PREFIX + "*")):
            yield db_dir

    @classmethod
    def iter_from(cls, path: str):
        for db_dir in cls.iter_paths(path):
            c = cls.from_db(db_dir)
            if c:
                yield c

    @property
    def data_dir(self) -> str:
        p = self._dir if self._dir else ""
        return os.path.join(p, self._DATA_DIR)

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.field_names()}

    def save(self):
        with open(self.db_path(self._dir), "w") as f:
            json.dump(self.to_dict(), f)


@dataclasses.dataclass
class ResultData(DataShelf):
    cmd: str
    input: str
    orig_pdf_path: str
    mmap_log: str
    runtime: float
    test_cmd_line: str
    timed_out: bool
    capture_date: str
    compressed: bool
    exit_value: int
    trace_log: List[str] = dataclasses.field(default_factory=list)
    write_log: List[str] = dataclasses.field(default_factory=list)
    environ: Dict[str, str] = dataclasses.field(default_factory=dict)
    version: str = __version__
    pruned: bool = False
    _PATH: ClassVar[str] = "resultinfo.db"
    _DIR_PREFIX: ClassVar[str] = "res_"

    def __post_init__(self, **kwargs):
        if self.trace_log is None:
            self.trace_log = []
        if self.write_log is None:
            self.write_log = []

    @property
    def result_id(self) -> str:
        return os.path.basename(self._dir)[len(self._DIR_PREFIX):]

    def bin_info(self):
        dirname = os.path.dirname(self._dir)
        res_id = self.result_id
        bi = BinInfo.from_db(dirname)
        if not bi:
            # then we might be using a symbolic link,
            # look up which bins/parsers holds this result
            for b in BinInfo._iter_parsers(dirname):
                if res_id in [r.result_id for r in b.results]:
                    bi = b
                    break
            return None

        missing = [b for b in bi.bins
                   if not os.path.exists(os.path.join(bi.data_dir,
                                                      os.path.basename(b)))]
        to_restore = [b for b in missing if os.path.exists(b)]
        if missing:
            if to_restore:
                logging.warning("Restoring binaries missing from data "
                                "directory: %s", to_restore)
                for b in to_restore:
                    bi.do_save_bin(b)
            not_restored = [b for b in missing if b not in to_restore]
            if not_restored:
                logging.error("Uable to locate and restore binaries missing "
                              "from data directory: {not_restored}")
                bi.bins = [b for b in bi.bins if b not in not_restored]
        return bi


@dataclasses.dataclass
class BinInfo(DataShelf):
    name: str
    orig_path: str
    sha512sum: str
    bins: List[str]
    version: str = __version__
    _PATH: str = "bininfo.db"
    _DIR_PREFIX: str = "bins_"
    _res_dirname: dataclasses.InitVar[str] = ""
    _ORDER: ClassVar[dict] = ["version", "orig_path", "sha512sum"]

    def __post_init__(self, *args, **kwargs):
        self.bins = list(set(self.bins))

    def save(self):
        with open(self.db_path(self._dir), "w") as f:
            for v in [getattr(self, k) for k in self._ORDER] + self.bins:
                f.write(f"{v}\n")

    @classmethod
    def _read_db_new(cls, db_path: str) -> dict:
        with open(db_path, "r") as f:
            bins = [b.strip() for b in f.read().split("\n") if b.strip()]
        db_dict = {k: bins.pop(0) for k in cls._ORDER}
        db_dict["bins"] = bins + [db_dict["orig_path"]]
        db_dict["name"] = cls.name_from_dict(db_dict)
        return cls.from_dict(db_dict)

    @classmethod
    def name_from_dict(cls, db_dict: dict) -> str:
        return os.path.basename(db_dict["orig_path"])

    @classmethod
    def from_db(cls, db_dir: str, db_dict: dict = None):
        if db_dict and "name" not in db_dict:
            db_dict["name"] = cls.name_from_dict(db_dict)
        return super(BinInfo, cls).from_db(db_dir, db_dict)

    @property
    def result_root_dir(self) -> str:
        return os.path.dirname(self._dir)

    def results(self):
        return ResultData.iter_from(self._dir)

    def add_binaries_to_db(self, bins):
        self.bins += bins
        for b in bins:
            self.do_save_bin(b)
            os.system(f"echo {b} >> {self.db_path(self._dir)}")

    def do_save_bin(self, bin_path: str):
        # save version with debug symbols, if present (only tested
        # on ubuntu), otherwise save stripped version of binary
        i = bin_path
        dirname = self.data_dir
        if not os.path.exists(dirname):
            os.mkdir(dirname)
        path = os.path.join(dirname, os.path.basename(i))
        ret = os.system(f"eu-unstrip -e {i} -o {path} 2>/dev/null")
        if ret != 0:
            os.system(f"cp {i} {path}")

    def add_bins(self, bins: List[str]):
        # only try to add bins not in current_bins
        current_bins = self.bins
        not_added_bins = list(set([b for b in bins if b not in current_bins]))
        # assume no dupes currently
        checked = [(os.path.basename(b), b) for b in current_bins]
        dupes = []
        to_add = []
        # check if two libraries loaded from different locations
        # have the name basename
        for binary in not_added_bins:
            bn = os.path.basename(binary)
            matches = [(binary, path) for (base, path) in checked
                       if bn == base and path != binary]
            dupes += matches
            if not matches:
                to_add.append(binary)
            checked.append((bn, binary))
        if dupes:
            raise ResultsException("More than one library with the same name"
                                   "was loaded from different paths, we don't"
                                   f"know how to handle this: {dupes}")
        if current_bins and to_add:
            logging.warning(f"Adding newly found binaries to cache: {to_add}")
        # update parser info if there are new bins
        if to_add:
            self.add_binaries_to_db(to_add)
