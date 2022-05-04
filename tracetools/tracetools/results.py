# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import os
import sys
import uuid
import datetime
import bz2
import glob
# import atexit
import hashlib
import subprocess
from typing import List
from mmap_info import MmapInfo
import logging
from tracetools.results_data import ResultData, BinInfo, ResultsException


class ResultsInfo():
    def __init__(self, test_dir: str):
        test_dir = os.path.realpath(test_dir)
        self.result_info = ResultData.from_db(test_dir)
        if not self.result_info:
            raise ResultsException(f"Result info not found in {test_dir}")
        bin_info = self.result_info.bin_info()
        if not bin_info:
            raise ResultsException(f"No valid results dir found at {test_dir}")
        results_root = bin_info.result_root_dir
        self.r = Results(results_root)
        self.r.init(bin_info)
        self.mmap = os.path.join(self.result_dir, self.result_info.mmap_log) \
            if self.result_info.mmap_log else None

        self.tracelogs = [os.path.join(self.result_dir, t)
                          for t in self.result_info.trace_log]
        self.tracelogs.sort()
        if self.result_info.compressed:
            self.logs = [bz2.open(log, 'rb')
                         for log in self.tracelogs]
        else:
            self.logs = [open(log, 'rb')
                         for log in self.tracelogs]
        self.writelog_paths = [os.path.join(self.result_dir, t)
                               for t in self.result_info.write_log]
        self.writelogs = []
        for log in self.tracelogs:
            suffix = os.path.basename(log).split(".", 1)[-1]
            wl = os.path.join(os.path.dirname(log),
                              "write." + suffix)
            # build writelogs list in same order as tracelogs
            # set as none if tracelog thread has no corresponding
            # writelog
            if wl in self.writelog_paths:
                self.writelogs.append(wl)
            else:
                self.writelogs.append(None)

    @property
    def parser_bins_dir(self):
        return self.r.parser_bins_dir

    @property
    def num_threads(self) -> int:
        return len(self.logs)

    def import_file(self, path: str, clobber: bool = False,
                    file_contents: str = None,
                    dest_name: str = None) -> str:
        res_dir_path = self.result_dir
        basename = dest_name if dest_name else os.path.basename(path)
        dest_path = os.path.join(res_dir_path, basename)
        if not clobber and os.path.isfile(dest_path):
            raise Exception(f"file already exists at {dest_path}, "
                            "not overwriting")
        if file_contents is None:
            os.system(f"cp {path} {dest_path}")
        else:
            with open(dest_path, "w") as f:
                f.write(file_contents)
        return dest_path

    @property
    def result_dir(self) -> str:
        return self.result_info._dir

    @property
    def parser_bin(self):
        return self.r.parser_bin

    def get_results_file_path(self, name: str):
        path = os.path.join(self.result_dir, name)
        return path if os.path.exists(path) else None

    def get_lib_path(self, which: str) -> str:
        return self.r.lib_path(which)

    @property
    def exit_value(self) -> int:
        return self.result_info.exit_value if self.result_info else None

    def __repr__(self):
        return "[%s]" % self.result_dir

    def get_bin_metadata_path(self, which=None, suffix=".bndb"):
        which = os.path.basename(which if which else self.parser_name)
        return self.r.lookup_bin_metadata(which, suffix)

    def tag(self, name: str) -> bool:
        path = self.result_dir
        basename = os.path.basename(path)
        dirname = self.r.results_root
        curdir = os.getcwd()
        os.chdir(dirname)
        if os.path.exists(name):
            logging.error(f"Error: tag {name} already exists in {dirname}")
            ok = False
        else:
            os.symlink(basename, name)
            ok = True
        os.chdir(curdir)
        return ok


class Results():
    # bin_info_file = "info.db"
    TRACELOG_NAME = 'memcalltrace.'
    FILEWRITE_NAME = 'write.'
    ENABLE_FN_ENVIRON = "NOMAD_META_MR_MT_ENABLE_LOG"
    DISABLE_FN_ENVIRON = "NOMAD_META_MR_MT_DISABLE_LOG"
    ERROR_OFFSET_ENVIRON = "NOMAD_META_MR_MT_DOC_OFFSET_ERR"
    DOC_PATH_ENVIRON = "NOMAD_META_MR_MT_DOC_PATH"
    # comma separated list of libname,# virtual addresses
    PRUNE_LIST_LIBS_ENVIRON = "NOMAD_META_MR_MT_PRUNE_LIST_LIBS"  # libnames
    # sorted list of comma-separated virtual addrs per library, followed by
    # next library's list (in same library order as LIST_LIBS)
    PRUNE_LIST_ENVIRON = "NOMAD_META_MR_MT_PRUNE_LIST"
    PRUNE_LIBC_ENVIRON = "NOMAD_META_MR_MT_LIBC_NAME"

    def __init__(self, results_dir: str):
        self.results_root = results_dir
        self.parser_info = None

    def init(self, bin_info: BinInfo = None, bin_info_is_dir:bool = False):
        if not bin_info:
            for p in self.iter_parsers():
                self.parser_info = p
                return
        else:
            if bin_info_is_dir:
                bin_info = BinInfo.from_db(bin_info)
            self.parser_info = bin_info

    @classmethod
    def sha512sum(cls, path: str) -> str:
        with open(path, "rb") as f:
            dgst = hashlib.sha512(f.read())
        return dgst.hexdigest()

    @classmethod
    def _iter_parsers(self, root_dir: str):
        return BinInfo.iter_from(root_dir)

    def iter_parsers(self):
        return self._iter_parsers(self.results_root)

    def lookup_parser(self, parser: str):
        digest = self.sha512sum(parser)
        for binfo in self.iter_parsers():
            if binfo.sha512sum == digest and \
               os.path.exists(binfo.data_dir):
                return binfo

    def init_parser(self, parser: str):
        self.parser_info = self.lookup_parser(parser)
        # if initial runs of parser were cancelled,
        # parser_info may exist but there will not be
        # any data saved to the data/ dir (bins_saved)
        if not self.parser_info or \
           not os.path.exists(self.parser_info.data_dir):
            bins_dir = "bins_" + self._gen_bins_id()
            dirname = os.path.join(self.results_root,
                                   bins_dir)
            os.mkdir(dirname)
            self.parser_info = BinInfo.from_db(
                dirname,
                {
                    'orig_path': parser,
                    'bins': [],
                    'sha512sum': self.sha512sum(parser)
                },
            )
            self.parser_info.save()

    def any_result(self):
        for r in self.iter_results(iter_all=False):
            return ResultsInfo(r._dir)

    def get_all_results(self):
        return self.iter_results()

    def iter_results(self, iter_all: bool = True):
        if not iter_all:
            for res in ResultData.iter_from(self.parser_info._dir):
                if res:
                    yield res
        else:
            for binfo in self.iter_parsers():
                for res in binfo.results():
                    if res:
                        yield res

    def lib_path(self, which: str) -> str:
        return os.path.join(self.parser_bins_dir, which)

    @classmethod
    def _is_file_tracelog(cls, f: str) -> bool:
        return os.path.basename(f).startswith(cls.TRACELOG_NAME)

    @classmethod
    def _is_file_writelog(cls, f: str) -> bool:
        return os.path.basename(f).startswith(cls.FILEWRITE_NAME)

    @classmethod
    def _is_file_mmap(cls, f: str) -> bool:
        return os.path.basename(f).startswith('mmap')

    @property
    def parser_bin(self) -> str:
        return self.lib_path(self.parser_name)

    def _lookup_libs(self, mmap_file: str):
        if mmap_file:
            # if we have mmap_file info, lookup paths from there
            # as they are more accurate than calling ldd
            mi = MmapInfo(mmap_file, self.parser_bin)
            regions = mi.parse_file(None)
            paths = set()
            [paths.add(r.data.path) for r in regions
             if os.path.exists(r.data.path)]
            return list(paths)
        parser_path = self.parser_info.orig_path
        cmd = f"ldd {parser_path}"
        child = subprocess.Popen(cmd.split(),
                                 stdout=subprocess.PIPE)
        out, err = child.communicate()
        if not isinstance(out, str):
            out = out.decode()
        res = [parser_path]
        arrow = " => "
        for line in out.split("\n"):
            line = line.strip()
            if arrow in line:
                lib = line.split(" => ", 1)[1].rsplit(None, 1)[0].strip()
                res.append(lib)
            elif line:
                lib = line.rsplit(None, 1)
                if os.path.exists(lib[0]):
                    res.append(lib[0])

        return [os.path.realpath(lib) for lib in res]

    def _save_bins(self, mmap_file: str) -> List[str]:
        bs = self._lookup_libs(mmap_file)
        self.parser_info.add_bins(bs)

    def save_bin_metadata(self, path: str, which: str = None,
                          manual: bool = False,
                          suffix: str = ".bndb"):
        which = os.path.basename(which if which else self.parser_name)
        bins_dir = self.parser_bins_dir
        if not os.path.exists(os.path.join(bins_dir, which)):
            raise ResultsException(f"No binary named '{which}' found in "
                                   f"results bins directory ({bins_dir})")
        to_name = f"{which}{suffix}"
        to_path = f"{bins_dir}/{to_name}"
        cmd = f"cp {path} {bins_dir}/{to_name}"
        if os.path.isfile(to_path) and manual:
            logging.error(f"metadata file at {to_path} already exists",
                          "not overwriting. If you would like to override",
                          f"this, you should manually copy it via: {cmd}")
        else:
            os.system(cmd)

    @property
    def parser_name(self) -> str:
        return self.parser_info.name

    @property
    def parser_bins_dir(self) -> str:
        return self.parser_info.data_dir

    def lookup_bin_metadata(self, which: str = None,
                            suffix: str = ".bndb") -> str:
        which = which if which else self.parser_name
        return os.path.join(self.parser_bins_dir,
                            which + suffix)

    def _gen_bins_id(self) -> str:
        bins_id = uuid.uuid4().hex
        if BinInfo._DIR_PREFIX + bins_id in \
           [os.path.basename(r._dir) for r in self.iter_parsers()]:
            return self._gen_bins_id()
        return bins_id

    def gen_result_dir(self, mkdir: bool = True) -> str:
        path = os.path.join(self.parser_info._dir,
                            ResultData._DIR_PREFIX + self.gen_test_id())
        if mkdir:
            os.mkdir(path)
        return path

    def res_id_from_res_dir(self, res_dir: str) -> str:
        return os.path.basename(res_dir).split(ResultData._DIR_PREFIX)[-1]

    def gen_test_id(self) -> str:
        test_id = uuid.uuid4().hex
        if ResultData._DIR_PREFIX + test_id in \
           [os.path.basename(r._dir) for r in self.iter_results()]:
            return self.gen_test_id()
        return test_id

    def update_from_run(self, test_dir, pdf, cmd, t, compress,
                        exit_value, environ=None, copy=None):
        results = glob.glob(f"{test_dir}/*.log")
        environ = environ if environ else {}
        copy = copy if copy else []
        # if not self.bins_saved:
        mmap_file = None
        mmap_file_ctime = None
        for r in results:
            if self._is_file_mmap(r):
                # if there is more than 1 mmap file, choose the
                # one that was most recently created. Hopefully
                # this will capture all the mmap info we need
                ctime = os.path.getctime(r)
                if mmap_file is None or ctime > mmap_file_ctime:
                    mmap_file = r
                    mmap_file_ctime = ctime
        self._save_bins(mmap_file)

        results_dir = self.parser_info._dir
        j_res = {}
        j_res['cmd'] = cmd
        j_res['compressed'] = compress
        j_res['runtime'] = t
        j_res['test_cmd_line'] = " ".join(sys.argv)
        j_res['capture_date'] = str(datetime.datetime.now())
        j_res['exit_value'] = exit_value
        if exit_value is None:
            j_res['timed_out'] = True
        else:
            j_res['timed_out'] = False
        testid = self.res_id_from_res_dir(test_dir)
        j_res['id'] = testid
        dirname = testid
        # j_res['results_dir'] = dirname
        j_res['orig_pdf_path'] = pdf
        j_res['environ'] = environ
        j_res['pruned'] = self.PRUNE_LIST_ENVIRON in environ
        res_path = os.path.join(results_dir, ResultData._DIR_PREFIX + dirname)
        if not os.path.exists(res_path):
            os.mkdir(res_path)
        for copy_file in copy:
            os.system(f"cp {copy_file} {res_path}")
        os.system(f"cp {pdf} {res_path}")
        j_res['input'] = os.path.basename(pdf)
        has_memtrace_log = False
        has_write_log = False
        error_printed = False
        mmap_file_ctime = None
        for r in results:
            if compress and self._is_file_tracelog(r):
                os.system(f"bzip2 {r}")
                r += ".bz2"
            if os.path.dirname(os.path.realpath(r)) != \
               os.path.realpath(res_path):
                os.system(f"mv {r} {res_path}")
            bn = os.path.basename(r)
            if self._is_file_tracelog(r):
                if has_memtrace_log:
                    if not error_printed:
                        error_printed = True
                        logging.warning("traced application is multithreaded")
                    j_res['trace_log'].append(bn)
                else:
                    j_res['trace_log'] = [bn]
                    has_memtrace_log = True
            elif self._is_file_mmap(r):
                # if there is more than 1 mmap file, choose the
                # one that was most recently created. Hopefully
                # this will capture all the mmap info we need
                ctime = os.path.getctime(r)
                if mmap_file_ctime is None or ctime > mmap_file_ctime:
                    mmap_file_ctime = ctime
                    j_res['mmap_log'] = bn
            elif self._is_file_writelog(r):
                if has_write_log:
                    j_res["write_log"].append(r)
                else:
                    has_write_log = True
                    j_res["write_log"] = [r]
        if "mmap_log" not in j_res:
            raise ResultsException("Something went wrong and no mmap log "
                                   "exists. Did memory tracker log ever get "
                                   "enabled/populated?")
        r = ResultData.from_db(res_path, j_res)
        r.save()
        link_path = os.path.join(r._dir, os.path.basename(self.results_root))
        if os.path.exists(link_path):
            os.system(f"rm {link_path}")
        curdir = os.getcwd()
        os.chdir(self.results_root)
        os.system(f"ln -s {os.path.relpath(r._dir)}")
        os.chdir(curdir)
        return ResultsInfo(res_path)
