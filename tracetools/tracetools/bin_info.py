# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.
import logging
import os
import binja_tags
import bin_info_common


try:
    import binaryninja as bn
except Exception as e:
    logging.error("Cannot import bin_info/binary ninja")
    logging.error(str(e))
    # import bin_info_no_binja as bin_info
    # if binja not installed, it may not matter
    logging.error("Note: binja is not supported by pypy3")
    raise e


class BinjaInfoException(Exception):
    pass


class BinaryInfo(bin_info_common.BinaryInfoCommon):
    bin_type = 'ELF'
    suffix = ".bndb"

    @classmethod
    def create_bndb(cls, binary, path):
        logging.info("Creating new bndb for %s at %s..." % (binary, path))
        bv = bn.BinaryViewType[cls.bin_type].open(binary)
        if not bv.create_database(path):
            raise BinjaInfoException("failed to create bndb from %s at %s" %
                                     (binary, path))
        bv.update_analysis_and_wait()
        logging.info("..done")
        bv.save_auto_snapshot()
        return bv

    @classmethod
    def open_or_create_bndb(cls, binary, bndb_path, update_analysis=False):
        exists = False
        s = bn.settings.Settings()
        auto = s.get_bool("analysis.linearSweep.autorun")
        sig = s.get_bool("analysis.signatureMatcher.autorun")
        mode = s.get_string("analysis.mode")
        # disable some analysis methods to speed up bndb opening
        s.set_string("analysis.mode", "intermediate")
        s.set_bool("analysis.linearSweep.autorun", False)
        s.set_bool("analysis.signatureMatcher.autorun", False)

        if os.path.exists(bndb_path):
            exists = True
            logging.info("Opening bndb at %s" % bndb_path)
            bv = bn.BinaryViewType.get_view_of_file(bndb_path)
            logging.info("...done opening")
        elif binary and os.path.exists(binary):
            bv = cls.create_bndb(binary, bndb_path)
        else:
            raise BinjaInfoException("neither bndb nor binary exists, "
                                     "cannot continue")
        if update_analysis:
            logging.info("Waiting for bndb analysis to complete")
            bv.update_analysis_and_wait()
            logging.info("...done")
            if not exists:
                bv.save_auto_snapshot()
        s.set_string("analysis.mode", mode)
        s.set_bool("analysis.linearSweep.autorun", auto)
        s.set_bool("analysis.signatureMatcher.autorun", sig)
        return bv

    def __init__(self, binary, bndb_path, src_dirs=[],
                 update_analysis=True, mmap_file=None,
                 bin_dir=None):
        # one of binary or bndb must exist.
        bv = self.open_or_create_bndb(binary, bndb_path,
                                      update_analysis)
        super(BinaryInfo, self).__init__(binary, bv, mmap_file, src_dirs,
                                         bin_dir)
        self.bndb_path = bndb_path
        self._binja_tags = {}
        self.binary = binary if binary else self.bv.file.original_filename
        self.binary_name = os.path.basename(self.binary)

    def get_binary_view_basename(self, f):
        return os.path.basename(f.file.original_filename)

    def get_fn_addrs_from_name(self, name, find_all=False):
        return self._get_fn_addrs_from_name(name,
                                            bn.enums.SymbolType.FunctionSymbol,
                                            find_all)

    def get_fn_info_from_name(self, name, anytype=False, lib=None):
        return self._get_fn_info_from_name(name,
                                           bn.enums.SymbolType.FunctionSymbol,
                                           anytype, lib)

    def get_binja_tags_at(self, addr, seg=None):
        if not seg:
            seg = self.get_segment_at(addr)
        if seg:
            virtaddr = self._abs_to_virt(addr, seg)
            ts = self._get_binja_tags(seg.basename)
            if not ts:
                return None
            return ts.tags_by_addr(virtaddr)
        else:
            return binja_tags.BinjaTagEntry(addr, [])

    def has_binja(self, segment):
        base = segment.basename
        return True if self._get_binja_tags(base) else False

    def _get_binja_tags(self, which):
        tags = self._binja_tags.get(which, None)
        if tags:
            return tags
        else:
            bv = self.all_bvs.get(which, None)
            if not bv:
                return None
            self._binja_tags[which] = binja_tags.BinjaTagCache(bv)
            return self._binja_tags[which]

    def add_library_bv(self, path, db_path, notrack=False):
        def cb():
            return self.open_or_create_bndb(path, db_path)
        self._add_library_bv(path, db_path, cb, notrack)

    # sadly binaryninja does not seem to provide this info
    def lookup_data_type(self, virtaddr):
        return ("", 0, 0)

    # def lookup_data_type(self, virtaddr):
    #     # sadly we need to use debugging symbols to get this
    #     # I cannot find data in binaryninja
    #     s = self.bv.get_symbols(virtaddr, 1)
    #     if not len(s) == 1:
    #         return ""
    #     s = s[0]
    #     name = s.name
    #     e = elftools.elf.elffile.ELFFile(open(self.binary, 'rb'))
    #     di = e.get_dwarf_info()

    #     def get_var_die(die):
    #         n_attr = "DW_AT_name"
    #         if die.tag == 'DW_TAG_variable' and \
    #            n_attr in die.attributes and \
    #            die.attributes[n_attr] == name:
    #             return die
    #         for c in die.iter_children():
    #             get_var_die(c)
    #     def get_type_die(die):
    #         n_attr = "DW_AT_name"
    #         if die.tag == 'DW_TAG_type' and \
    #            n_attr in die.attributes and \
    #            die.attributes[n_attr] == name:
    #             return die
    #         for c in die.iter_children():
    #             get_var_die(c)

    #     topD = None
    #     for CU in di.iter_CUs():
    #         topD = CU.get_top_DIE()
    #         v = get_var_die(topD)
    #         if v:
    #             break
    #     if v and topD:
    #     return s.type

    def addr_to_fn(self, ip, segment, exact=False):
        virtip = self._abs_to_virt(ip, segment)
        bv = None
        f = []
        if segment:
            bv = self.all_bvs.get(segment.basename, None)
            if bv:
                if exact:
                    f = [bv.get_function_at(virtip)]
                else:
                    f = bv.get_functions_containing(virtip)
        return f[0] if f else None


if __name__ == "__main__":
    # some quick manual tests
    f = '/bin/ls'
    db = "~/code/pdftotext_ELF_bb_tagged.bndb"
    out2 = 'o.bndb'
    out = 'out.bndb'
    b = BinaryInfo(f, out2)
