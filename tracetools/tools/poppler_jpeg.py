#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Narf Industries LLC
# This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) under Contract No. HR001119C0074.

import sys
from tracetools import yarn_args
from tracetools.signatures.versions import VersionManager
from tracetools.signatures.signatures import MomentSignature, SigID, \
        NewFrameMoment, ReturnSignature
from tracetools.signatures.ghoststack import StackOverlayEntry
from tracetools.signatures.evaluator import SigEval
from tracetools import log_entries
import intervaltree as it

output = sys.stdout


class PopplerMomentSignature(MomentSignature):
    lib_name = "libpoppler.so.94"


class JpxFrame(StackOverlayEntry):
    lib_name = "libpoppler.so.94"
    CINFO_SIZE = 656
    SRC_MGR_SIZE = 56
    ERROR_MGR_SIZE = 168

    def __init__(self, flagged_sig):
        sigs = [self.manager.sig_from_id(SigID.CALL_TRACE),
                self.manager.sig_from_id(SigID.CINFO_MEM,
                                         flagged_sig.cinfo_addr,
                                         self.CINFO_SIZE),
                self.manager.sig_from_id(SigID.SRC_MGR_MEM,
                                         flagged_sig.src_mgr_addr,
                                         self.SRC_MGR_SIZE),
                self.manager.sig_from_id(SigID.ERROR_MGR_MEM,
                                         flagged_sig.error_mgr_addr,
                                         self.ERROR_MGR_SIZE),
                self.manager.sig_from_id(SigID.TAINT_READ)]
        self.cinfo_addr = flagged_sig.cinfo_addr
        super(JpxFrame, self).__init__(flagged_sig,
                                       ghostsite_sigs=set(sigs),
                                       return_sig=SigID.CINFO_FINI)


class CinfoInit(NewFrameMoment):
    lib_name = "libpoppler.so.94"
    sig_id_name = "CINFO_INIT"
    flag_addr_name = "dct_init_cinfo"
    flag_addr_idx = 0
    remove_when_flagged = False
    attr_name = "pc"
    log_type = log_entries.MemEntry

    # CINFO_ERR_OFFSET = 0
    push_frame_class = JpxFrame
    # offset gathered manually using: `pahole  -C DCTStream libpoppler.so.94`
    # struct str_src_mgr         src;                  /*  1080    80 */
    # struct str_error_mgr       err;                  /*   704   376 */

    DCTSTREAM_SRC_MGR_OFFSET = 1080
    DCTSTREAM_ERROR_MGR_OFFSET = 704

    @classmethod
    def setup(cls):
        cls.src_mgr_read = cls.addrs_of("dct_src_mgr_addr")

    def reset(self):
        self.cinfo_addr = None
        self.dctstream_addr = None

    @property
    def src_mgr_addr(self):
        return self.dctstream_adddr + self.DCTSTREAM_SRC_MGR_OFFSET

    @property
    def error_mgr_addr(self):
        return self.dctstream_adddr + self.DCTSTREAM_ERROR_MGR_OFFSET

    def do_log_entry(self, log_entry):
        super(CinfoInit, self).do_log_entry(log_entry)
        if log_entry.pc in self.src_mgr_read:
            self.dctstream_adddr = log_entry.value

    def flag(self):
        self.cinfo_addr = self.flagged_entry.addr
        # seg = self.get_segment_at(self.cinfo_addr)


class CinfoFini(ReturnSignature, PopplerMomentSignature):
    sig_id_name = "CINFO_FINI"
    flag_addr_name = "dct_fini_cinfo"
    remove_when_flagged = True
    attr_name = "pc"
    log_type = log_entries.MemEntry
    parent_frame_class = JpxFrame

    # offset gathered manually using: `pahole  -C DCTStream libpoppler.so.94`
    # struct jpeg_decompress_struct cinfo;             /*    48   656 */
    DCTSTREAM_CINFO_OFFSET = 48

    @property
    def cinfo_addr(self):
        return self.flagged_entry.value + self.DCTSTREAM_CINFO_OFFSET

    def flag(self):
        if self.parent_frame.cinfo_addr != self.cinfo_addr:
            self.OOPS("cinfo address doesn't match parent frame",
                      self.parent_frame,
                      f"cinfo at {self.parent_frame.cinfo_addr:x}",
                      f"fini at {self.cinfo_addr}",
                      self, self.flagged_entry)


class MemInfoSig(PopplerMomentSignature):
    struct_def = []
    struct_name = "struct"

    @classmethod
    def _setup(cls):
        super(MemInfoSig, cls)._setup()
        cls.fields = it.IntervalTree([it.Interval(b, b + sz, n)
                                      for (n, b, sz) in cls.struct_def])

    def __init__(self, start_addr, size):
        super(MemInfoSig, self).__init__()
        self.start = start_addr
        self.end = start_addr + size
        # self.accesses = []

    def in_range(self, addr):
        return self.start <= addr and addr < self.end

    def field_at(self, addr):
        matches = self.fields.at(addr - self.start)
        return matches.pop().data if matches else None

    def _do_flag(self, log_entry):
        # self.accesses.append(log_entry)
        super(MemInfoSig, self)._do_flag(log_entry)
        seg = self.get_segment_at(self.flagged_entry.pc)
        virt = self.abs_to_virt(self.flagged_entry.pc, seg)
        addr = self.flagged_entry.addr
        global output
        if self.manager.last_stack:
            print(self.manager.last_stack, file=output)
            self.manager.last_stack = None
        print(f"{virt:x}@{seg.basename} {self.flagged_entry.typ_name}",
              self.struct_name, "VAL",
              f"[{self.flagged_entry.value_bytes.hex()}] "
              f"- {self.field_at(addr)}",
              file=output)

    def do_log_entry(self, log_entry):
        if log_entries.is_kind(log_entries.MemEntry, log_entry):
            if self.in_range(log_entry.addr):
                self.do_flag(log_entry)


class CinfoMem(MemInfoSig):
    sig_id_name = "CINFO_MEM"
    struct_name = "jpeg_decompress_struct"

    # jpeg_decompress_struct (field name, offset, size)
    # for now this is manually gathered using pahole
    struct_def = [
        ("struct jpeg_error_mgr * err", 0, 8),
        ("struct jpeg_memory_mgr * mem", 8, 8),
        ("struct jpeg_progress_mgr * progress", 16, 8),
        ("void * client_data", 24, 8),
        ("boolean is_decompressor", 32, 4),
        ("int global_state", 36, 4),
        ("struct jpeg_source_mgr * src", 40, 8),
        ("JDIMENSION image_width", 48, 4),
        ("JDIMENSION image_height", 52, 4),
        ("int num_components", 56, 4),
        ("J_COLOR_SPACE jpeg_color_space", 60, 4),
        ("J_COLOR_SPACE out_color_space", 64, 4),
        ("unsigned int scale_num", 68, 4),
        ("unsigned int scale_denom", 72, 4),
        ("double output_gamma", 80, 8),
        ("boolean buffered_image", 88, 4),
        ("boolean raw_data_out", 92, 4),
        ("J_DCT_METHOD dct_method", 96, 4),
        ("boolean do_fancy_upsampling", 100, 4),
        ("boolean do_block_smoothing", 104, 4),
        ("boolean quantize_colors", 108, 4),
        ("J_DITHER_MODE dither_mode", 112, 4),
        ("boolean two_pass_quantize", 116, 4),
        ("int desired_number_of_colors", 120, 4),
        ("boolean enable_1pass_quant", 124, 4),
        ("boolean enable_external_quant", 128, 4),
        ("boolean enable_2pass_quant", 132, 4),
        ("JDIMENSION output_width", 136, 4),
        ("JDIMENSION output_height", 140, 4),
        ("int out_color_components", 144, 4),
        ("int output_components", 148, 4),
        ("int rec_outbuf_height", 152, 4),
        ("int actual_number_of_colors", 156, 4),
        ("JSAMPARRAY colormap", 160, 8),
        ("JDIMENSION output_scanline", 168, 4),
        ("int input_scan_number", 172, 4),
        ("JDIMENSION input_iMCU_row", 176, 4),
        ("int output_scan_number", 180, 4),
        ("JDIMENSION output_iMCU_row", 184, 4),
        ("int * coef_bits", 192, 8),
        ("JQUANT_TBL * quant_tbl_ptrs[4]", 200, 32),
        ("JHUFF_TBL * dc_huff_tbl_ptrs[4]", 232, 32),
        ("JHUFF_TBL * ac_huff_tbl_ptrs[4]", 264, 32),
        ("int data_precision", 296, 4),
        ("jpeg_component_info * comp_info", 304, 8),
        ("boolean is_baseline", 312, 4),
        ("boolean progressive_mode", 316, 4),
        ("boolean arith_code", 320, 4),
        ("UINT8 arith_dc_L[16]", 324, 16),
        ("UINT8 arith_dc_U[16]", 340, 16),
        ("UINT8 arith_ac_K[16]", 356, 16),
        ("unsigned int restart_interval", 372, 4),
        ("boolean saw_JFIF_marker", 376, 4),
        ("UINT8 JFIF_major_version", 380, 1),
        ("UINT8 JFIF_minor_version", 381, 1),
        ("UINT8 density_unit", 382, 1),
        ("UINT16 X_density", 384, 2),
        ("UINT16 Y_density", 386, 2),
        ("boolean saw_Adobe_marker", 388, 4),
        ("UINT8 Adobe_transform", 392, 1),
        ("boolean CCIR601_sampling", 396, 4),
        ("jpeg_saved_marker_ptr marker_list", 400, 8),
        ("int max_h_samp_factor", 408, 4),
        ("int max_v_samp_factor", 412, 4),
        ("int min_DCT_h_scaled_size", 416, 4),
        ("int min_DCT_v_scaled_size", 420, 4),
        ("JDIMENSION total_iMCU_rows", 424, 4),
        ("JSAMPLE * sample_range_limit", 432, 8),
        ("int comps_in_scan", 440, 4),
        ("jpeg_component_info * cur_comp_info[4]", 448, 32),
        ("JDIMENSION MCUs_per_row", 480, 4),
        ("JDIMENSION MCU_rows_in_scan", 484, 4),
        ("int blocks_in_MCU", 488, 4),
        ("int MCU_membership[10]", 492, 40),
        ("int Ss", 532, 4),
        ("int Se", 536, 4),
        ("int Ah", 540, 4),
        ("int Al", 544, 4),
        ("int block_size", 548, 4),
        ("const int * natural_order", 552, 8),
        ("int lim_Se", 560, 4),
        ("int unread_marker", 564, 4),
        ("struct jpeg_decomp_master * master", 568, 8),
        ("struct jpeg_d_main_controller * main", 576, 8),
        ("struct jpeg_d_coef_controller * coef", 584, 8),
        ("struct jpeg_d_post_controller * post", 592, 8),
        ("struct jpeg_input_controller * inputctl", 600, 8),
        ("struct jpeg_marker_reader * marker", 608, 8),
        ("struct jpeg_entropy_decoder * entropy", 616, 8),
        ("struct jpeg_inverse_dct * idct", 624, 8),
        ("struct jpeg_upsampler * upsample", 632, 8),
        ("struct jpeg_color_deconverter * cconvert", 640, 8),
        ("struct jpeg_color_quantizer * cquantize", 648, 8),
    ]


class SrcMgrMem(MemInfoSig):
    sig_id_name = "SRC_MGR_MEM"

    # jpeg_source_mgr struct (field name, offset, size)
    # for now this is manually gathered using pahole
    struct_name = "jpeg_source_mgr"
    struct_def = [
        ("const JOCTET  * next_input_byte", 0, 8),
        ("size_t bytes_in_buffer", 8, 8),
        ("void (*init_source)(j_decompress_ptr)", 16, 8),
        ("boolean  (*fill_input_buffer)(j_decompress_ptr)", 24, 8),

        ("void  (*skip_input_data)(j_decompress_ptr, long int)", 32, 8),
        ("boolean (*resync_to_restart)(j_decompress_ptr, int)", 40, 8),
        ("void (*term_source)(j_decompress_ptr);", 48, 8)
    ]


class ErrorMgrMem(MemInfoSig):
    sig_id_name = "ERROR_MGR_MEM"

    # jpeg_source_mgr struct (field name, offset, size)
    # for now this is manually gathered using pahole
    struct_name = "jpeg_error_mgr"
    struct_def = [
        ("void (*error_exit)(j_common_ptr)", 0, 8),
        ("void (*emit_message)(j_common_ptr, int)", 8, 8),
        ("void (*output_message)(j_common_ptr)", 16, 8),
        ("void (*format_message)(j_common_ptr, char *)", 24, 8),
        ("void (*reset_error_mgr)(j_common_ptr)", 32, 8),
        ("int msg_code", 40, 4),
        ("{union {int, char}} msg_parm", 44, 80),
        ("int trace_level", 124, 4),
        ("long int num_warnings", 128, 8),
        ("const char  * const *  jpeg_message_table", 136, 8),
        ("int  last_jpeg_message", 144, 4),
        ("const char  * const * addon_message_table", 152, 8),
        ("int first_addon_message", 160, 4),
        ("int last_addon_message", 164, 4)
    ]


class JpegTracker(SigEval):
    # for now, manually calculated sizes/offsets

    def __init__(self, a):
        global output
        a.no_binja = True
        manager = VersionManager(a.results_obj, True)
        super(JpegTracker, self).__init__(manager.create_parselog(a))
        self.output = self.ml.print_out
        output = self.outut
        self.add_sig(self.sig_from_id(SigID.CINFO_INIT))
        self.last_stack = None
        self.last_taint_sig = None

    def callback_CALL_TRACE(self, signature):
        if self.last_taint_sig:
            offsets = self.last_taint_sig.get_taint()
            if offsets:
                if self.last_stack:
                    print(self.last_stack, file=self.output)
                    print("TAINT_READ input file offsets: ",
                          ", ".join([f"({i.begin}, {i.end})"
                                     for i in offsets]),
                          file=self.output)
            self.last_taint_sig.reset()
        self.last_stack = " > ".join([f"{c}@{c.target_virtpc:x}:" +
                                      c.target_seg.basename
                                      for c in self.ml.stack])

    def callback_TAINT_READ(self, signature):
        self.last_taint_sig = signature

    def close(self):
        self.ml.close()


def run(args=None):
    parser = yarn_args.YarnArgParser("get poppler jpeg parsing information",
                                     out=True)
    p = JpegTracker(parser.parse_args(args if args else sys.argv[1:]))
    p.run()
    p.close()


if __name__ == "__main__":
    if False:
        import cProfile
        cProfile.run("run()")
    else:
        run()
