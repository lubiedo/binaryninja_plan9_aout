from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag
from binaryninja.enums import SectionSemantics
from binaryninja.enums import SymbolType
from binaryninja.log import log_error
from binaryninja.log import log_info
from binaryninja.types import Symbol

import struct
import traceback

class aoutView(BinaryView):
    name = "aout"
    long_name = "9 a.out"

    do_magic   = lambda f,b : struct.pack('>l', ((f)|((((4*(b))+0)*(b))+7)))
    HDR_MAGIC  = 0x00008000
    MAGIC_DICT = {
        do_magic(0,8): "68020",             # retired
        do_magic(0,11): "x86",
        do_magic(0,12): "intel 960",        # retired
        do_magic(0,13): "sparc",
        do_magic(0,16): "mips 3000 BE",
        do_magic(0,17): "att dsp 3210",     # retired
        do_magic(0,18): "mips 4000 BE",
        do_magic(0,19): "amd 29000",        # retired
        do_magic(0,20): "armv7",
        do_magic(0,21): "ppc",
        do_magic(0,22): "mips 4000 LE",
        do_magic(0,23): "dec alpha",        # retired
        do_magic(0,24): "mips 3000 LE",
        do_magic(0,25): "sparc64",          # retired
        do_magic(HDR_MAGIC,26): "x86_64",
        do_magic(HDR_MAGIC,27): "ppc64",
        do_magic(HDR_MAGIC,28): "aarch64",
    }

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata = data.file, parent_view = data)
        self.raw = data

    def check_magic(self, magic_bytes):
        try:
            return self.MAGIC_DICT[magic_bytes]
        except:
            return False

    @classmethod
    def is_valid_for_data(self, data):
        hdr = data.read(0, 0x4)
        if (self.check_magic(self, hdr) != False):
            return True
        return False

    def init_common(self):
        self.hdr_offset = 0x20

        self.hdr = self.raw.read(0, self.hdr_offset)
        self.architecture = self.check_magic(self.hdr[0x0:0x4])
        if (self.architecture != False):
            self.platform = Architecture[self.architecture].standalone_platform
        else:
            log_info("Not a valid a.out file!")
            return False

        self.base_addr = 0x1000
        if self.architecture == "x86_64": # 6l
            self.base_addr = 0x200000
            self.hdr_offset += 0x08

        self.load_addr = self.hdr_offset

        # typedef struct Exec {
        #          long       magic;      /* magic number */                    0x00-0x04
        #          long       text;       /* size of text segment */            0x04-0x08
        #          long       data;       /* size of initialized data */        0x08-0x0C
        #          long       bss;        /* size of uninitialized data */      0x0C-0x10
        #          long       syms;       /* size of symbol table */            0x10-0x14
        #          long       entry;      /* entry point */                     0x14-0x18
        #          long       spsz;       /* size of pc/sp offset table */      0x18-0x1C
        #          long       pcsz;       /* size of pc/line number table */    0x1C-0x20
        # } Exec;
        self.size = struct.unpack(">L", self.hdr[0x04:0x08])[0]
        self.data_size = struct.unpack(">L", self.hdr[0x08:0xC])[0]
        self.bss_size = struct.unpack(">L", self.hdr[0xC:0x10])[0]
        self.syms_size = struct.unpack(">L", self.hdr[0x10:0x14])[0]
        self.entry_addr = struct.unpack(">L", self.hdr[0x14:0x18])[0]
        self.pcsp_offset = struct.unpack(">L", self.hdr[0x18:0x1C])[0]
        self.pcline_offset = struct.unpack(">L", self.hdr[0x1C:0x20])[0]

    def init(self):
        try:
            if self.init_common() == False:
                return

            offset = self.load_addr
            voff   = offset + self.base_addr

            self.add_user_section(".text", voff, self.size,
                SectionSemantics.ReadOnlyCodeSectionSemantics)
            self.add_auto_segment(
                voff,
                self.size,
                offset,
                self.size,
                SegmentFlag.SegmentContainsCode |
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
            )
            offset += self.size
            voff   += self.size

            '''
            When a Plan 9 binary file is executed, a memory image of
            three segments is set up: the text segment, the data seg-
            ment, and the stack.  The text segment begins at a virtual
            address which is a multiple of the machine-dependent page
            size.  The text segment consists of the header and the first
            text bytes of the binary file.  The entry field gives the
            virtual address of the entry point of the program.  The data
            segment starts at the first page-rounded virtual address
            after the text segment.  It consists of the next data bytes
            of the binary file, followed by bss bytes initialized to
            zero.  The stack occupies the highest possible locations in
            the core image, automatically growing downwards.  The bss
            segment may be extended by brk(2).
            '''

            voff = self.round(voff)
            self.add_user_section(".data", voff, self.data_size,
                SectionSemantics.ReadWriteDataSectionSemantics)

            self.add_auto_segment(
                voff,
                self.data_size,
                offset,
                self.data_size,
                SegmentFlag.SegmentContainsData |
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
            )

            offset += self.data_size
            voff   += self.data_size

            self.add_user_section(".bss", voff, self.bss_size,
                SectionSemantics.ReadWriteDataSectionSemantics)

            voff   += self.bss_size
            if self.syms_size > 0:                                              # check that binary wasn't strip(1)
                self.add_user_section(".syms", voff,
                    self.syms_size, SectionSemantics.ReadOnlyDataSectionSemantics)
                self.add_auto_segment(
                    voff,
                    self.syms_size,
                    offset,
                    self.syms_size,
                    SegmentFlag.SegmentContainsData |
                    SegmentFlag.SegmentReadable
                )
                # process and rename funcs using symbol table
                syms_table = self.raw.read(offset, offset + self.syms_size)
                self.process_symtable(syms_table)

                offset += self.syms_size
                voff   += self.syms_size

            if (self.architecture != False):
                self.add_entry_point(self.entry_addr)
            else:
                log_info("Not a valid a.out file!")
                return False
            return True
        except:
            log_error(traceback.format_exc())
            return False

    # structs based on:
    # https://github.com/0intro/plan9/blob/master/sys/src/libmach/sym.c#L404
    def process_symtable(self, table):
        pos = 0
        while pos + 6 < len(table):
            name = ""
            (value, type) = struct.unpack(">Lc", table[pos:pos+5])
            type = chr(type[0] ^ 0x80)
            pos += 4
            if type == 'z':
                #n = 0                                                          # NOT USED: size of name to malloc()
                pos += 2                                                        # advance to beginning of hist
                while table[pos:pos+2] != b'\x00\x00':
                    #n += 2
                    pos += 2                                                    # next 2-bytes block
                pos += 2                                                        # skip double nil
            else:
                while pos < len(table):
                    pos += 1
                    if chr(table[pos]) == "\x00":
                        pos += 1
                        break
                    name += chr(table[pos])

            #log_info('%08x\t%c\t%s' % (value,type,name))
            if type == 'T' or type == 't' or type == 'L' or type == 'l':
                self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol,
                    value, name))

    def round(self, addr):
        return self.base_addr + (self.base_addr * (addr // self.base_addr))

    def perform_get_start(self):
        return 0
    def perform_is_executable(self):
        return True
    def perform_get_entry_point(self):
        return self.entry_addr
