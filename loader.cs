using Reko.Core;
using System;
using System.Collections.Generic;
using System.IO;

namespace Nucleus
{
    public class Symbol
    {
        public enum SymbolType
        {
            SYM_TYPE_UKN = 0x000,
            SYM_TYPE_FUNC = 0x001
        };

        public Symbol() { type = SymbolType.SYM_TYPE_UKN; name = null; addr = 0; }

        public SymbolType type;
        public string name;
        public ulong addr;
    };

    public enum SectionType
    {
        NONE = 0,
        CODE = 1,
        DATA = 2
    }

    public partial class Section
    {
        public Section() { binary = null; type = 0; vma = 0; size = 0; bytes = null; }

        public bool contains(ulong addr) { return (addr >= vma) && (addr - vma < size); }
        public bool is_import_table() { return name == ".plt"; }

        public Binary binary;
        public string name;
        public SectionType type;
        public ulong vma;
        public ulong size;
        public byte[] bytes;
    };

    public class Binary
    {
        public
          enum BinaryType
        {
            BIN_TYPE_AUTO = 0,
            BIN_TYPE_RAW = 1,
            BIN_TYPE_ELF = 2,
            BIN_TYPE_PE = 3
        };
        public enum BinaryArch
        {
            ARCH_NONE = 0,
            ARCH_AARCH64 = 1,
            ARCH_ARM = 2,
            ARCH_MIPS = 3,
            ARCH_PPC = 4,
            ARCH_X86 = 5
        };

        public Binary() { type = (0); arch = (0); bits = (0); entry = (0); }

        public string filename;
        public BinaryType type;
        public string type_str;
        public BinaryArch arch;
        public IProcessorArchitecture reko_arch;
        public string arch_str;
        public uint bits;
        public ulong entry;
        public List<Section> sections = new();
        public List<Symbol> symbols = new();

        public void create_reko_architecture()
        {
            switch (arch)
            {
            case BinaryArch.ARCH_X86:
                reko_arch = X86.create_architecture(this);
                break;
            case BinaryArch.ARCH_MIPS:
                reko_arch = Mips.create_architecture(this);
                break;
            default:
                Log.print_err("Reko support for {0} not implemented yet.", arch);
                Environment.Exit(1);
                return;
            }
        }
    }

    //int  load_binary   (string &fname, Binary *bin, Binary::BinaryType type);
    //void unload_binary (Binary *bin);


    partial class Nucleus
    {
        static string[][] binary_types_descr = {
  new[] {"auto", "Try to automatically determine binary format (default)"},
  new[] {"raw" , "Raw binary (memory dump, ROM, network capture, ...)"},
  new[] {"elf" , "Unix ELF"},
  new[] {"pe"  , "Windows PE"},
};

        public static (string str, Binary.BinaryArch arch, string description)[] binary_arch_descr = {
  ("auto"    , Binary.BinaryArch.ARCH_NONE, "Try to automatically determine architecture (default)"),
  ("aarch64" , Binary.BinaryArch.ARCH_AARCH64, "aarch64 (experimental)"),
  ("arm"     , Binary.BinaryArch.ARCH_ARM,     "arm (experimental)"),
  ("mips"    , Binary.BinaryArch.ARCH_MIPS,    "mips (experimental)"),
  ("ppc"     , Binary.BinaryArch.ARCH_PPC, "ppc: Specify ppc-32 or ppc-64 (default ppc-64, experimental)"),
  ("x86"     , Binary.BinaryArch.ARCH_X86, "x86: Specify x86-16, x86-32 or x86-64 (default x86-64)"),
        };

        #region BFD
        public class bfd
        {
            internal static object error_no_error;
            internal static object target_unknown_flavour;

            internal static void init()
            {
                throw new NotImplementedException();
            }

            internal static bfd openr(string p, object o)
            {
                throw new NotImplementedException();
            }

            internal static object get_error()
            {
                throw new NotImplementedException();
            }

            internal static object errmsg(object v)
            {
                throw new NotImplementedException();
            }

            internal static bool check_format(bfd bin, int bfd_object)
            {
                throw new NotImplementedException();
            }

            internal static void set_error(object error_no_error)
            {
                throw new NotImplementedException();
            }

            internal static object get_flavour(bfd bin)
            {
                throw new NotImplementedException();
            }

            internal static long get_symtab_upper_bound(bfd bfd_h)
            {
                throw new NotImplementedException();
            }

            internal static long get_dynamic_symtab_upper_bound(bfd bfd_h)
            {
                throw new NotImplementedException();
            }

            internal static long canonicalize_dynamic_symtab(bfd bfd_h, asymbol[] bfd_dynsym)
            {
                throw new NotImplementedException();
            }

            internal static ulong asymbol_value(asymbol asymbol)
            {
                throw new NotImplementedException();
            }
        }

        public class asymbol { }

        const int bfd_object = 0x4F;

        #endregion

        static bool bfd_inited = false;

        static bfd open_bfd(string fname)
        {

            bfd bin;

            if (!bfd_inited) {
                bfd.init();
                bfd_inited = true;
            }

            bin = bfd.openr(fname, null);
            if (bin == null) {
                Log.print_err("failed to open binary '{0}' ({1})", fname, bfd.errmsg(bfd.get_error()));
                return null;
            }

            if (!bfd.check_format(bin, bfd_object)) {
                Log.print_err("file '{0}' does not look like a binary object ({1}), maybe load as raw?", fname, bfd.errmsg(bfd.get_error()));
                return null;
            }

            /* Some versions of bfd_check_format pessimistically set a wrong_format
             * error before detecting the format, and then neglect to unset it once
             * the format has been detected. We unset it manually to prevent problems. */
            bfd.set_error(bfd.error_no_error);

            if (bfd.get_flavour(bin) == bfd.target_unknown_flavour) {
                Log.print_err("unrecognized format for binary '{0}' ({1})", fname, bfd.errmsg(bfd.get_error()));
                return null;
            }

            //Log.verbose(2, "binary '{0}' has format '{1}'", fname, bin.xvec.name);

            return bin;
        }


        int
        load_symbols_bfd(bfd bfd_h, Binary bin)
        {
            /*
            int ret;
            long n, nsyms, i;
            asymbol[] bfd_symtab;
            Symbol sym;

            bfd_symtab = null;

            n = bfd.get_symtab_upper_bound(bfd_h);
            if (n < 0)
            {
                Log.Log.print_err("failed to read symtab ({0})", bfd.errmsg(bfd.get_error()));
                goto fail;
            }
            else if (n != 0)
            {
                try
                {
                    bfd_symtab = new byte[n];
                }
                catch
                {
                    Log.Log.print_err("out of memory");
                    goto fail;
                }
                nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
                if (nsyms < 0) {
                    Log.Log.print_err("failed to read symtab (%s)", bfd_errmsg(bfd_get_error()));
                    goto fail;
                }
                for (i = 0; i < nsyms; i++) {
                    if (bfd_symtab[i].flags & BSF_FUNCTION) {
                        sym = new Symbol();
                        bin.symbols.Add(sym);
                        sym.type |= Symbol.SymbolType.SYM_TYPE_FUNC;
                        sym.name = bfd_symtab[i].name;
                        sym.addr = bfd.asymbol_value(bfd_symtab[i]);
                    }
                }
            }

            ret = 0;
            goto cleanup;

            fail:
            ret = -1;

            cleanup:
            return ret;
            */
            return 0;
        }


        int
        load_dynsym_bfd(bfd bfd_h, Binary bin)
        {
            /*
            int ret;
            long n, nsyms, i;
            asymbol[] bfd_dynsym;
            Symbol sym;

            bfd_dynsym = null;

            n = bfd.get_dynamic_symtab_upper_bound(bfd_h);
            if (n < 0) {
                Log.Log.print_err("failed to read dynamic symtab (%s)", bfd_errmsg(bfd_get_error()));
                goto fail;
            } else if (n != 0) {
                bfd_dynsym = (asymbol**)malloc(n);
                if (!bfd_dynsym) {
                    Log.print_err("out of memory");
                    goto fail;
                }
                nsyms = bfd.canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
                if (nsyms < 0) {
                    Log.Log.print_err("failed to read dynamic symtab (%s)", bfd_errmsg(bfd_get_error()));
                    goto fail;
                }
                for (i = 0; i < nsyms; i++) {
                    if (bfd_dynsym[i].flags & BSF_FUNCTION) {
                        bin.symbols.push_back(Symbol());
                        sym = &bin.symbols.back();
                        sym.type |= Symbol::SYM_TYPE_FUNC;
                        sym.name = string(bfd_dynsym[i].name);
                        sym.addr = bfd_asymbol_value(bfd_dynsym[i]);
                    }
                }
            }

            ret = 0;
            goto cleanup;

            fail:
            ret = -1;

            cleanup:
            if (bfd_dynsym) free(bfd_dynsym);
            return ret;
            */
            return 0;
        }

        static int
        load_sections_bfd(bfd bfd_h, Binary bin)
        {
            /*
            int bfd_flags, sectype;
            uint64_t vma, size;
            const char* secname;
            asection* bfd_sec;
            Section* sec;

            for (bfd_sec = bfd_h.sections; bfd_sec; bfd_sec = bfd_sec.next) {
                bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);

                sectype = Section::SEC_TYPE_NONE;
                if (bfd_flags & SEC_CODE) {
                    sectype |= Section::SEC_TYPE_CODE;
                } else if (bfd_flags & SEC_DATA) {
                    sectype |= Section::SEC_TYPE_DATA;
                } else {
                    continue;
                }

                vma = bfd_section_vma(bfd_h, bfd_sec);
                size = bfd_section_size(bfd_h, bfd_sec);
                secname = bfd_section_name(bfd_h, bfd_sec);
                if (!secname) secname = "<unnamed>";

                sec = new Section();
                bin.sections.Add(sec);

                sec.binary = bin;
                sec.name = string(secname);
                sec.type = sectype;
                sec.vma = vma;
                sec.size = size;
                sec.bytes = (uint8_t*)malloc(size);
                if (!sec.bytes) {
                    Log.print_err("out of memory");
                    return -1;
                }

                if (!bfd_get_section_contents(bfd_h, bfd_sec, sec.bytes, 0, size)) {
                    Log.print_err("failed to read section '%s' (%s)", secname, bfd_errmsg(bfd_get_error()));
                    return -1;
                }
            }
            */
            return 0;
        }


        static int load_binary_bfd(string fname, Binary bin, Binary.BinaryType type)
        {
            /*
  int ret;
  bfd *bfd_h;
  const bfd_arch_info_type *bfd_info;

  bfd_h = NULL;

  bfd_h = open_bfd(fname);
  if(!bfd_h) {
    goto fail;
  }

  bin.filename = string(fname);
  bin.entry    = bfd_get_start_address(bfd_h);

  bin.type_str = string(bfd_h.xvec.name);
  switch(bfd_h.xvec.flavour) {
  case bfd_target_elf_flavour:
    bin.type = Binary::BIN_TYPE_ELF;
    break;
  case bfd_target_coff_flavour:
    bin.type = Binary::BIN_TYPE_PE;
    break;
  case bfd_target_unknown_flavour:
  default:
    Log.print_err("unsupported binary type (%s)", bfd_h.xvec.name);
    goto fail;
  }

  bfd_info = bfd_get_arch_info(bfd_h);
  bin.arch_str = string(bfd_info.printable_name);
  switch(bfd_info.mach) {
  case bfd_mach_i386_i386:
    bin.arch = Binary::ARCH_X86; 
    bin.bits = 32;
    break;
  case bfd_mach_x86_64:
    bin.arch = Binary::ARCH_X86;
    bin.bits = 64;
    break;
  default:
    Log.print_err("unsupported architecture (%s)", bfd_info.printable_name);
    goto fail;
  }

  /* Symbol handling is best-effort only (they may not even be present) */
            /*
            load_symbols_bfd(bfd_h, bin);
            load_dynsym_bfd(bfd_h, bin);

            if(load_sections_bfd(bfd_h, bin) < 0) goto fail;

            ret = 0;
            goto cleanup;

          fail:
            ret = -1;

          cleanup:
            if(bfd_h) bfd_close(bfd_h);

            return ret;
                      */
            return 0;
        }


        static int
        load_binary_raw(string fname, Binary bin, Binary.BinaryType type)
        {
            bin.filename = fname;
            bin.type = type;
            bin.type_str = "raw";

            if (options.binary.arch == Binary.BinaryArch.ARCH_NONE) {
                Log.print_err("cannot determine binary architecture, specify manually");
                return -1;
            }
            bin.arch = options.binary.arch;
            bin.bits = options.binary.bits;
            bin.arch_str = binary_arch_descr[(int)options.binary.arch].Item1;
            bin.entry = 0;

            if (bin.bits == 0) {
                switch (bin.arch) {
                case Binary.BinaryArch.ARCH_X86:
                    bin.bits = 64;
                    break;
                default:
                    break;
                }
            }

            var sec = new Section();
            bin.sections.Add(sec);

            sec.binary = bin;
            sec.name = "raw";
            sec.type = SectionType.CODE;
            sec.vma = options.binary.base_vma;

            try
            {
                //sec.bytes = generate_random_data(10);
                sec.bytes = File.ReadAllBytes(fname);
            }
            catch (Exception ex) {
                Log.print_err("failed to open binary '{0}' ({1})", fname, ex.Message);
                return -1;
            }

            sec.size = (uint)sec.bytes.Length;
            if (sec.size == 0)
            {
                Log.print_err("binary '{0}' appears to be empty", fname);
                return -1;
            }
            return 0;
        }

        private static byte[] generate_random_data(int size)
        {
            var mem = new byte[size];
            var rnd = new Random(42);
            rnd.NextBytes(mem);
            return mem;
            for (int i = 0; i < 10; ++i)
            {
                int c = rnd.Next() % 4;
                int p = rnd.Next() % mem.Length;
                for (int j = 0; j < c; ++j)
                {
                    mem[(p + j) % mem.Length] = 0x90;
                }
            }

            return mem;
        }

        static int load_binary(string fname, Binary bin, Binary.BinaryType type)
        {
            if (type == Binary.BinaryType.BIN_TYPE_RAW) {
                return load_binary_raw(fname, bin, type);
            } else {
                return load_binary_bfd(fname, bin, type);
            }
        }


        static void
        unload_binary(Binary bin)
        {
        }
    }
}
