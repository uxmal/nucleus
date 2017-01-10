using System;
using System.Collections.Generic;

namespace Nucleus
{
    partial class Nucleus
    {
        public static int Main(string[] args)
        {
            uint i;
            Binary bin;
            Section sec;
            Symbol sym;
            List<DisasmSection> disasm = new List<DisasmSection>();
            CFG cfg = new CFG();

            set_exception_handlers();

            if (parse_options(argc, argv) < 0) {
                return 1;
            }

            if (load_binary(options.binary.filename, out bin, options.binary.type) < 0) {
                return 1;
            }

            verbose(1, "loaded binary '%s' %s/%s (%u bits) entry@0x%016jx",
                    bin.filename,
                    bin.type_str, bin.arch_str,
                    bin.bits, bin.entry);
            for (i = 0; i < bin.sections.Count; i++) {
                sec = &bin.sections[i];
                verbose(1, "  0x{0:X16} {1,8} {2,-20} {3}",
                        sec.vma, sec.size, sec.name,
                        sec.type == Section.SectionType.SEC_TYPE_CODE ? "CODE" : "DATA");
            }
            if (bin.symbols.Count > 0) {
                verbose(1, "scanned symbol tables");
                for (i = 0; i < bin.symbols.Count; i++) {
                    sym = &bin.symbols[i];
                    verbose(1, "  %-40s 0x%016jx %s",
                            sym.name.c_str(), sym.addr,
                            (sym.type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "");
                }
            }

            if (nucleus_disasm(bin, disasm) < 0) {
                return 1;
            }

            if (cfg.make_cfg(bin, disasm) < 0) {
                return 1;
            }

            if (options.summarize_functions) {
                cfg.print_function_summaries(Console.Out);
            } else {
                fprintf(stdout, "\n");
                foreach (var dis in disasm) {
                    dis.print_BBs(stdout);
                }
                cfg.print_functions(Console.Out);
            }

            if (!string.IsNullOrEmpty(options.exports.ida)) {
                (void)export_bin2ida(options.exports.ida, bin, &disasm, cfg);
            }
            if (!string.IsNullOrEmpty(options.exports.dot)) {
                (void)export_cfg2dot(options.exports.dot, cfg);
            }

            unload_binary(bin);

            return 0;
        }
    }
}

