using System;
using System.Collections.Generic;

namespace Nucleus
{
    partial class Nucleus
    {
        public static int Main(string[] args)
        {
            int i;
            Binary bin = new Binary();
            Section sec;
            Symbol sym;
            List<DisasmSection> disasm = new List<DisasmSection>();
            CFG cfg = new CFG();

            try
            {

                if (parse_options(args) < 0)
                {
                    return 1;
                }

                if (load_binary(options.binary.filename, bin, options.binary.type) < 0)
                {
                    return 1;
                }

                Log.verbose(1, "loaded binary '{0}' {1}/{2} ({3} bits) entry@{4}",
                        bin.filename,
                        bin.type_str, bin.arch_str,
                        bin.bits, bin.entry);
                for (i = 0; i < bin.sections.Count; i++)
                {
                    sec = bin.sections[i];
                    Log.verbose(1, "  0x{0:X16} {1,8} {2,-20} {3}",
                            sec.vma, sec.size, sec.name,
                            sec.type == SectionType.CODE ? "CODE" : "DATA");
                }
                if (bin.symbols.Count > 0)
                {
                    Log.verbose(1, "scanned symbol tables");
                    for (i = 0; i < bin.symbols.Count; i++)
                    {
                        sym = bin.symbols[i];
                        Log.verbose(1, "  {0,-40} 0x{1:X16} {2}",
                                sym.name, sym.addr,
                                (sym.type & Symbol.SymbolType.SYM_TYPE_FUNC) != 0 ? "FUNC" : "");
                    }
                }

                if (nucleus_disasm(bin, disasm) < 0)
                {
                    return 1;
                }

                if (cfg.make_cfg(bin, disasm) < 0)
                {
                    return 1;
                }

                if (options.summarize_functions)
                {
                    cfg.print_function_summaries(Console.Out);
                }
                else
                {
                    Console.Out.WriteLine();
                    foreach (var dis in disasm)
                    {
                        dis.print_BBs(Console.Out);
                    }
                    cfg.print_functions(Console.Out);
                }

                if (!string.IsNullOrEmpty(options.exports.ida))
                {
                    export_bin2ida(options.exports.ida, bin, disasm, cfg);
                }
                if (!string.IsNullOrEmpty(options.exports.dot))
                {
                    export_cfg2dot(options.exports.dot, cfg);
                }

                unload_binary(bin);
            }
            catch
            {
               Log.print_err("unhandled exception, terminating...");
            }
            return 0;
        }
    }
}

