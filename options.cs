using System;
using System.IO;
using static Nucleus.utils;
using static GetOpt;

namespace Nucleus
{

    public partial class Nucleus
    {
        public static options options = new options();

        static void print_usage(string prog)
        {
            //extern const char *strategy_functions_doc[];
            //extern const char *binary_types_descr[][2];
            //extern const char *binary_arch_descr[][2];

            /*
            Console.Write(NUCLEUS_VERSION"\n");
            Console.Write(NUCLEUS_CREDITS"\n");
            Console.Write("\n%s [-vwhtafbDpgi] -e <binary> -d <strategy>\n", prog);
            Console.Write("  -e <binary>\n");
            Console.Write("     : target binary\n");
            Console.Write("  -d <strategy>\n");
            Console.Write("     : select disassembly strategy\n");
            foreach (var si = 0; strategy_functions; i++) {
                Console.Write("         %-12s %s\n", strategy_functions[i], strategy_functions_doc[i]);
            }
            Console.Write("  -t <binary format>\n");
            Console.Write("     : hint on binary format (may be ignored)\n");
            for (i = 0; binary_types_descr[i][0]; i++) {
                Console.Write("         %-12s %s\n", binary_types_descr[i][0], binary_types_descr[i][1]);
            }
            Console.Write("  -a <arch>\n");
            Console.Write("     : disassemble as specified instruction architecture (only for raw binaries)\n");
            for (i = 0; binary_arch_descr[i][0]; i++) {
                Console.Write("         %-12s %s\n", binary_arch_descr[i][0], binary_arch_descr[i][1]);
            }
            Console.Write("  -f : produce list of function entry points and sizes\n");
            Console.Write("  -b <vma>\n");
            Console.Write("     : binary base vma (only for raw binaries)\n");
            Console.Write("  -D : disassemble data sections as code\n");
            Console.Write("  -p : allow privileged instructions\n");
            Console.Write("  -g <file>\n");
            Console.Write("     : export CFG to graphviz dot file\n");
            Console.Write("  -i <file>\n");
            Console.Write("     : export binary info to IDA Pro script\n");
            Console.Write("  -v : verbose\n");
            Console.Write("  -w : disable warnings\n");
            Console.Write("  -h : help\n");
            Console.Write("\nConfiguration used in paper 'Compiler-Agnostic Function Detection in Binaries':\n");
            Console.Write("    %s -d linear -f -e <binary>\n", prog);
            Console.Write("\n");
            */
        }


        static int
        parse_options(string[] argv)
        {
          int i, opt;
          string optstr = "vwhd:t:a:fb:Dpg:i:e:";
          //extern const char *binary_types_descr[][2];
          //extern const char *binary_arch_descr[][2];
          string s;

          options.verbosity           = 0;
          options.warnings            = true;
          options.only_code_sections  = true;
          options.allow_privileged    = false;
          options.summarize_functions = false;

          string fullpath = Path.GetFullPath(argv[0]);
          options.nucleuspath.real = fullpath;
          options.nucleuspath.dir  = Path.GetDirectoryName(fullpath);
          options.nucleuspath.@base = Path.GetFileName(fullpath);

          options.binary.type     = Binary.BinaryType.BIN_TYPE_AUTO;
          options.binary.arch     = Binary.BinaryArch.ARCH_NONE;
          options.binary.base_vma = 0;

          options.strategy.function = null;

          var go = new GetOpt(argv, optstr);
          while((opt = go.getopt(out var optarg)) != -1) {
            switch(opt) {
            case 'v':
              options.verbosity++;
              break;

            case 'w':
              options.warnings = false;
              break;

            case 'e':
              options.binary.filename = optarg;
              break;

            case 't':
              for(i = 0; binary_types_descr[i][0] != null; i++) {
                if(optarg ==  binary_types_descr[i][0]) {
                  options.binary.type = (Binary.BinaryType)i;
                  break;
                }
              }
              if(binary_types_descr[i][0] == null) {
                Console.Write("ERROR: Unrecognized binary format '%s'\n", optarg);
                print_usage(argv[0]);
                return -1;
              }
              break;

            case 'a':
              s = optarg;
              i = s.IndexOf('-');
              if (i > 0)
                s = s.Substring(0, i);
              for(i = 0; i < binary_arch_descr.Length; ++i) {
                if(s == binary_arch_descr[i].str) {
                  options.binary.arch = binary_arch_descr[i].arch;
                  break;
                }
              }
              s = optarg;
              if(s.IndexOf('-') > 0) {
                s = s.Substring(s.IndexOf('-')+1);
                options.binary.bits = Convert.ToUInt32(s);
              }
              if(i >= binary_arch_descr.Length) {
                Console.Write("ERROR: Unrecognized binary architecture '%s'\n", optarg);
                print_usage(argv[0]);
                return -1;
              }
              break;

            case 'f':
              options.summarize_functions = true;
              break;

            case 'b':
              options.binary.base_vma = Convert.ToUInt64(optarg, 16);
              if(options.binary.base_vma == 0) {
                Console.Write("ERROR: Invalid binary base address {0}\n", optarg);
                return -1;
              }
              break;

            case 'D':
              options.only_code_sections = false;
              break;

            case 'p':
              options.allow_privileged = true;
              break;

            case 'g':
              options.exports.dot = optarg;
              break;

            case 'i':
              options.exports.ida = optarg;
              break;

            case 'd':
              options.strategy.name = optarg;
              break;

            case 'h':
            default:
              print_usage(argv[0]);
              return -1;
            }
          }

          if(string.IsNullOrEmpty(options.binary.filename)) {
            print_usage(argv[0]);
            return -1;
          }

          if(string.IsNullOrEmpty(options.strategy.name)) {
            Console.WriteLine("ERROR: No strategy function specified");
            print_usage(argv[0]);
            return -1;
          } else if(load_bb_strategy_functions() < 0) {
            print_usage(argv[0]);
            return -1;
          }
            return 0;
        }
    }
}
