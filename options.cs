using System;

namespace Nucleus
{

    public partial class Nucleus
    {
        public static options options = new options();

        static void print_usage(string prog)
        {
            int i;
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
          options.allow_privileged    = 0;
          options.summarize_functions = false;

          options.nucleuspath.real = str_realpath(argv[0]);
          options.nucleuspath.dir  = str_realpath_dir(argv[0]);
          options.nucleuspath.@base = str_realpath_base(argv[0]);

          options.binary.type     = Binary.BinaryType.BIN_TYPE_AUTO;
          options.binary.arch     = Binary.BinaryArch.ARCH_NONE;
          options.binary.base_vma = 0;

          options.strategy.function = null;

          bool opterr = false;
          while((opt = getopt(argc, argv, optstr)) != -1) {
            switch(opt) {
            case 'v':
              options.verbosity++;
              break;

            case 'w':
              options.warnings = 0;
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
              s = string(optarg);
              s = s.substr(0, s.find('-'));
              for(i = 0; binary_arch_descr[i][0]; i++) {
                if(!strcmp(s, binary_arch_descr[i][0])) {
                  options.binary.arch = (Binary::BinaryArch)i;
                  break;
                }
              }
              s = string(optarg);
              if(s.find('-') != string::npos) {
                s = s.substr(s.find('-')+1);
              }
              options.binary.bits = strtoul(s, NULL, 0);
              if(!binary_arch_descr[i][0]) {
                Console.Write("ERROR: Unrecognized binary architecture '%s'\n", optarg);
                print_usage(argv[0]);
                return -1;
              }
              break;

            case 'f':
              options.summarize_functions = 1;
              break;

            case 'b':
              options.binary.base_vma = Convert.ToUInt64(optarg, null, 0);
              if(!options.binary.base_vma) {
                Console.Write("ERROR: Invalid binary base address %s\n", optarg);
                return -1;
              }
              break;

            case 'D':
              options.only_code_sections = 0;
              break;

            case 'p':
              options.allow_privileged = 1;
              break;

            case 'g':
              options.exports.dot = string(optarg);
              break;

            case 'i':
              options.exports.ida = string(optarg);
              break;

            case 'd':
              options.strategy_function.name = string(optarg);
              break;

            case 'h':
            default:
              print_usage(argv[0]);
              return -1;
            }
          }

          if(options.binary.filename.empty()) {
            print_usage(argv[0]);
            return -1;
          }

          if(options.strategy_function.name.empty()) {
            Console.Write("ERROR: No strategy function specified\n");
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
