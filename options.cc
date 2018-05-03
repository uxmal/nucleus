#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include "nucleus.h"
#include "util.h"
#include "strategy.h"
#include "loader.h"
#include "options.h"


struct options options;


void
print_usage(char *prog)
{
  int i;
  extern const char *strategy_functions_doc[];
  extern const char *binary_types_descr[][2];
  extern const char *binary_arch_descr[][2];

  printf(NUCLEUS_VERSION"\n");
  printf(NUCLEUS_CREDITS"\n");
  printf("\n%s [-vwhtafbDpgi] -e <binary> -d <strategy>\n", prog);
  printf("  -e <binary>\n");
  printf("     : target binary\n");
  printf("  -d <strategy>\n");
  printf("     : select disassembly strategy\n");
  for(i = 0; strategy_functions[i]; i++) {
    printf("         %-12s %s\n", strategy_functions[i], strategy_functions_doc[i]);
  }
  printf("  -t <binary format>\n");
  printf("     : hint on binary format (may be ignored)\n");
  for(i = 0; binary_types_descr[i][0]; i++) {
    printf("         %-12s %s\n", binary_types_descr[i][0], binary_types_descr[i][1]);
  }
  printf("  -a <arch>\n");
  printf("     : disassemble as specified instruction architecture (only for raw binaries)\n");
  for(i = 0; binary_arch_descr[i][0]; i++) {
    printf("         %-12s %s\n", binary_arch_descr[i][0], binary_arch_descr[i][1]);
  }
  printf("  -f : produce list of function entry points and sizes\n");
  printf("  -b <vma>\n");
  printf("     : binary base vma (only for raw binaries)\n");
  printf("  -D : disassemble data sections as code\n");
  printf("  -p : allow privileged instructions\n");
  printf("  -g <file>\n");
  printf("     : export CFG to graphviz dot file\n");
  printf("  -i <file>\n");
  printf("     : export binary info to IDA Pro script\n");
  printf("  -n <file>\n");
  printf("     : export binary info to Binary Ninja script\n");
  printf("  -v : verbose\n");
  printf("  -w : disable warnings\n");
  printf("  -h : help\n");
  printf("\nConfiguration used in paper 'Compiler-Agnostic Function Detection in Binaries':\n");
  printf("    %s -d linear -f -e <binary>\n", prog);
  printf("\n");
}


int
parse_options(int argc, char *argv[])
{
  int i, opt;
  char optstr[] = "vwhd:t:a:fb:Dpg:i:n:e:";
  extern const char *binary_types_descr[][2];
  extern const char *binary_arch_descr[][2];
  std::string s;

  options.verbosity           = 0;
  options.warnings            = 1;
  options.only_code_sections  = 1;
  options.allow_privileged    = 0;
  options.summarize_functions = 0;

  options.nucleuspath.real = str_realpath(std::string(argv[0]));
  options.nucleuspath.dir  = str_realpath_dir(std::string(argv[0]));
  options.nucleuspath.base = str_realpath_base(std::string(argv[0]));

  options.binary.type     = Binary::BIN_TYPE_AUTO;
  options.binary.arch     = Binary::ARCH_NONE;
  options.binary.base_vma = 0;

  options.strategy_function.score_function  = NULL;
  options.strategy_function.mutate_function = NULL;
  options.strategy_function.select_function = NULL;

  opterr = 0;
  while((opt = getopt(argc, argv, optstr)) != -1) {
    switch(opt) {
    case 'v':
      options.verbosity++;
      break;

    case 'w':
      options.warnings = 0;
      break;

    case 'e':
      options.binary.filename = std::string(optarg);
      break;

    case 't':
      for(i = 0; binary_types_descr[i][0]; i++) {
        if(!strcmp(optarg, binary_types_descr[i][0])) {
          options.binary.type = (Binary::BinaryType)i;
          break;
        }
      }
      if(!binary_types_descr[i][0]) {
        printf("ERROR: Unrecognized binary format '%s'\n", optarg);
        print_usage(argv[0]);
        return -1;
      }
      break;

    case 'a':
      s = std::string(optarg);
      s = s.substr(0, s.find('-'));
      for(i = 0; binary_arch_descr[i][0]; i++) {
        if(!strcmp(s.c_str(), binary_arch_descr[i][0])) {
          options.binary.arch = (Binary::BinaryArch)i;
          break;
        }
      }
      s = std::string(optarg);
      if(s.find('-') != std::string::npos) {
        s = s.substr(s.find('-')+1);
      }
      options.binary.bits = strtoul(s.c_str(), NULL, 0);
      if(!binary_arch_descr[i][0]) {
        printf("ERROR: Unrecognized binary architecture '%s'\n", optarg);
        print_usage(argv[0]);
        return -1;
      }
      break;

    case 'f':
      options.summarize_functions = 1;
      break;

    case 'b':
      options.binary.base_vma = strtoul(optarg, NULL, 0);
      if(!options.binary.base_vma) {
        printf("ERROR: Invalid binary base address %s\n", optarg);
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
      options.exports.dot = std::string(optarg);
      break;

    case 'i':
      options.exports.ida = std::string(optarg);
      break;

    case 'n':
      options.exports.binja = std::string(optarg);
      break;

    case 'd':
      options.strategy_function.name = std::string(optarg);
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
    printf("ERROR: No strategy function specified\n");
    print_usage(argv[0]);
    return -1;
  } else if(load_bb_strategy_functions() < 0) {
    print_usage(argv[0]);
    return -1;
  }

  return 0;
}

