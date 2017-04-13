#include <stdio.h>

#include <list>
#include <string>

#include "nucleus.h"
#include "disasm.h"
#include "cfg.h"
#include "loader.h"
#include "util.h"
#include "exception.h"
#include "options.h"
#include "export.h"
#include "log.h"


int
main(int argc, char *argv[])
{
  size_t i;
  Binary bin;
  Section *sec;
  Symbol *sym;
  std::list<DisasmSection> disasm;
  CFG cfg;

  set_exception_handlers();

  if(parse_options(argc, argv) < 0) {
    return 1;
  }

  if(load_binary(options.binary.filename, &bin, options.binary.type) < 0) {
    return 1;
  }

  verbose(1, "loaded binary '%s' %s/%s (%u bits) entry@0x%016jx", 
          bin.filename.c_str(), 
          bin.type_str.c_str(), bin.arch_str.c_str(), 
          bin.bits, bin.entry);
  for(i = 0; i < bin.sections.size(); i++) {
    sec = &bin.sections[i];
    verbose(1, "  0x%016jx %-8ju %-20s %s", 
            sec->vma, sec->size, sec->name.c_str(), 
            sec->type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
  }
  if(bin.symbols.size() > 0) {
    verbose(1, "scanned symbol tables");
    for(i = 0; i < bin.symbols.size(); i++) {
      sym = &bin.symbols[i];
      verbose(1, "  %-40s 0x%016jx %s", 
              sym->name.c_str(), sym->addr, 
              (sym->type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "");
    }
  }

  if(nucleus_disasm(&bin, &disasm) < 0) {
    return 1;
  }

  if(cfg.make_cfg(&bin, &disasm) < 0) {
    return 1;
  }

  if(options.summarize_functions) {
    cfg.print_function_summaries(stdout);
  } else {
    fprintf(stdout, "\n");
    for(auto &dis: disasm) {
      dis.print_BBs(stdout);
    }
    cfg.print_functions(stdout);
  }

  if(!options.exports.ida.empty()) {
    (void)export_bin2ida(options.exports.ida, &bin, &disasm, &cfg);
  }
  if(!options.exports.binja.empty()) {
    (void)export_bin2binja(options.exports.binja, &bin, &disasm, &cfg);
  }
  if(!options.exports.dot.empty()) {
    (void)export_cfg2dot(options.exports.dot, &cfg);
  }

  unload_binary(&bin);

  return 0;
}

