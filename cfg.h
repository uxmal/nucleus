#ifndef NUCLEUS_CFG_H
#define NUCLEUS_CFG_H

#include <stdio.h>
#include <stdint.h>

#include <list>
#include <map>

#include "bb.h"
#include "edge.h"
#include "function.h"
#include "disasm.h"
#include "loader.h"

class CFG {
public:
  CFG() {}

  int make_cfg (Binary *bin, std::list<DisasmSection> *disasm);

  BB *get_bb (uint64_t addr, unsigned *offset = NULL);
 
  void print_functions (FILE *out);
  void print_function_summaries (FILE *out);

  Binary                  *binary;
  std::list<BB*>           entry;
  std::list<Function>      functions;
  std::map<uint64_t, BB*>  start2bb;
  std::map<uint64_t, BB*>  bad_bbs;

private:
  /* pass: address-taken detection */
  void mark_addrtaken        (uint64_t addr);
  void analyze_addrtaken_ppc ();
  void analyze_addrtaken_x86 ();
  void analyze_addrtaken     ();

  /* pass: switch detection */
  void mark_jmptab_as_data   (uint64_t start, uint64_t end);
  void find_switches_aarch64 ();
  void find_switches_arm     ();
  void find_switches_mips    ();
  void find_switches_ppc     ();
  void find_switches_x86     ();
  void find_switches         ();

  void expand_function       (Function *f, BB *bb);
  void find_functions        ();
  void find_entry            ();
  void verify_padding        ();
  void detect_bad_bbs        ();
  void link_bbs              (Edge::EdgeType type, BB *bb, uint64_t target, uint64_t jmptab = 0);
  void unlink_bb             (BB *bb);
  void unlink_edge           (BB *bb, BB *cc);
};

#endif /* NUCLEUS_CFG_H */

