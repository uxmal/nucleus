#ifndef NUCLEUS_FUNCTION_H
#define NUCLEUS_FUNCTION_H

#include <stdio.h>
#include <stdint.h>

#include <list>

#include "bb.h"

class CFG;

class Function {
public:
  Function() : cfg(NULL), start(0), end(0) { id = global_id++; }

  void print (FILE *out);
  void print_summary (FILE *out);

  void find_entry ();
  void add_bb     (BB *bb);

  CFG            *cfg;
  uint64_t        id;
  uint64_t        start;
  uint64_t        end;
  std::list<BB*>  entry;
  std::list<BB*>  BBs;

private:
  static uint64_t global_id;
};

#endif /* NUCLEUS_FUNCTION_H */

