#ifndef NUCLEUS_BB_H
#define NUCLEUS_BB_H

#include <stdio.h>
#include <stdint.h>

#include <list>

#include "insn.h"
#include "edge.h"
#include "loader.h"

class Function;

class BB {
public:
  BB() : start(0), end(0), function(NULL), section(NULL), score(0.0), 
         alive(false), invalid(false), privileged(false), addrtaken(false), padding(false), trap(false) {}
  BB(const BB &bb) : start(bb.start), end(bb.end), insns(bb.insns), function(bb.function), section(bb.section), score(bb.score), 
                     alive(bb.alive), invalid(bb.invalid), privileged(bb.privileged), addrtaken(bb.addrtaken), padding(bb.padding), trap(bb.trap), 
                     ancestors(bb.ancestors), targets(bb.targets) {}

  void reset()                           { start = 0; end = 0; insns.clear(); function = NULL; section = NULL; score = 0.0; 
                                           alive = false; invalid = false; privileged = false; addrtaken = false; padding = false; trap = false;
                                           ancestors.clear(); targets.clear(); }
  void set(uint64_t start, uint64_t end) { reset(); this->start = start; this->end = end; }

  bool is_addrtaken () { return addrtaken; }
  bool is_invalid   () { return invalid; }
  bool is_padding   () { return padding; }
  bool is_trap      () { return trap; }
  bool is_called    ();
  bool returns      ();

  void print(FILE *out);

  static bool comparator (BB& bb, BB& cc)     { return bb.start < cc.start; }
  inline bool operator<  (const BB& cc) const { return this->start < cc.start; }

  uint64_t                start;
  uint64_t                end;
  std::list<Instruction>  insns;
  Function               *function;
  Section                *section;

  double                  score;
  bool                    alive;
  bool                    invalid;
  bool                    privileged;
  bool                    addrtaken;
  bool                    padding;
  bool                    trap;

  std::list<Edge>         ancestors;
  std::list<Edge>         targets;
};

#endif /* NUCLEUS_BB_H */

