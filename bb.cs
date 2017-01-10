#include <stdio.h>

#include "bb.h"
#include "insn.h"


void
BB::print(FILE *out)
{
  fprintf(out, "BB @0x%016jx (score %.10f) %s%s%s%s {\n", 
          start, score, invalid ? "i" : "-", privileged ? "p" : "-", 
          addrtaken ? "a" : "-", padding ? "n" : "-");
  if(invalid) {
    fprintf(out, "  0x%016jx  (bad)", start);
  } else {
    for(auto &ins: insns) {
      ins.print(out);
    }
  }
  if(!ancestors.empty()) {
    fprintf(out, "--A ancestors:\n");
    for(auto &e: ancestors) {
      fprintf(out, "--A 0x%016jx (%s)\n", e.src->insns.back().start, e.type2str().c_str());
    }
  }
  if(!targets.empty()) {
    fprintf(out, "--T targets:\n");
    for(auto &e: targets) {
      fprintf(out, "--T 0x%016jx (%s)\n", e.dst->start+e.offset, e.type2str().c_str());
    }
  }
  fprintf(out, "}\n\n");
}


bool
BB::is_called()
{
  for(auto &e: ancestors) {
    if((e.type == Edge::EDGE_TYPE_CALL) 
       || (e.type == Edge::EDGE_TYPE_CALL_INDIRECT)) {
      return true;
    }
  }

  return false;
}


bool
BB::returns()
{
  return (insns.back().flags & Instruction::INS_FLAG_RET);
}

