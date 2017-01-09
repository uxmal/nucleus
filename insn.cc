#include <stdio.h>

#include "edge.h"
#include "insn.h"


void
Instruction::print(FILE *out)
{
  fprintf(out, "  0x%016jx  %s\t%s\n", start, mnem.c_str(), op_str.c_str());
}


Edge::EdgeType
Instruction::edge_type()
{
  if(flags & INS_FLAG_JMP) {
    return (flags & INS_FLAG_INDIRECT) ? Edge::EDGE_TYPE_JMP_INDIRECT : Edge::EDGE_TYPE_JMP;
  } else if(flags & INS_FLAG_CALL) {
    return (flags & INS_FLAG_INDIRECT) ? Edge::EDGE_TYPE_CALL_INDIRECT : Edge::EDGE_TYPE_CALL;
  } else if(flags & INS_FLAG_RET) {
    return Edge::EDGE_TYPE_RET;
  } else {
    return Edge::EDGE_TYPE_NONE;
  }
}

