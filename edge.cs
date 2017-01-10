#include <string>

#include "edge.h"


std::string
Edge::type2str()
{
  std::string s;

  switch(this->type) {
  case EDGE_TYPE_JMP:
    s = "jmp";
    break;
  case EDGE_TYPE_JMP_INDIRECT:
    s = "ijmp";
    break;
  case EDGE_TYPE_CALL:
    s = "call";
    break;
  case EDGE_TYPE_CALL_INDIRECT:
    s = "icall";
    break;
  case EDGE_TYPE_RET:
    s = "ret";
    break;
  case EDGE_TYPE_FALLTHROUGH:
    s = "fallthrough";
    break;
  default:
    s = "none";
    break;
  }

  if(this->is_switch) {
    s += "/switch";
  }
  if(this->offset) {
    s += "/+" + std::to_string(this->offset);
  }

  return s;
}

