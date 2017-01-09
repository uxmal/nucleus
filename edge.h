#ifndef NUCLEUS_EDGE_H
#define NUCLEUS_EDGE_H

#include <stdint.h>

#include <string>

class BB;

class Edge {
public:
  enum EdgeType {
    EDGE_TYPE_NONE,
    EDGE_TYPE_JMP,
    EDGE_TYPE_JMP_INDIRECT,
    EDGE_TYPE_CALL,
    EDGE_TYPE_CALL_INDIRECT,
    EDGE_TYPE_RET,
    EDGE_TYPE_FALLTHROUGH
  };

  Edge(Edge::EdgeType type_, BB *src_, BB *dst_) : type(type_), src(src_), dst(dst_), is_switch(false), jmptab(0), offset(0) {}
  Edge(Edge::EdgeType type_, BB *src_, BB *dst_, bool is_switch_, uint64_t jmptab_, unsigned offset_) : type(type_), src(src_), dst(dst_), is_switch(is_switch_), jmptab(jmptab_), offset(offset_) {}

  std::string type2str ();

  EdgeType  type;
  BB       *src;
  BB       *dst;
  bool      is_switch;
  uint64_t  jmptab;
  unsigned  offset;
};

#endif /* NUCLEUS_EDGE_H */

