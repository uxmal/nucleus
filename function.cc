#include <stdio.h>
#include <stdint.h>

#include <list>

#include "cfg.h"
#include "bb.h"
#include "util.h"
#include "function.h"


uint64_t Function::global_id = 0;

void
Function::print(FILE *out)
{
  size_t i;
  unsigned offset;

  if(entry.empty()) {
    fprintf(out, "function %ju: start@0x%016jx end@0x%016jx (entry point unknown)\n", id, start, end);
  } else {
    i = 0;
    for(auto entry_bb: entry) {
      offset = 0;
      for(auto &e: entry_bb->ancestors) {
        if(e.type == Edge::EDGE_TYPE_CALL) offset = e.offset;
      }
      if(i == 0) {
        fprintf(out, "function %ju: entry@0x%016jx %ju bytes\n", id, entry_bb->start + offset, (end-entry_bb->start));
        if(entry.size() > 1) {
          fprintf(out, "/-- alternative entry points:\n");
        }
      } else {
        fprintf(out, "/-- 0x%016jx\n", entry_bb->start + offset);
      }
      i++;
    }
  }
  for(auto &bb: BBs) {
    fprintf(out, "    BB@0x%016jx\n", bb->start);
  }
}


void
Function::print_summary(FILE *out)
{
  BB *entry_bb;
  unsigned offset;

  if(entry.empty()) {
    fprintf(out, "0x0\t\t\t%ju\n", end-start);
  } else {
    entry_bb = entry.front();
    offset = 0;
    for(auto &e: entry_bb->ancestors) {
      if(e.type == Edge::EDGE_TYPE_CALL) offset = e.offset;
    }
    fprintf(out, "0x%016jx\t%ju\n", entry_bb->start + offset, (end-entry_bb->start));
  }
}


void
Function::find_entry()
{
  bool reached_directly;
  std::list<BB*> called;
  std::list<BB*> headers;

  /* Entries are sorted by priority as follows:
   * (1) Called BBs in order of increasing address
   * (2) Ancestor-less BBs in order of increasing address
   * (3) Starting address of the function (only if no other entry found)
   */

  for(auto bb: this->BBs) {
    if(bb->is_called()) {
      called.push_back(bb);
    }
  }

  called.sort(compare_ptr<BB>);
  for(auto bb: called) this->entry.push_back(bb);

  for(auto bb: this->BBs) {
    reached_directly = false;
    for(auto &e: bb->ancestors) {
      if(e.offset == 0) reached_directly = true;
    }
    if(!reached_directly) {
      headers.push_back(bb);
    }
  }

  headers.sort(compare_ptr<BB>);
  for(auto bb: headers) this->entry.push_back(bb);

  if(this->entry.empty()) {
    if(this->cfg->start2bb.count(start)) {
      this->entry.push_back(this->cfg->start2bb[start]);
    }
  }
}


void
Function::add_bb(BB *bb)
{
  this->BBs.push_back(bb);
  if(!this->start || (bb->start < this->start)) {
    this->start = bb->start;
  }
  if(!this->end || (bb->end > this->end)) {
    if(!(bb->insns.back().flags & Instruction::INS_FLAG_NOP)) this->end = bb->end;
  }
  bb->function = this;
}

