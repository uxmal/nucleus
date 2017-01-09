#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <string>
#include <vector>
#include <list>
#include <exception>

#include "loader.h"
#include "bb.h"
#include "insn.h"
#include "dataregion.h"
#include "disasm.h"
#include "strategy.h"
#include "util.h"
#include "options.h"
#include "log.h"

typedef double   (*bb_score_function_t)  (DisasmSection*, BB*);
typedef unsigned (*bb_mutate_function_t) (DisasmSection*, BB*, BB**);
typedef int      (*bb_select_function_t) (DisasmSection*, BB*, unsigned);


/*******************************************************************************
 **                        strategy function: linear                          **
 ******************************************************************************/
double
bb_score_linear(DisasmSection *dis, BB *bb)
{
  bb->score = 1.0;
  return bb->score;
}


unsigned
bb_mutate_linear(DisasmSection *dis, BB *parent, BB **mutants)
{
  if(!parent) {
    try {
      (*mutants) = new BB[1];
    } catch(std::bad_alloc &e) {
      print_err("out of memory");
      return 0;
    }
    /* start disassembling at the start of the section */
    (**mutants).set(dis->section->vma, 0);
  } else if(dis->section->contains(parent->end)) {
    /* next BB is directly after the current BB */
    (**mutants).set(parent->end, 0);
  } else {
    (**mutants).set(0, 0);
    return 0;
  }

  return 1;
}


int
bb_select_linear(DisasmSection *dis, BB *mutants, unsigned len)
{
  unsigned i;

  for(i = 0; i < len; i++) {
    mutants[i].alive = true;
  }

  return len;
}
/*******************************************************************************
 **                       strategy function: recursive                        **
 ******************************************************************************/
double
bb_score_recursive(DisasmSection *dis, BB *bb)
{
  bb->score = 1.0;
  return bb->score;
}


unsigned
bb_queue_recursive(DisasmSection *dis, BB *parent, BB **mutants, unsigned n, const unsigned max_mutants)
{
  uint64_t target;

  for(auto &ins: parent->insns) {
    target = ins.target;
    if(target && dis->section->contains(target)
       && !(dis->addrmap.addr_type(target) & AddressMap::DISASM_REGION_BB_START)) {
      /* recursively queue the target BB for disassembly */
      (*mutants)[n++].set(target, 0);
    }
    if((n+1) == max_mutants) break;
  }
  if((parent->insns.back().flags & Instruction::INS_FLAG_COND)
     || (parent->insns.back().flags & Instruction::INS_FLAG_CALL)) {
    /* queue fall-through block of conditional jump or call */
    if(((n+1) < max_mutants) && dis->section->contains(parent->end) 
       && !(dis->addrmap.addr_type(parent->end) & AddressMap::DISASM_REGION_BB_START)) {
      (*mutants)[n++].set(parent->end, 0);
    }
  }

  return n;
}


unsigned
bb_mutate_recursive(DisasmSection *dis, BB *parent, BB **mutants)
{
  unsigned i, n;
  const unsigned max_mutants = 4096;
  std::vector<Symbol> *symbols;

  /* XXX: This strategy may yield overlapping BBs. Also, the current
   * implementation is very basic and yields low coverage. For normal
   * use the linear strategy is recommended. */

  n = 0;
  if(!parent) {
    try {
      (*mutants) = new BB[max_mutants];
    } catch(std::bad_alloc &e) {
      print_err("out of memory");
      return 0;
    }

    /* first guess for BBs are the entry point and function symbols if available, 
     * or the section start address otherwise */
    if(dis->section->contains(dis->section->binary->entry)) {
      (*mutants)[n++].set(dis->section->binary->entry, 0);
    }
    symbols = &dis->section->binary->symbols;
    for(i = 0; i < symbols->size(); i++) {
      if((symbols->at(i).type & Symbol::SYM_TYPE_FUNC) && ((n+1) < max_mutants)
          && dis->section->contains(symbols->at(i).addr)) {
        (*mutants)[n++].set(symbols->at(i).addr, 0);
      }
    }
    if(n == 0) {
      (*mutants)[n++].set(dis->section->vma, 0);
    }

    return n;
  } else {
    n = bb_queue_recursive(dis, parent, mutants, n, max_mutants);
    if(n == 0) {
      /* no recursive targets found, resort to heuristics */
      if(dis->section->contains(parent->end) && !(dis->addrmap.addr_type(parent->end) & AddressMap::DISASM_REGION_BB_START)) {
        /* guess next BB directly after parent */
        (*mutants)[n++].set(parent->end, 0);
      }
    }
  }

  return n;
}


int
bb_select_recursive(DisasmSection *dis, BB *mutants, unsigned len)
{
  unsigned i;

  for(i = 0; i < len; i++) {
    mutants[i].alive = true;
  }

  return len;
}
/*******************************************************************************
 **                            dispatch functions                             **
 ******************************************************************************/
const char *strategy_functions[] = {
  "linear",
  "recursive",
  NULL
};

const char *strategy_functions_doc[] = {
  /* linear     */ "Linear disassembly",
  /* recursive  */ "Recursive disassembly (incomplete implementation, not recommended)",
  NULL
};

void *bb_strategy_functions[][4] = {
  { (void*)bb_score_linear    , (void*)bb_mutate_linear    , (void*)bb_select_linear     },
  { (void*)bb_score_recursive , (void*)bb_mutate_recursive , (void*)bb_select_recursive  },
  { NULL, NULL, NULL }
};


static int
get_strategy_function_idx()
{
  int i;

  i = 0;
  while(strategy_functions[i]) {
    if(options.strategy_function.name.compare(strategy_functions[i]) == 0) {
      return i;
    }
    i++;
  }

  return -1;
}


int
load_bb_strategy_functions()
{
  int i;
  std::string func;

  func = options.strategy_function.name;
  i = get_strategy_function_idx();
  if(i >= 0) {
    options.strategy_function.score_function  = (bb_score_function_t)bb_strategy_functions[i][0];
    options.strategy_function.mutate_function = (bb_mutate_function_t)bb_strategy_functions[i][1];
    options.strategy_function.select_function = (bb_select_function_t)bb_strategy_functions[i][2];
  } else {
    goto fail;
  }

  return 0;

fail:
  print_err("unknown strategy function '%s'", func.c_str());
  return -1;
}


double
bb_score(DisasmSection *dis, BB *bb)
{
  if(!options.strategy_function.score_function) {
    if(load_bb_strategy_functions() < 0) return -1.0;
  }

  return options.strategy_function.score_function(dis, bb);
}


unsigned
bb_mutate(DisasmSection *dis, BB *parent, BB **mutants)
{
  if(!options.strategy_function.mutate_function) {
    if(load_bb_strategy_functions() < 0) return 0;
  }

  return options.strategy_function.mutate_function(dis, parent, mutants);
}


int
bb_select(DisasmSection *dis, BB *mutants, unsigned len)
{
  if(!options.strategy_function.select_function) {
    if(load_bb_strategy_functions() < 0) return 0;
  }

  return options.strategy_function.select_function(dis, mutants, len);
}

