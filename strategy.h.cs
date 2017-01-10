#ifndef NUCLEUS_MUTATE_H
#define NUCLEUS_MUTATE_H

#include <stdint.h>

#include "disasm.h"

extern const char *strategy_functions[];

int load_bb_strategy_functions ();

double   bb_score     (DisasmSection *dis, BB *bb);
unsigned bb_mutate    (DisasmSection *dis, BB *parent, BB **mutants);
int      bb_select (DisasmSection *dis, BB *mutants, unsigned len);

#endif /* NUCLEUS_MUTATE_H */

