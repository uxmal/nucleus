#include <capstone/capstone.h>

#include "disasm-ppc.h"
#include "log.h"


static int
is_cs_nop_ins(cs_insn *ins)
{
  switch(ins->id) {
  default:
    return 0;
  }
}


static int
is_cs_semantic_nop_ins(cs_insn *ins)
{
  switch(ins->id) {
  default:
    return 0;
  }
}


static int
is_cs_trap_ins(cs_insn *ins)
{
  switch(ins->id) {
  default:
    return 0;
  }
}


static int
is_cs_cflow_group(uint8_t g)
{
  return 0;
}


static int
is_cs_cflow_ins(cs_insn *ins)
{
  return 0;
}


static int
is_cs_call_ins(cs_insn *ins)
{
  switch(ins->id) {
  default:
    return 0;
  }
}


static int
is_cs_ret_ins(cs_insn *ins)
{
  switch(ins->id) {
  default:
    return 0;
  }
}


static int
is_cs_unconditional_jmp_ins(cs_insn *ins)
{
  switch(ins->id) {
  default:
    return 0;
  }
}


static int
is_cs_conditional_cflow_ins(cs_insn *ins)
{
  switch(ins->id) {
  default:
    return 0;
  }
}


static int
is_cs_privileged_ins(cs_insn *ins)
{
  switch(ins->id) {
  default:
    return 0;
  }
}


static uint8_t
cs_to_nucleus_op_type(x86_op_type op)
{
  switch(op) {
  default:
    return Operand::OP_TYPE_NONE;
  }
}


int
nucleus_disasm_bb_ppc(Binary *bin, DisasmSection *dis, BB *bb)
{
  return 0;
}
