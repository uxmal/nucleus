#include <assert.h>

#include <capstone/capstone.h>

#include "disasm-ppc.h"
#include "log.h"


static int
is_cs_nop_ins(cs_insn *ins)
{
  cs_ppc *ppc;

  ppc = &ins->detail->ppc;
  switch(ins->id) {
  case PPC_INS_NOP:
    /* nop */
    return 1;
  case PPC_INS_ORI:
    /* ori r0,r0,r0 */
    if((ppc->op_count == 3)
       && (ppc->operands[0].type == PPC_OP_REG)
       && (ppc->operands[1].type == PPC_OP_REG)
       && (ppc->operands[2].type == PPC_OP_REG)
       && (ppc->operands[0].reg == 0)
       && (ppc->operands[1].reg == 0)
       && (ppc->operands[2].reg == 0)) {
      return 1;
    }
    return 0;
  default:
    return 0;
  }
}


static int
is_cs_trap_ins(cs_insn *ins)
{
  switch(ins->id) {
  case PPC_INS_TW:
  case PPC_INS_TWI:
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_cflow_ins(cs_insn *ins)
{
  /* XXX: Capstone does not provide information for all generic groups
   * for ppc instructions, unlike x86, so we have to do it manually.
   * Once this is implemented, it will suffice to check for the following groups:
   * CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET */

  switch(ins->id) {
  case PPC_INS_B:
  case PPC_INS_BA:
  case PPC_INS_BC:
  case PPC_INS_BCA:
  case PPC_INS_BL:
  case PPC_INS_BLA:
  case PPC_INS_BLR:
  case PPC_INS_BCL:
  case PPC_INS_BCLA:
  case PPC_INS_BCTR:
  case PPC_INS_BCTRL:
  case PPC_INS_BCCTR:
  case PPC_INS_BCCTRL:
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_call_ins(cs_insn *ins)
{
  switch(ins->id) {
  case PPC_INS_BL:
  case PPC_INS_BLA:
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_ret_ins(cs_insn *ins)
{
  int32_t bo, bi;
  switch(ins->id) {
  case PPC_INS_BLR:
    return 1;
  case PPC_INS_BCLR:
    assert(ins->detail->ppc.op_count >= 2);
    assert(ins->detail->ppc.operands[0].type == PPC_OP_IMM);
    assert(ins->detail->ppc.operands[1].type == PPC_OP_IMM);
    bo = ins->detail->ppc.operands[0].imm;
    bi = ins->detail->ppc.operands[1].imm;
    if (bo == 20 && bi == 0) {
      return 1;
    }
  default:
    return 0;
  }
}


static int
is_cs_unconditional_jmp_ins(cs_insn *ins)
{
  int32_t bo, bi;
  switch(ins->id) {
  case PPC_INS_B:
  case PPC_INS_BA:
  case PPC_INS_BCTR:
    return 1;
  case PPC_INS_BCCTR:
    assert(ins->detail->ppc.op_count >= 2);
    assert(ins->detail->ppc.operands[0].type == PPC_OP_IMM);
    assert(ins->detail->ppc.operands[1].type == PPC_OP_IMM);
    bo = ins->detail->ppc.operands[0].imm;
    bi = ins->detail->ppc.operands[1].imm;
    if (bo == 20 && bi == 0) {
      return 1;
    }
    return 0;
  default:
    return 0;
  }
}


static int
is_cs_conditional_cflow_ins(cs_insn *ins)
{
  int32_t bo, bi;
  switch(ins->id) {
  case PPC_INS_B:
  case PPC_INS_BA:
    if(ins->detail->ppc.bc == PPC_BC_INVALID) {
      return 0;
    }
    return 1;
  case PPC_INS_BC:
  case PPC_INS_BCA:
    assert(ins->detail->ppc.op_count >= 2);
    assert(ins->detail->ppc.operands[0].type == PPC_OP_IMM);
    assert(ins->detail->ppc.operands[1].type == PPC_OP_IMM);
    bo = ins->detail->ppc.operands[0].imm;
    bi = ins->detail->ppc.operands[1].imm;
    if(bo == 20 && bi == 0) {
      return 0;
    }
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_privileged_ins(cs_insn *ins)
{
  switch(ins->id) {
  case PPC_INS_DCBI:
  case PPC_INS_MFMSR:
  case PPC_INS_MFSR:
  case PPC_INS_MFSRIN:
  case PPC_INS_MTMSR:
  case PPC_INS_MTSR:
  case PPC_INS_MTSRIN:
  case PPC_INS_RFI:
  case PPC_INS_TLBIA:
  case PPC_INS_TLBIE:
  case PPC_INS_TLBSYNC:
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_indirect_ins(cs_insn *ins)
{
  switch(ins->id) {
  case PPC_INS_BCTR:
  case PPC_INS_BCTRL:
  case PPC_INS_BCCTR:
  case PPC_INS_BCCTRL:
    return 1;
  default:
    return 0;
  }
}


static uint8_t
cs_to_nucleus_op_type(ppc_op_type op)
{
  switch(op) {
  case PPC_OP_REG:
    return Operand::OP_TYPE_REG;
  case PPC_OP_IMM:
    return Operand::OP_TYPE_IMM;
  case PPC_OP_MEM:
    return Operand::OP_TYPE_MEM;
  case PPC_OP_CRX:
  case PPC_OP_INVALID:
  default:
    return Operand::OP_TYPE_NONE;
  }
}


int
nucleus_disasm_bb_ppc(Binary *bin, DisasmSection *dis, BB *bb)
{
  int init, ret, jmp, cflow, indir, cond, call, nop, only_nop, priv, trap, ndisassembled;
  csh cs_dis;
  cs_mode cs_mode_flags;
  cs_insn *cs_ins;
  cs_ppc_op *cs_op;
  const uint8_t *pc;
  uint64_t pc_addr, offset;
  size_t i, j, n;
  Instruction *ins;
  Operand *op;

  init   = 0;
  cs_ins = NULL;

  switch(bin->bits) {
  case 64:
    cs_mode_flags = (cs_mode)(CS_MODE_BIG_ENDIAN | CS_MODE_64);
    break;
  case 32:
    cs_mode_flags = (cs_mode)(CS_MODE_BIG_ENDIAN);
    break;
  default:
    print_err("unsupported bit width %u for architecture %s", bin->bits, bin->arch_str.c_str());
    goto fail;
  }

  if(cs_open(CS_ARCH_PPC, cs_mode_flags, &cs_dis) != CS_ERR_OK) {
    print_err("failed to initialize libcapstone");
    goto fail;
  }
  init = 1;
  cs_option(cs_dis, CS_OPT_DETAIL, CS_OPT_ON);

  cs_ins = cs_malloc(cs_dis);
  if(!cs_ins) {
    print_err("out of memory");
    goto fail;
  }

  offset = bb->start - dis->section->vma;
  if((bb->start < dis->section->vma) || (offset >= dis->section->size)) {
    print_err("basic block address points outside of section '%s'", dis->section->name.c_str());
    goto fail;
  }

  pc = dis->section->bytes + offset;
  n = dis->section->size - offset;
  pc_addr = bb->start;
  bb->end = bb->start;
  bb->section = dis->section;
  ndisassembled = 0;
  only_nop = 0;
  while(cs_disasm_iter(cs_dis, &pc, &n, &pc_addr, cs_ins)) {
    if(cs_ins->id == PPC_INS_INVALID) {
      bb->invalid = 1;
      bb->end += 1;
      break;
    }
    if(!cs_ins->size) {
      break;
    }

    trap  = is_cs_trap_ins(cs_ins);
    nop   = is_cs_nop_ins(cs_ins);
    ret   = is_cs_ret_ins(cs_ins);
    jmp   = is_cs_unconditional_jmp_ins(cs_ins) || is_cs_conditional_cflow_ins(cs_ins);
    cond  = is_cs_conditional_cflow_ins(cs_ins);
    cflow = is_cs_cflow_ins(cs_ins);
    call  = is_cs_call_ins(cs_ins);
    priv  = is_cs_privileged_ins(cs_ins);
    indir = is_cs_indirect_ins(cs_ins);

    if(!ndisassembled && nop) only_nop = 1; /* group nop instructions together */
    if(!only_nop && nop) break;
    if(only_nop && !nop) break;

    ndisassembled++;

    bb->end += cs_ins->size;
    bb->insns.push_back(Instruction());
    if(priv) {
      bb->privileged = true;
    }
    if(nop) {
      bb->padding = true;
    }
    if(trap) {
      bb->trap = true;
    }

    ins = &bb->insns.back();
    ins->id         = cs_ins->id;
    ins->start      = cs_ins->address;
    ins->size       = cs_ins->size;
    ins->mnem       = std::string(cs_ins->mnemonic);
    ins->op_str     = std::string(cs_ins->op_str);
    ins->privileged = priv;
    ins->trap       = trap;
    if(nop)   ins->flags |= Instruction::INS_FLAG_NOP;
    if(ret)   ins->flags |= Instruction::INS_FLAG_RET;
    if(jmp)   ins->flags |= Instruction::INS_FLAG_JMP;
    if(cond)  ins->flags |= Instruction::INS_FLAG_COND;
    if(cflow) ins->flags |= Instruction::INS_FLAG_CFLOW;
    if(call)  ins->flags |= Instruction::INS_FLAG_CALL;
    if(indir) ins->flags |= Instruction::INS_FLAG_INDIRECT;

    for(i = 0; i < cs_ins->detail->ppc.op_count; i++) {
      cs_op = &cs_ins->detail->ppc.operands[i];
      ins->operands.push_back(Operand());
      op = &ins->operands.back();
      op->type = cs_to_nucleus_op_type(cs_op->type);
      if(op->type == Operand::OP_TYPE_IMM) {
        op->ppc_value.imm = cs_op->imm;
      } else if(op->type == Operand::OP_TYPE_REG) {
        op->ppc_value.reg = (ppc_reg)cs_op->reg;
      } else if(op->type == Operand::OP_TYPE_MEM) {
        op->ppc_value.mem.base = cs_op->mem.base;
        op->ppc_value.mem.disp = cs_op->mem.disp;
      }
    }

    if(cflow) {
      for(j = 0; j < cs_ins->detail->ppc.op_count; j++) {
        cs_op = &cs_ins->detail->ppc.operands[j];
        if(cs_op->type == PPC_OP_IMM) {
          ins->target = cs_op->imm;
        }
      }
    }

    /* XXX: Some relocations entries point to symbols in sections
     * that are ignored by Nucleus, e.g. calls to external functions.
     * We ignore such calls directly at disasm level. */
    if(call && ins->target == ins->start) {
      ins->flags &= ~Instruction::INS_FLAG_CALL;
      ins->flags &= ~Instruction::INS_FLAG_CFLOW;
    }

    if(cflow) {
      /* end of basic block */
      break;
    }
  }

  if(!ndisassembled) {
    bb->invalid = 1;
    bb->end += 1; /* ensure forward progress */
  }

  ret = ndisassembled;
  goto cleanup;

  fail:
  ret = -1;

  cleanup:
  if(cs_ins) {
    cs_free(cs_ins, 1);
  }
  if(init) {
    cs_close(&cs_dis);
  }
  return ret;
}
