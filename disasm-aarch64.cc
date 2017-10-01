#include <capstone/capstone.h>

#include "disasm-aarch64.h"
#include "log.h"


static int
is_cs_nop_ins(cs_insn *ins)
{
  switch(ins->id) {
  case ARM64_INS_NOP:
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_trap_ins(cs_insn *ins)
{
  switch(ins->id) {
  /* XXX: todo */
  default:
    return 0;
  }
}


static int
is_cs_cflow_ins(cs_insn *ins)
{
  /* XXX: Capstone does not provide information for all generic groups
   * for aarch64 instructions, unlike x86, so we have to do it manually.
   * Once this is implemented, it will suffice to check for the following groups:
   * CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET */

  switch(ins->id) {
  case ARM64_INS_B:
  case ARM64_INS_BR:
  case ARM64_INS_BL:
  case ARM64_INS_BLR:
  case ARM64_INS_CBNZ:
  case ARM64_INS_CBZ:
  case ARM64_INS_TBNZ:
  case ARM64_INS_TBZ:
  case ARM64_INS_RET:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_call_ins(cs_insn *ins)
{
  switch(ins->id) {
  case ARM64_INS_BL:
  case ARM64_INS_BLR:
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_ret_ins(cs_insn *ins)
{
  /* ret */
  if(ins->id == ARM64_INS_RET) {
    return 1;
  }

  return 0;
}


static int
is_cs_unconditional_jmp_ins(cs_insn *ins)
{
  switch(ins->id) {
  case ARM64_INS_B:
    if(ins->detail->arm64.cc != ARM64_CC_INVALID &&
       ins->detail->arm64.cc != ARM64_CC_AL) {
      return 0;
    }
    return 1;
  case ARM64_INS_BR:
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_conditional_cflow_ins(cs_insn *ins)
{
  switch(ins->id) {
  case ARM64_INS_B:
    if (ins->detail->arm64.cc != ARM64_CC_AL) {
      return 1;
    }
    return 0;
  case ARM64_INS_CBNZ:
  case ARM64_INS_CBZ:
  case ARM64_INS_TBNZ:
  case ARM64_INS_TBZ:
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_privileged_ins(cs_insn *ins)
{
  switch(ins->id) {
  /* XXX: todo */
  default:
    return 0;
  }
}


static int
is_cs_indirect_ins(cs_insn *ins)
{
  switch(ins->id) {
  case ARM64_INS_BR:
  case ARM64_INS_BLR:
    return 1;
  default:
    return 0;
  }
}


static uint8_t
cs_to_nucleus_op_type(arm64_op_type op)
{
  switch(op) {
  case ARM64_OP_REG:
    return Operand::OP_TYPE_REG;
  case ARM64_OP_IMM:
    return Operand::OP_TYPE_IMM;
  case ARM64_OP_MEM:
    return Operand::OP_TYPE_MEM;
  case ARM64_OP_FP:
    return Operand::OP_TYPE_FP;
  case ARM64_OP_INVALID:
  default:
    return Operand::OP_TYPE_NONE;
  }
}


int
nucleus_disasm_bb_aarch64(Binary *bin, DisasmSection *dis, BB *bb)
{
  int init, ret, jmp, indir, cflow, cond, call, nop, only_nop, priv, trap, ndisassembled;
  csh cs_dis;
  cs_mode cs_mode_flags;
  cs_insn *cs_ins;
  cs_arm64_op *cs_op;
  const uint8_t *pc;
  uint64_t pc_addr, offset;
  size_t i, j, n;
  Instruction *ins;
  Operand *op;

  init   = 0;
  cs_ins = NULL;

  switch(bin->bits) {
  case 64:
    cs_mode_flags = (cs_mode)(CS_MODE_ARM);
    break;
  default:
    print_err("unsupported bit width %u for architecture %s", bin->bits, bin->arch_str.c_str());
    goto fail;
  }

  if(cs_open(CS_ARCH_ARM64, cs_mode_flags, &cs_dis) != CS_ERR_OK) {
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
    if(cs_ins->id == ARM64_INS_INVALID) {
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

    for(i = 0; i < cs_ins->detail->arm64.op_count; i++) {
      cs_op = &cs_ins->detail->arm64.operands[i];
      ins->operands.push_back(Operand());
      op = &ins->operands.back();
      op->type = cs_to_nucleus_op_type(cs_op->type);
      if(op->type == Operand::OP_TYPE_IMM) {
        op->aarch64_value.imm = cs_op->imm;
      } else if(op->type == Operand::OP_TYPE_REG) {
        op->aarch64_value.reg = (arm64_reg)cs_op->reg;
      } else if(op->type == Operand::OP_TYPE_FP) {
        op->aarch64_value.fp = cs_op->fp;
      } else if(op->type == Operand::OP_TYPE_MEM) {
        op->aarch64_value.mem.base    = cs_op->mem.base;
        op->aarch64_value.mem.index   = cs_op->mem.index;
        op->aarch64_value.mem.disp    = cs_op->mem.disp;
        if(cflow) ins->flags |= Instruction::INS_FLAG_INDIRECT;
      }
    }

    if(cflow) {
      for(j = 0; j < cs_ins->detail->arm64.op_count; j++) {
        cs_op = &cs_ins->detail->arm64.operands[j];
        if(cs_op->type == ARM64_OP_IMM) {
          ins->target = cs_op->imm;
        }
      }
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
