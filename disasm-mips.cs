using Reko.Arch.Mips;

namespace Nucleus
{
    public static class Mips
    {

#if NYI
        static int
is_cs_nop_ins(MipsInstruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.NOP:
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_trap_ins(MipsInstruction ins)
{
  switch(ins.Mnemonic) {
  /* XXX: todo */
  default:
    return 0;
  }
}


static int
is_cs_cflow_ins(MipsInstruction ins)
{
  /* XXX: Capstone does not provide information for all generic groups
   * for mips instructions, unlike x86, so we have to do it manually.
   * Once this is implemented, it will suffice to check for the following groups:
   * CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET */

  switch(ins.Mnemonic) {
  case Mnemonic.J:
  case Mnemonic.JR:
  case Mnemonic.B:
  case Mnemonic.BAL:
  case Mnemonic.JAL:
  case Mnemonic.JALR:
  case Mnemonic.BEQ:
  case Mnemonic.BNE:
  case Mnemonic.BGTZ:
  case Mnemonic.BGEZ:
  case Mnemonic.BNEZ:
  case Mnemonic.BEQZ:
  case Mnemonic.BLEZ:
  case Mnemonic.BLTZ:
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_call_ins(MipsInstruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.BAL:
  case Mnemonic.JAL:
  case Mnemonic.JALR:
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_ret_ins(MipsInstruction ins)
{
  /* jr ra */
  if(ins.Mnemonic == Mnemonic.JR
     && ins.detail.mips.operands[0].type == MIPS_OP_REG
     && ins.detail.mips.operands[0].reg == MIPS_REG_RA) {
    return 1;
  }

  return 0;
}


static int
is_cs_unconditional_jmp_ins(MipsInstruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.B:
  case Mnemonic.J:
    return 1;
  case Mnemonic.JR:
    if (ins.detail.mips.operands[0].reg != MIPS_REG_RA) {
      return 1;
    }
    return 0;
  default:
    return 0;
  }
}


static int
is_cs_conditional_cflow_ins(MipsInstruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.BEQ:
  case Mnemonic.BNE:
  case Mnemonic.BGTZ:
  case Mnemonic.BGEZ:
  case Mnemonic.BNEZ:
  case Mnemonic.BEQZ:
  case Mnemonic.BLEZ:
  case Mnemonic.BLTZ:
    return 1;
  default:
    return 0;
  }
}


static int
is_cs_privileged_ins(MipsInstruction ins)
{
  switch(ins.Mnemonic) {
  /* XXX: todo */
  default:
    return 0;
  }
}


static int
is_cs_indirect_ins(MipsInstruction ins)
{
  /* jr rN */
  if(ins.Mnemonic == Mnemonic.JR
     && ins.detail.mips.operands[0].type == MIPS_OP_REG
     && ins.detail.mips.operands[0].reg != MIPS_REG_RA) {
    return 1;
  }

  /* jalr rN */
  if(ins.Mnemonic == Mnemonic.JALR) {
    return 1;
  }

  return 0;
}


static uint8_t
cs_to_nucleus_op_type(mips_op_type op)
{
  switch(op) {
  case MIPS_OP_REG:
    return Operand::OP_TYPE_REG;
  case MIPS_OP_IMM:
    return Operand::OP_TYPE_IMM;
  case MIPS_OP_MEM:
    return Operand::OP_TYPE_MEM;
  case MIPS_OP_INVALID:
  default:
    return Operand::OP_TYPE_NONE;
  }
}

#endif

        public static int
        nucleus_disasm_bb_mips(Binary bin, DisasmSection dis, BB bb)
        {
            return -1;
#if NYI
            int init, ret, jmp, cflow, indir, cond, call, nop, only_nop, priv, trap, ndisassembled;
  csh cs_dis;
  cs_mode cs_mode_flags;
  cs_insn *cs_ins;
  cs_mips_op *cs_op;
  const uint8_t *pc;
  uint64_t pc_addr, offset;
  size_t i, j, n;
  Instruction *ins, *last_cflow;
  Operand *op;

  init   = 0;
  cs_ins = nullptr;
  last_cflow = nullptr;

  switch(bin.bits) {
  case 64:
    cs_mode_flags = (cs_mode)(CS_MODE_BIG_ENDIAN | CS_MODE_64);
    break;
  case 32:
    cs_mode_flags = (cs_mode)(CS_MODE_BIG_ENDIAN | CS_MODE_32);
    break;
  case 16:
    cs_mode_flags = (cs_mode)(CS_MODE_BIG_ENDIAN | CS_MODE_16);
    break;
  default:
    print_err("unsupported bit width %u for architecture %s", bin.bits, bin.arch_str.c_str());
    goto fail;
  }

  if(cs_open(CS_ARCH_MIPS, cs_mode_flags, &cs_dis) != CS_ERR_OK) {
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

  offset = bb.start - dis.section.vma;
  if((bb.start < dis.section.vma) || (offset >= dis.section.size)) {
    print_err("basic block address points outside of section '%s'", dis.section.name.c_str());
    goto fail;
  }

  pc = dis.section.bytes + offset;
  n = dis.section.size - offset;
  pc_addr = bb.start;
  bb.end = bb.start;
  bb.section = dis.section;
  ndisassembled = 0;
  only_nop = 0;
  while(cs_disasm_iter(cs_dis, &pc, &n, &pc_addr, cs_ins)) {
    if(cs_ins.Mnemonic == Mnemonic.INVALID) {
      bb.invalid = 1;
      bb.end += 1;
      break;
    }
    if(!cs_ins.size) {
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
    if(!last_cflow && !only_nop && nop) break;
    if(!last_cflow && only_nop && !nop) break;

    ndisassembled++;

    bb.end += cs_ins.size;
    bb.insns.push_back(Instruction());
    if(priv) {
      bb.privileged = true;
    }
    if(nop) {
      bb.padding = true;
    }
    if(trap) {
      bb.trap = true;
    }

    ins = &bb.insns.back();
    ins.Mnemonic         = cs_ins.Mnemonic;
    ins.start      = cs_ins.address;
    ins.size       = cs_ins.size;
    ins.mnem       = std::string(cs_ins.mnemonic);
    ins.op_str     = std::string(cs_ins.op_str);
    ins.privileged = priv;
    ins.trap       = trap;
    if(nop)   ins.flags |= Instruction::INS_FLAG_NOP;
    if(ret)   ins.flags |= Instruction::INS_FLAG_RET;
    if(jmp)   ins.flags |= Instruction::INS_FLAG_JMP;
    if(cond)  ins.flags |= Instruction::INS_FLAG_COND;
    if(cflow) ins.flags |= Instruction::INS_FLAG_CFLOW;
    if(call)  ins.flags |= Instruction::INS_FLAG_CALL;
    if(indir) ins.flags |= Instruction::INS_FLAG_INDIRECT;

    for(i = 0; i < cs_ins.detail.mips.op_count; i++) {
      cs_op = &cs_ins.detail.mips.operands[i];
      ins.operands.push_back(Operand());
      op = &ins.operands.back();
      op.type = cs_to_nucleus_op_type(cs_op.type);
      if(op.type == Operand::OP_TYPE_IMM) {
        op.mips_value.imm = cs_op.imm;
      } else if(op.type == Operand::OP_TYPE_REG) {
        op.mips_value.reg = (mips_reg)cs_op.reg;
      } else if(op.type == Operand::OP_TYPE_MEM) {
        op.mips_value.mem.base = cs_op.mem.base;
        op.mips_value.mem.disp = cs_op.mem.disp;
        if(cflow) ins.flags |= Instruction::INS_FLAG_INDIRECT;
      }
    }

    if(cflow) {
      for(j = 0; j < cs_ins.detail.mips.op_count; j++) {
        cs_op = &cs_ins.detail.mips.operands[j];
        if(cs_op.type == MIPS_OP_IMM) {
          ins.target = cs_op.imm;
        }
      }
    }

    /* end of basic block occurs after delay slot of cflow instructions */
    if(last_cflow) {
      ins.flags = last_cflow.flags;
      ins.target = last_cflow.target;
      last_cflow.flags = 0;
      break;
    }
    if(cflow) {
      last_cflow = ins;
    }
  }

  if(!ndisassembled) {
    bb.invalid = 1;
    bb.end += 1; /* ensure forward progress */
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
#endif
        }
    }
}
