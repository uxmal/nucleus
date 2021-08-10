using Reko.Arch.Arm.AArch32;
using Reko.Core;
using Reko.Core.Machine;
using Reko.Core.Memory;
using System.Collections.Generic;

namespace Nucleus
{
    public class Arm { 
    static bool is_cs_nop_ins(A32Instruction ins)
{
        return ins.InstructionClass.HasFlag(InstrClass.Padding);
}


static bool
is_cs_trap_ins(A32Instruction ins)
{
  switch(ins.Mnemonic) {
  /* XXX: todo */
  default:
    return false;
  }
}


static bool
is_cs_call_ins(A32Instruction ins)
{

            return (ins.InstructionClass & (InstrClass.Transfer | InstrClass.Call)) == InstrClass.Call;
}


static bool
is_cs_ret_ins(A32Instruction ins)
{
            return ins.InstructionClass.HasFlag(InstrClass.Return);
            /*
  // bx lr
  if(ins.id == ARM_INS_BX
     && ins.detail.arm.op_count == 1
     && ins.detail.arm.operands[0].type == ARM_OP_REG
     && ins.detail.arm.operands[0].reg == ARM_REG_LR) {
    return 1;
  }

  // ldmfd sp!, {..., pc}
  if(ins.id == ARM_INS_POP) {
    for(i = 0; i < ins.detail.arm.op_count; i++) {
      if(ins.detail.arm.operands[i].type == ARM_OP_REG &&
         ins.detail.arm.operands[i].reg == ARM_REG_PC) {
        return 1;
      }
    }
  }

  // mov pc, lr 
  if(ins.id == ARM_INS_MOV
     && ins.detail.arm.operands[0].type == ARM_OP_REG
     && ins.detail.arm.operands[0].reg == ARM_REG_PC
     && ins.detail.arm.operands[1].type == ARM_OP_REG
     && ins.detail.arm.operands[1].reg == ARM_REG_LR) {
    return 1;
  }

  return 0;*/
}


static bool
is_cs_unconditional_jmp_ins(A32Instruction ins)
{
            return (ins.InstructionClass & InstrClass.ConditionalTransfer | InstrClass.Call) ==
                InstrClass.Transfer;
}


        static bool is_cs_conditional_cflow_ins(A32Instruction ins)
        {
            return (ins.InstructionClass | InstrClass.ConditionalTransfer) ==
                            InstrClass.ConditionalTransfer;
        }


static bool
is_cs_cflow_ins(A32Instruction ins)
{
            return ins.InstructionClass.HasFlag(InstrClass.Transfer);
}


static bool is_cs_indirect_ins(A32Instruction ins)
{
            return (ins.InstructionClass &(InstrClass.Transfer|InstrClass.Return))
                == InstrClass.Transfer
                && ins.Operands.Length > 0
                && (ins.Operands[^1] is not AddressOperand)
                && (ins.Operands[^1] is not ImmediateOperand);
}


static bool
is_cs_privileged_ins(A32Instruction ins)
{
  switch(ins.Mnemonic) {
  /* XXX: todo */
  default:
    return false;
  }
}



public static int
nucleus_disasm_bb_arm(Binary bin, DisasmSection dis, BB bb)
{
            bool init, ret, jmp, indir, cflow, cond, call, nop, only_nop, priv, trap;
            int ndisassembled;
  ulong pc_addr, offset;
  int i, j;

  init   = false;

  switch(bin.bits) {
  case 32:
    break;
  default:
    Log.print_err("unsupported bit width {0} for architecture {1}.", bin.bits, bin.arch_str);
    goto fail;
  }

            var arch = new Reko.Arch.Arm.Arm32Architecture(null, "arm32", new Dictionary<string, object>());
            init = true;

  offset = bb.start - dis.section.vma;
  if((bb.start < dis.section.vma) || (offset >= dis.section.size)) {
    Log.print_err("basic block address points outside of section '{0}'.", dis.section.name);
                return -1; ;
  }

            if (!arch.TryParseAddress(dis.section.vma.ToString("X"), out var addrSection))
            {
                Log.print_err("Lolwut: {0:X}", dis.section.vma);
            }
            var mem = arch.CreateMemoryArea(addrSection, dis.section.bytes);
            var pc = arch.CreateImageReader(mem, (long)offset);
            ulong n = dis.section.size - offset;
  pc_addr = bb.start;
  bb.end = bb.start;
  bb.section = dis.section;
  ndisassembled = 0;
  only_nop = false;
  foreach (A32Instruction cs_ins in arch.CreateDisassembler(pc)) {
    if(cs_ins.Mnemonic == Mnemonic.it) {
      bb.invalid = true;
      bb.end += 1;
      break;
    }
    if(cs_ins.Length == 0) {
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

    if(ndisassembled == 0 && nop) only_nop = true; /* group nop instructions together */
    if(!only_nop && nop) break;
    if(only_nop && !nop) break;

    ndisassembled++;

    bb.end += (ulong) cs_ins.Length;
    bb.insns.Add(cs_ins);
    if(priv) {
      bb.privileged = true;
    }
    if(nop) {
      bb.padding = true;
    }
    if(trap) {
      bb.trap = true;
    }

    /*

    ins = &bb.insns.back();
    ins.id         = cs_ins.id;
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

    for(i = 0; i < cs_ins.detail.arm.op_count; i++) {
      cs_op = &cs_ins.detail.arm.operands[i];
      ins.operands.push_back(Operand());
      op = &ins.operands.back();
      op.type = cs_to_nucleus_op_type(cs_op.type);
      if(op.type == Operand::OP_TYPE_IMM) {
        op.arm_value.imm = cs_op.imm;
      } else if(op.type == Operand::OP_TYPE_REG) {
        op.arm_value.reg = (arm_reg)cs_op.reg;
      } else if(op.type == Operand::OP_TYPE_FP) {
        op.arm_value.fp = cs_op.fp;
      } else if(op.type == Operand::OP_TYPE_MEM) {
        op.arm_value.mem.base    = cs_op.mem.base;
        op.arm_value.mem.index   = cs_op.mem.index;
        op.arm_value.mem.scale   = cs_op.mem.scale;
        op.arm_value.mem.disp    = cs_op.mem.disp;
        if(cflow) ins.flags |= Instruction::INS_FLAG_INDIRECT;
      }
    }

    if(cflow) {
      for(j = 0; j < cs_ins.detail.arm.op_count; j++) {
        cs_op = &cs_ins.detail.arm.operands[j];
        if(cs_op.type == ARM_OP_IMM) {
          ins.target = cs_op.imm;
        }
      }
    }
    */
    if(cflow) {
      /* end of basic block */
      break;
    }
  }

  if(ndisassembled == 0) {
    bb.invalid = true;
    bb.end += (uint)(arch.InstructionBitSize / arch.MemoryGranularity); /* ensure forward progress */
  }

  return ndisassembled;

  fail:
  return -1;

}}
}