using Reko.Arch.Arm;
using Reko.Arch.Arm.AArch64;
using Reko.Core;
using Reko.Core.Machine;
using Reko.Core.Memory;
using System;
using System.Collections.Generic;

namespace Nucleus
{
    using static capstone;

    public partial class AArch64 {
#if NYI
        public static bool is_cs_nop_ins(AArch64Instruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.nop:
    return true;
  default:
    return false;
  }
}


static bool
is_cs_trap_ins(AArch64Instruction ins)
{
  switch(ins.Mnemonic) {
  /* XXX: todo */
  default:
    return false;
  }
}


static bool
is_cs_cflow_ins(AArch64Instruction ins)
{
  /* XXX: Capstone does not provide information for all generic groups
   * for aarch64 instructions, unlike x86, so we have to do it manually.
   * Once this is implemented, it will suffice to check for the following groups:
   * CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET */

  switch(ins.Mnemonic) {
  case Mnemonic.b:
  case Mnemonic.br:
  case Mnemonic.bl:
  case Mnemonic.blr:
  case Mnemonic.cbnz:
  case Mnemonic.cbz:
  case Mnemonic.tbnz:
  case Mnemonic.tbz:
  case Mnemonic.ret:
    return true;
  default:
    return false;
  }
}

static bool
is_cs_call_ins(AArch64Instruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.bl:
  case Mnemonic.blr:
    return true;
  default:
    return false;
  }
}


static bool
is_cs_ret_ins(AArch64Instruction ins)
{
  /* ret */
  if(ins.Mnemonic == Mnemonic.ret) {
    return 1;
  }

  return 0;
}


static bool
is_cs_unconditional_jmp_ins(AArch64Instruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.b:
    if(ins.Operands[0] is ConditionOperand cc && 
       cc.Condition != ArmCondition.AL) {
      return false;
    }
    return true;
  case Mnemonic.br:
    return true;
  default:
    return false;
  }
}


static bool
is_cs_conditional_cflow_ins(AArch64Instruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.b:
    return ins.Operands[0] is ConditionOperand cc &&
                    cc.Condition != ArmCondition.AL;
  case Mnemonic.cbnz:
  case Mnemonic.cbz:
  case Mnemonic.tbnz:
  case Mnemonic.tbz:
    return true;
  default:
    return false;
  }
}


static bool
is_cs_privileged_ins(AArch64Instruction ins)
{
  return ins.InstructionClass.HasFlag(InstrClass.System);
  switch(ins.Mnemonic) {
  /* XXX: todo */
  default:
    return 0;
  }
}


static bool
is_cs_indirect_ins(AArch64Instruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.br:
  case Mnemonic.blr:
    return true;
  default:
    return false;
  }
}


static Operand.OperandType
cs_to_nucleus_op_type(MachineOperand op)
{
  switch(op) {
  case RegisterOperand _:
    return Operand.OperandType.OP_TYPE_REG;
  case ImmediateOperand _:
  case AddressOperand _:
    return Operand.OperandType.OP_TYPE_IMM;
  case MemoryOperand _:
    return Operand.OperandType.OP_TYPE_MEM;
  case ARM64_OP_FP:
    return Operand.OperandType.OP_TYPE_FP;
  default:
    return Operand.OperandType.OP_TYPE_NONE;
  }
}

#endif

public static bool
nucleus_disasm_bb_aarch64(Binary bin, DisasmSection dis, BB bb)
{
            return false;
#if NYI
            bool init, ret, jmp, indir, cflow, cond, call, nop, only_nop, priv, trap;
  int ndisassembled;
  IEnumerator<AArch64Instruction> cs_dis;
  cs_mode cs_mode_flags;
  AArch64Instruction cs_ins;
  MachineOperand cs_op;
  EndianImageReader pc;
  ulong pc_addr, offset;
  int i, j;
  ulong n;
  Instruction ins;
  Operand op;

  init   = false;
  cs_ins = null;

  switch(bin.bits) {
  case 64:
    break;
  default:
    Log.print_err("unsupported bit width {0}u for architecture {1}", bin.bits, bin.arch_str);
    goto fail;
  }
  var arch = new Arm64Architecture(null, "aarch64", new());
  offset = bb.start - dis.section.vma;
  if((bb.start < dis.section.vma) || (offset >= dis.section.size)) {
    Log.print_err("basic block address points outside of section '%s'", dis.section.name);
    goto fail;
  }

  var mem = new ByteMemoryArea(Address.Ptr64(bb.start), dis.section.bytes);
  pc = arch.Endianness.CreateImageReader(mem, (long)offset);
  n = dis.section.size - offset;
  pc_addr = bb.start;
  bb.end = bb.start;
  bb.section = dis.section;
  ndisassembled = 0;
  only_nop = false;
  cs_dis = new AArch64Disassembler(arch, pc).GetEnumerator();

  while(cs_dis.MoveNext()) {
    if(cs_ins.Mnemonic == Mnemonic.Invalid) {
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

    bb.end += (uint)cs_ins.Length;
    ins = new Instruction();
    bb.insns.Add(ins);
    if(priv) {
      bb.privileged = true;
    }
    if(nop) {
      bb.padding = true;
    }
    if(trap) {
      bb.trap = true;
    }

    ins.id         = (uint)cs_ins.Mnemonic;
    ins.start      = cs_ins.Address.ToLinear();
    ins.size       = (byte)cs_ins.Length;
    ins.mnem       = cs_ins.MnemonicAsString;
    ins.op_str     = op_str(cs_ins);
    ins.privileged = priv;
    ins.trap       = trap;
    if(nop)   ins.flags |= Instruction.InstructionFlags.INS_FLAG_NOP;
    if(ret)   ins.flags |= Instruction.InstructionFlags.INS_FLAG_RET;
    if(jmp)   ins.flags |= Instruction.InstructionFlags.INS_FLAG_JMP;
    if(cond)  ins.flags |= Instruction.InstructionFlags.INS_FLAG_COND;
    if(cflow) ins.flags |= Instruction.InstructionFlags.INS_FLAG_CFLOW;
    if(call)  ins.flags |= Instruction.InstructionFlags.INS_FLAG_CALL;
    if(indir) ins.flags |= Instruction.InstructionFlags.INS_FLAG_INDIRECT;

    for(i = 0; i < cs_ins.Operands.Length; i++) {
      cs_op = cs_ins.Operands[i];
      op = new Operand();
      ins.operands.Add(op);
      op.type = cs_to_nucleus_op_type(cs_op);
      if(op.type == Operand.OperandType.OP_TYPE_IMM) {
        op.aarch64_value.imm = cs_op.imm;
      } else if(op.type == Operand.OperandType.OP_TYPE_REG) {
        op.aarch64_value.reg = (arm64_reg)cs_op.reg;
      } else if(op.type == Operand.OperandType.OP_TYPE_FP) {
        op.aarch64_value.fp = cs_op.fp;
      } else if(op.type == Operand.OperandType.OP_TYPE_MEM) {
        op.x86_value.aarch64_value.mem.@base    = cs_op.mem.@base;
        op.aarch64_value.mem.index   = cs_op.mem.index;
        op.aarch64_value.mem.disp    = cs_op.mem.disp;
        if(cflow) ins.flags |= Instruction.InstructionFlags.INS_FLAG_INDIRECT;
      }
    }

    if(cflow) {
      if (cs_ins.Operands[^1] is AddressOperand addr) {
          ins.target = addr.Address.ToLinear();
      }
    }

    if(cflow) {
      /* end of basic block */
      break;
    }
  }

  if(ndisassembled == 0) {
    bb.invalid = true;
    bb.end += 1; /* ensure forward progress */
  }

  ret = ndisassembled != 0;
  goto cleanup;

  fail:
  ret = false;

  cleanup:
  return ret;
#endif
}

        private static string op_str(AArch64Instruction cs_ins)
        {
            throw new NotImplementedException();
        }
    }
}