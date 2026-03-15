using Reko.Arch.Arm;
using Reko.Arch.Arm.AArch64;
using Reko.Core;
using Reko.Core.Expressions;
using Reko.Core.Machine;
using Reko.Core.Memory;
using System;
using System.Collections.Generic;

namespace Nucleus
{
    using static capstone;

    public partial class AArch64 {

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
    return true;
  }

  return false;
}


static bool
is_cs_unconditional_jmp_ins(AArch64Instruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.b:
    if(ins.Operands[0] is ConditionOperand<ArmCondition> cc && 
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
    return ins.Operands[0] is ConditionOperand<ArmCondition> cc &&
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
  return ins.InstructionClass.HasFlag(InstrClass.Privileged);
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
  case RegisterStorage r:
    if (Registers.SimdRegs128[0].Domain <= r.Domain &&
        Registers.SimdRegs128[^1].Domain >= r.Domain)
        return Operand.OperandType.OP_TYPE_FP;
    else
        return Operand.OperandType.OP_TYPE_REG;
  case Constant _:
  case Address _:
    return Operand.OperandType.OP_TYPE_IMM;
  case MemoryOperand _:
    return Operand.OperandType.OP_TYPE_MEM;
  default:
    return Operand.OperandType.OP_TYPE_NONE;
  }
}

public static bool
nucleus_disasm_bb_aarch64(Binary bin, DisasmSection dis, BB bb)
{
            bool ret, jmp, indir, cflow, cond, call, nop, only_nop, priv, trap;
  int ndisassembled;
  IEnumerator<AArch64Instruction> cs_dis;
  AArch64Instruction cs_ins;
  EndianImageReader pc;
  ulong pc_addr, offset;
  ulong n;

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
    Log.print_err("basic block address points outside of section '{0}'", dis.section.name);
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
}


    }
}