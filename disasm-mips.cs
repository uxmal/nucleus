using Reko.Arch.Mips;
using Reko.Core;
using Reko.Core.Machine;
using Reko.Core.Memory;
using System;
using System.Collections.Generic;

namespace Nucleus
{
    public static class Mips
    {

        static bool is_cs_nop_ins(MipsInstruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.nop:
    return true;
  default:
    return false;
  }
}


static bool is_cs_trap_ins(MipsInstruction ins)
{
  switch(ins.Mnemonic) {
  /* XXX: todo */
  default:
    return false;
  }
}


static bool is_cs_cflow_ins(MipsInstruction ins)
{
  /* XXX: Capstone does not provide information for all generic groups
   * for mips instructions, unlike x86, so we have to do it manually.
   * Once this is implemented, it will suffice to check for the following groups:
   * CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET */

  switch(ins.Mnemonic) {
  case Mnemonic.j:
  case Mnemonic.jr:
  case Mnemonic.b:
  case Mnemonic.bal:
  case Mnemonic.jal:
  case Mnemonic.jalr:
  case Mnemonic.beq:
  case Mnemonic.bne:
  case Mnemonic.bgtz:
  case Mnemonic.bgez:
  case Mnemonic.bnez:
  case Mnemonic.beqz:
  case Mnemonic.blez:
  case Mnemonic.bltz:
    return true;
  default:
    return false;
  }
}


        static bool is_cs_call_ins(MipsInstruction ins)
        {
            return ins.InstructionClass.HasFlag(InstrClass.Call);
        }


static bool
is_cs_ret_ins(MipsInstruction ins)
{
  /* jr ra */
  if(ins.Mnemonic == Mnemonic.jr
     && ins.Operands[0] is RegisterOperand reg
     && reg.Register == Registers.ra) {
    return true;
  }

  return false;
}


static bool
is_cs_unconditional_jmp_ins(MipsInstruction ins)
{
            return (ins.InstructionClass
                & (InstrClass.Transfer | InstrClass.Call | InstrClass.Return | InstrClass.Conditional)) ==
                InstrClass.Transfer;
}


static bool is_cs_conditional_cflow_ins(MipsInstruction ins)
{
            return (ins.InstructionClass & InstrClass.ConditionalTransfer) ==
                InstrClass.ConditionalTransfer;
}


static bool is_cs_privileged_ins(MipsInstruction ins)
{
            return ins.InstructionClass.HasFlag(InstrClass.Privileged);
}


static bool
is_cs_indirect_ins(MipsInstruction ins)
{
            return (ins.InstructionClass & (InstrClass.Transfer | InstrClass.Return)) == InstrClass.Transfer; 
}

        public static IProcessorArchitecture create_architecture(Binary bin)
        {
            var options = new Dictionary<string, object>();
            switch (bin.bits)
            {
            case 64:
                options[ProcessorOption.Endianness] = "be";
                options[ProcessorOption.WordSize] = 64;
                return new MipsBe64Architecture(null, "", options);
            case 32:
                options[ProcessorOption.Endianness] = "be";
                options[ProcessorOption.WordSize] = 32;
                return new MipsBe32Architecture(null, "", options);
            case 16:
                // wut?
                options[ProcessorOption.Endianness] = "be";
                options[ProcessorOption.WordSize] = 32;
                options[ProcessorOption.InstructionSet] = "nano";
                return new MipsBe64Architecture(null, "", options);
            default:
                Log.print_err("unsupported bit width %u for architecture %s", bin.bits, bin.arch_str);
                Environment.Exit(1);
                return default!;
            }
        }

        public static int nucleus_disasm_bb_mips(Binary bin, DisasmSection dis, BB bb)
        {
            bool ret, jmp, cflow, indir, cond, call, nop, only_nop, priv, trap;
            int ndisassembled;
  MipsInstruction last_cflow = null;


  var offset = bb.start - dis.section.vma;
  if((bb.start < dis.section.vma) || (offset >= dis.section.size)) {
    Log.print_err("basic block address points outside of section '{0}'", dis.section.name);
    return -1;
  }
  var arch = bin.reko_arch;
  if (!arch.TryParseAddress(dis.section.vma.ToString("X"), out var addrSection))
  {
    Log.print_err("Lolwut: {0:X}", dis.section.vma);
  }

  var mem = new ByteMemoryArea(addrSection, dis.section.bytes);
  var pc = arch.CreateImageReader(mem, (long)offset);
  bb.end = bb.start;
  bb.section = dis.section;
  ndisassembled = 0;
  only_nop = false;
  foreach (MipsInstruction cs_ins in arch.CreateDisassembler(pc)) {
    if(cs_ins.Mnemonic == Mnemonic.illegal) {
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
    if(last_cflow == null && !only_nop && nop) break;
    if(last_cflow == null && only_nop && !nop) break;

    ndisassembled++;

    bb.end += (uint) cs_ins.Length;
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

    var ins = bb.insns[^1];
    //ins.Mnemonic         = cs_ins.Mnemonic;
    //ins.start      = cs_ins.address;
    //ins.size       = cs_ins.size;
    //ins.mnem       = std::string(cs_ins.mnemonic);
    //ins.op_str     = std::string(cs_ins.op_str);
    //ins.privileged = priv;
    //ins.trap       = trap;
    //if(nop)   ins.flags |= Instruction.INS_FLAG_NOP;
    //if(ret)   ins.flags |= Instruction.INS_FLAG_RET;
    //if(jmp)   ins.flags |= Instruction.INS_FLAG_JMP;
    //if(cond)  ins.flags |= Instruction.INS_FLAG_COND;
    //if(cflow) ins.flags |= Instruction.INS_FLAG_CFLOW;
    //if(call)  ins.flags |= Instruction.INS_FLAG_CALL;
    //if(indir) ins.flags |= Instruction.INS_FLAG_INDIRECT;

    //for(i = 0; i < cs_ins.detail.mips.op_count; i++) {
    //  cs_op = &cs_ins.detail.mips.operands[i];
    //  ins.operands.push_back(Operand());
    //  op = &ins.operands.back();
    //  op.type = cs_to_nucleus_op_type(cs_op.type);
    //  if(op.type == Operand::OP_TYPE_IMM) {
    //    op.mips_value.imm = cs_op.imm;
    //  } else if(op.type == Operand::OP_TYPE_REG) {
    //    op.mips_value.reg = (mips_reg)cs_op.reg;
    //  } else if(op.type == Operand::OP_TYPE_MEM) {
    //    op.mips_value.mem.base = cs_op.mem.base;
    //    op.mips_value.mem.disp = cs_op.mem.disp;
    //    if(cflow) ins.flags |= Instruction::INS_FLAG_INDIRECT;
    //  }
    //}

    //if(cflow) {
    //  for(j = 0; j < cs_ins.detail.mips.op_count; j++) {
    //    cs_op = &cs_ins.detail.mips.operands[j];
    //    if(cs_op.type == MIPS_OP_IMM) {
    //      ins.target = cs_op.imm;
    //    }
    //  }
    //}

    /* end of basic block occurs after delay slot of cflow instructions */
    if(last_cflow is not null) {
      //cs_ins.flags = last_cflow.flags;
      //ins.target = last_cflow.target;
      //last_cflow.flags = 0;
      break;
    }
    if(cflow) {
      last_cflow = cs_ins;
    }
  }

  if (ndisassembled == 0) {
    bb.invalid = true;
    bb.end += 1; /* ensure forward progress */
  }

  return ndisassembled;
        }
    }
}
