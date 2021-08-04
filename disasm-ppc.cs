
using Reko.Arch.PowerPC;
using Reko.Core;
using Reko.Core.Machine;
using Reko.Core.Memory;
using System.Diagnostics;

namespace Nucleus
{ 
    public class PowerPC {
static bool
is_cs_nop_ins(PowerPcInstruction ppc)
{

  switch(ppc.Mnemonic) {
  //case Mnemonic.NOP:
    /* nop */
    //return true;
  case Mnemonic.ori:
    /* ori r0,r0,r0 */
    if((ppc.Operands.Length == 3)
       && (ppc.Operands[0] is RegisterOperand r0)
       && (ppc.Operands[1] is RegisterOperand r1)
       && (ppc.Operands[2] is RegisterOperand r2)
       && (r0.Register.Number == 0)
       && (r1.Register.Number == 0)
       && (r2.Register.Number == 0)) {
      return true;
    }
    return false;
  default:
    return false;
  }
}


static bool
is_cs_trap_ins(PowerPcInstruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.tw:
  case Mnemonic.twi:
    return true;
  default:
    return false;
  }
}


static bool
is_cs_cflow_ins(PowerPcInstruction ins)
{
  /* XXX: Capstone does not provide information for all generic groups
   * for ppc instructions, unlike x86, so we have to do it manually.
   * Once this is implemented, it will suffice to check for the following groups:
   * CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET */

  switch(ins.Mnemonic) {
  case Mnemonic.b:
  //case Mnemonic.ba:
  case Mnemonic.bc:
  //case Mnemonic.bca:
  case Mnemonic.bl:
  //case Mnemonic.bla:
  case Mnemonic.blr:
  case Mnemonic.bcl:
  //case Mnemonic.bcla:
  //case Mnemonic.bctr:
  case Mnemonic.bctrl:
  case Mnemonic.bcctr:
  case Mnemonic.bcctrl:
    return true;
  default:
    return false;
  }
}


static bool
is_cs_call_ins(PowerPcInstruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.bl:
  //case Mnemonic.BLA:
    return true;
  default:
    return false;
  }
}


static bool
is_cs_ret_ins(PowerPcInstruction ppc)
{
  switch(ppc.Mnemonic) {
  case Mnemonic.blr:
    return true;
  //case Mnemonic.bclr:
  //  Debug.Assert(ppc.Operands.Length  >= 2);
  //  Debug.Assert(ppc.Operands[0] is ImmediateOperand);
  //  Debug.Assert(ppc.Operands[1] is ImmediateOperand);
  //  bo = ((ImmediateOperand)ppc.Operands[0]).Value.ToInt32();
  //  bi = ((ImmediateOperand)ppc.Operands[1]).Value.ToInt32();
  //  if (bo == 20 && bi == 0) {
  //    return true;
  //  }
  default:
    return false;
  }
}


static bool
is_cs_unconditional_jmp_ins(PowerPcInstruction ppc)
{
  int bo, bi;
  switch(ppc.Mnemonic) {
  case Mnemonic.b:
  //case Mnemonic.BA:
  //case Mnemonic.bctr:
    return true;
  case Mnemonic.bcctr:
    Debug.Assert(ppc.Operands.Length >= 2);
    Debug.Assert(ppc.Operands[0] is ImmediateOperand);
    Debug.Assert(ppc.Operands[1] is ImmediateOperand);
    bo = ((ImmediateOperand)ppc.Operands[0]).Value.ToInt32();
    bi = ((ImmediateOperand)ppc.Operands[1]).Value.ToInt32();
    if (bo == 20 && bi == 0) {
      return true;
    }
    return false;
  default:
    return false;
  }
}


        static bool
        is_cs_conditional_cflow_ins(PowerPcInstruction ins)
        {
            return (ins.InstructionClass & InstrClass.ConditionalTransfer) ==
                InstrClass.ConditionalTransfer;
        }


static bool
is_cs_privileged_ins(PowerPcInstruction ins)
{
  switch(ins.Mnemonic) {
  case Mnemonic.dcbi:
  case Mnemonic.mfmsr:
  //case Mnemonic.mfsr:
  //case Mnemonic.mfsrin:
  case Mnemonic.mtmsr:
  //case Mnemonic.mtsr:
  //case Mnemonic.mtsrin:
  case Mnemonic.rfi:
  //case Mnemonic.tlbia:
  case Mnemonic.tlbie:
  case Mnemonic.tlbsync:
    return true;
  default:
    return false;
  }
}


static bool
is_cs_indirect_ins(PowerPcInstruction ins)
{
  switch(ins.Mnemonic) {
  //case Mnemonic.bctr:
  case Mnemonic.bctrl:
  case Mnemonic.bcctr:
  case Mnemonic.bcctrl:
    return true;
  default:
    return false;
  }
}


//static OpT
//cs_to_nucleus_op_type(ppc_op_type op)
//{
//  switch(op) {
//  case PPC_OP_REG:
//    return Operand::OP_TYPE_REG;
//  case PPC_OP_IMM:
//    return Operand::OP_TYPE_IMM;
//  case PPC_OP_MEM:
//    return Operand::OP_TYPE_MEM;
//  case PPC_OP_CRX:
//  case PPC_OP_INVALID:
//  default:
//    return Operand::OP_TYPE_NONE;
//  }
//}


public static bool
nucleus_disasm_bb_ppc(Binary bin, DisasmSection dis, BB bb)
{
            return false;
#if NYI
            bool init, ret, jmp, cflow, indir, cond, call, nop, only_nop, priv, trap;
            int ndisassembled;
  cs_mode cs_mode_flags;
  cs_ppc_op *cs_op;
  EndianImageReader pc;
  uint64_t pc_addr, offset;
  size_t i, j, n;

  init   = 0;

  switch(bin.bits) {
  case 64:
    cs_mode_flags = (cs_mode)(CS_MODE_BIG_ENDIAN | CS_MODE_64);
    break;
  case 32:
    cs_mode_flags = (cs_mode)(CS_MODE_BIG_ENDIAN);
    break;
  default:
    Log.print_err("unsupported bit width %u for architecture %s", bin.bits, bin.arch_str.c_str());
    goto fail;
  }

  if(cs_open(CS_ARCH_PPC, cs_mode_flags, &cs_dis) != CS_ERR_OK) {
    print_err("failed to initialize libcapstone");
    goto fail;
  }
  init = true;
  cs_option(cs_dis, CS_OPT_DETAIL, CS_OPT_ON);

  cs_ins = cs_malloc(cs_dis);
  if(!cs_ins) {
    print_err("out of memory");
    goto fail;
  }

  offset = bb.start - dis.section.vma;
  if((bb.start < dis.section.vma) || (offset >= dis.section.size)) {
    Log.print_err("basic block address points outside of section '{0}'", dis.section.name);
    goto fail;
  }

  pc = dis.section.bytes + offset;
  n = dis.section.size - offset;
  pc_addr = bb.start;
  bb.end = bb.start;
  bb.section = dis.section;
  ndisassembled = 0;
  only_nop = false;
  var arch = new PowerPcBe64Architecture(null, "ppcbe64", null);
  var cs_dis = arch.CreateDisassemblerImpl(pc).GetEnumerator();
  while (cs_dis.MoveNext()) {
    var cs_ins = cs_dis.Current;
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

    if(ndisassembled == 0 && nop) only_nop = 1; /* group nop instructions together */
    if(!only_nop && nop) break;
    if(only_nop && !nop) break;

    ndisassembled++;

    bb.end += cs_ins.Length;
    var ins = new Instruction();
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

    ins.id = cs_ins.Mnemonic;
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

    for(i = 0; i < cs_ins.detail.ppc.op_count; i++) {
      cs_op = &cs_ins.detail.ppc.operands[i];
      ins.operands.Add(new Operand());
      op = &ins.operands.back();
      op.type = cs_to_nucleus_op_type(cs_op.type);
      if(op.type == Operand::OP_TYPE_IMM) {
        op.ppc_value.imm = cs_op.imm;
      } else if(op.type == Operand::OP_TYPE_REG) {
        op.ppc_value.reg = (ppc_reg)cs_op.reg;
      } else if(op.type == Operand::OP_TYPE_MEM) {
        op.ppc_value.mem.@base = cs_op.mem.@base;
        op.ppc_value.mem.disp = cs_op.mem.disp;
      }
    }

    if(cflow) {
      for(j = 0; j < cs_ins.detail.ppc.op_count; j++) {
        cs_op = &cs_ins.detail.ppc.operands[j];
        if(cs_op.type == PPC_OP_IMM) {
          ins.target = cs_op.imm;
        }
      }
    }

    /* XXX: Some relocations entries point to symbols in sections
     * that are ignored by Nucleus, e.g. calls to external functions.
     * We ignore such calls directly at disasm level. */
    if(call && ins.target == ins.start) {
      ins.flags &= ~Instruction::INS_FLAG_CALL;
      ins.flags &= ~Instruction::INS_FLAG_CFLOW;
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

  return true;

  fail:
    return false;
#endif
}}}
