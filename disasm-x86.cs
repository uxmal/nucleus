using Reko.Arch.X86;
using Reko.Core;
using Reko.Core.Machine;
using Reko.Core.Memory;
using System;
using System.Collections.Generic;

namespace Nucleus
{
    using RekoInstruction = Reko.Arch.X86.X86Instruction;
    using MemoryOperand = Reko.Arch.X86.MemoryOperand;
    using Mnemonic = Reko.Arch.X86.Mnemonic;

    public partial class X86 {

        static bool is_cs_nop_ins(RekoInstruction ins)
        {
            switch (ins.Mnemonic) {
            case Mnemonic.nop:
            case Mnemonic.fnop:
                return true;
            default:
                return false;
            }
        }


        static bool
        is_cs_semantic_nop_ins(RekoInstruction ins)
        {

            /* XXX: to make this truly platform-independent, we need some real
             * semantic analysis, but for now checking known cases is sufficient */

            switch (ins.Mnemonic) {
            case Mnemonic.mov:
                /* mov reg,reg */
                return (ins.Operands[0] is RegisterOperand rr1
                   && ins.Operands[1] is RegisterOperand rr2
                   && rr1.Register == rr2.Register);
            case Mnemonic.xchg:
                /* xchg reg,reg */
                return (ins.Operands[0] is RegisterOperand xr1
                   && ins.Operands[1] is RegisterOperand xr2
                   && xr1.Register == xr2.Register);
            case Mnemonic.lea:
                /* lea    reg,[reg + 0x0] */
                if ((ins.Operands[0] is RegisterOperand l1d)
                   && (ins.Operands[1] is MemoryOperand l1m)
                   && (l1m.SegOverride == RegisterStorage.None)
                   && (l1m.Base == l1d.Register)
                   && (l1m.Index == RegisterStorage.None)
                   /* mem.scale is irrelevant since index is not used */
                   && (l1m.Offset is null || l1m.Offset.IsZero)) {
                    return true;
                }
                /* lea    reg,[reg + eiz*x + 0x0] */
                if (
                      (ins.Operands[0] is RegisterOperand l2d)
                   && (ins.Operands[1] is MemoryOperand l2m)
                   && (l2m.SegOverride == RegisterStorage.None)
                   && (l2m.Base == RegisterStorage.None)
                   && (l2m.Index == l2d.Register)
                   && (l2m.Scale == 1)
                   && (l2m.Offset is null || l2m.Offset.IsZero)) {
                    return true;
                }
                return false;
            default:
                return false;
            }
        }

        static bool
        is_cs_trap_ins(RekoInstruction ins)
        {
            switch (ins.Mnemonic) {
            //case Mnemonic.int3:
            case Mnemonic.ud2:
                return true;
            default:
                return false;
            }
        }


        static bool
        is_cs_cflow_group(InstrClass g)
        {
            return (g & InstrClass.Transfer) != 0;
        }


        static bool
        is_cs_cflow_ins(RekoInstruction ins)
        {
            return is_cs_cflow_group(ins.InstructionClass);
        }


        static bool
        is_cs_call_ins(RekoInstruction ins)
        {
            switch (ins.Mnemonic) {
            case Mnemonic.call:
                return true;
            default:
                return false;
            }
        }


        static bool
        is_cs_ret_ins(RekoInstruction ins)
        {
            switch (ins.Mnemonic) {
            case Mnemonic.ret:
            case Mnemonic.retf:
                return true;
            default:
                return false;
            }
        }


        static bool
        is_cs_unconditional_jmp_ins(RekoInstruction ins)
        {
            switch (ins.Mnemonic) {
            case Mnemonic.jmp:
                return true;
            default:
                return false;
            }
        }


        static bool
        is_cs_conditional_cflow_ins(RekoInstruction ins)
        {
            switch (ins.Mnemonic) {
            case Mnemonic.jnc:
            case Mnemonic.ja:
            case Mnemonic.jbe:
            case Mnemonic.jc:
            case Mnemonic.jcxz:
            case Mnemonic.jecxz:
            case Mnemonic.jz:
            case Mnemonic.jge:
            case Mnemonic.jg:
            case Mnemonic.jle:
            case Mnemonic.jl:
            case Mnemonic.jnz:
            case Mnemonic.jno:
            case Mnemonic.jpo:
            case Mnemonic.jns:
            case Mnemonic.jo:
            case Mnemonic.jpe:
            case Mnemonic.jrcxz:
            case Mnemonic.js:
                return true;
            case Mnemonic.jmp:
            default:
                return false;
            }
        }


        static bool
        is_cs_privileged_ins(RekoInstruction ins)
        {
            switch (ins.Mnemonic) {
            case Mnemonic.hlt:
            case Mnemonic.@in:
            case Mnemonic.insb:
            case Mnemonic.ins:
            case Mnemonic.@out:
            case Mnemonic.outsb:
            case Mnemonic.outs:
            case Mnemonic.rdmsr:
            case Mnemonic.wrmsr:
            case Mnemonic.rdpmc:
            case Mnemonic.rdtsc:
            case Mnemonic.lgdt:
            case Mnemonic.lldt:
            case Mnemonic.ltr:
            case Mnemonic.lmsw:
            case Mnemonic.clts:
            case Mnemonic.invd:
            case Mnemonic.invlpg:
            case Mnemonic.wbinvd:
                return true;
            default:
                return false;
            }
        }


        static Operand.OperandType
        cs_to_nucleus_op_type(MachineOperand op)
        {
            switch (op) {
            case RegisterOperand _:
                return Operand.OperandType.OP_TYPE_REG;
            case ImmediateOperand _:
                return Operand.OperandType.OP_TYPE_IMM;
            case MemoryOperand _:
                return Operand.OperandType.OP_TYPE_MEM;
            default:
                return Operand.OperandType.OP_TYPE_NONE;
            }
        }

        public static IProcessorArchitecture create_disassembler(Binary bin)
        {
            var options = new Dictionary<string, object>();
            switch (bin.bits)
            {
            case 64:
                return new X86ArchitectureFlat64(null, "", options);
            case 32:
                return new X86ArchitectureFlat32(null, "", options);
            case 16:
                return new X86ArchitectureReal(null, "", options);
            default:
                Log.print_err("unsupported bit width {0} for architecture {1}", bin.bits, bin.arch_str);
                Environment.Exit(1);
                return null;
            }
        }


        public static bool nucleus_disasm_bb_x86(Binary bin, DisasmSection dis, BB bb)
        {
            bool ret, jmp, cflow, cond, call, nop, only_nop, priv, trap;
  int ndisassembled;
  ulong pc_addr, offset;

            var arch = bin.reko_arch;

  offset = bb.start - dis.section.vma;
  if((bb.start < dis.section.vma) || (offset >= dis.section.size)) {
    Log.print_err("basic block address points outside of section '{0}'", dis.section.name);
    goto fail;
  }
    if (!arch.TryParseAddress(dis.section.vma.ToString("X"), out var addrSection))
    {
        Log.print_err("Lolwut: {0:X}", dis.section.vma);
    }
  var mem = new ByteMemoryArea(addrSection, dis.section.bytes);
  var pc = arch.CreateImageReader(mem, (long)offset);
  ulong n = dis.section.size - offset;
  pc_addr = bb.start;
  bb.end = bb.start;
  bb.section = dis.section;
  ndisassembled = 0;
  only_nop = false;
  var dasm = arch.CreateDisassembler(pc) //$HOw did I know that, huh.
                .GetEnumerator();
  while (dasm.MoveNext()) {
    var cs_ins = (X86Instruction) dasm.Current;
    if(cs_ins.Mnemonic == Mnemonic.illegal) {
      bb.invalid = true;
      bb.end += 1;
      break;
    }
    if(cs_ins.Length == 0) {
      break;
    }

    trap  = is_cs_trap_ins(cs_ins);
    nop   = is_cs_nop_ins(cs_ins) 
            /* Visual Studio sometimes places semantic nops at the function start */
            || (is_cs_semantic_nop_ins(cs_ins) && (bin.type != Binary.BinaryType.BIN_TYPE_PE))
            /* Visual Studio uses int3 for padding */
            || (trap && (bin.type == Binary.BinaryType.BIN_TYPE_PE));
    ret   = is_cs_ret_ins(cs_ins);
    jmp   = is_cs_unconditional_jmp_ins(cs_ins) || is_cs_conditional_cflow_ins(cs_ins);
    cond  = is_cs_conditional_cflow_ins(cs_ins);
    cflow = is_cs_cflow_ins(cs_ins);
    call  = is_cs_call_ins(cs_ins);
    priv  = is_cs_privileged_ins(cs_ins);

    if(ndisassembled == 0 && nop) only_nop = true; /* group nop instructions together */
    if(!only_nop && nop) break;
    if(only_nop && !nop) break;

    ndisassembled++;

    bb.end += (uint)cs_ins.Length;
    var ins = new Instruction();
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
    if(nop)   ins.flags |= Instruction::INS_FLAG_NOP;
    if(ret)   ins.flags |= Instruction::INS_FLAG_RET;
    if(jmp)   ins.flags |= Instruction::INS_FLAG_JMP;
    if(cond)  ins.flags |= Instruction::INS_FLAG_COND;
    if(cflow) ins.flags |= Instruction::INS_FLAG_CFLOW;
    if(call)  ins.flags |= Instruction::INS_FLAG_CALL;

    for(i = 0; i < cs_ins.detail.x86.op_count; i++) {
      cs_op = &cs_ins.detail.x86.operands[i];
      ins.operands.Add(new Operand());
      op = &ins.operands.back();
      op.type = cs_to_nucleus_op_type(cs_op.type);
      op.size = cs_op.size;
      if(op.type == Operand::OP_TYPE_IMM) {
        op.x86_value.imm = cs_op.imm;
      } else if(op.type == Operand::OP_TYPE_REG) {
        op.x86_value.reg = cs_op.reg;
        if(cflow) ins.flags |= Instruction::INS_FLAG_INDIRECT;
      } else if(op.type == Operand::OP_TYPE_FP) {
        op.x86_value.fp = 0;
      } else if(op.type == Operand::OP_TYPE_MEM) {
        op.x86_value.mem.segment = cs_op.mem.segment;
        op.x86_value.mem.base    = cs_op.mem.base;
        op.x86_value.mem.index   = cs_op.mem.index;
        op.x86_value.mem.scale   = cs_op.mem.scale;
        op.x86_value.mem.disp    = cs_op.mem.disp;
        if(cflow) ins.flags |= Instruction::INS_FLAG_INDIRECT;
      }
    }

    for(i = 0; i < cs_ins.detail.groups_count; i++) {
      if(is_cs_cflow_group(cs_ins.detail.groups[i])) {
        for(j = 0; j < cs_ins.detail.x86.op_count; j++) {
          cs_op = &cs_ins.detail.x86.operands[j];
          if(cs_op.type == X86_OP_IMM) {
            ins.target = cs_op.imm;
          }
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
    bb.end += 1; /* ensure forward progress */
  }

  return true;

fail:
  return false;

cleanup:
  return false;
        }
    }
}