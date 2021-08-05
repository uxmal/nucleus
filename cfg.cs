using Reko.Core;
using Reko.Core.Machine;
using Reko.Core.Memory;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

#pragma warning disable IDE1006

namespace Nucleus
{
    public partial class CFG
    {
        public void print_functions(TextWriter @out)
        {
            foreach (var f in this.functions) {
                f.print(@out);
            }
        }

        public void print_function_summaries(TextWriter @out)
        {
            foreach (var f in this.functions) {
                f.print_summary(@out);
            }
        }

        void mark_addrtaken(ulong addr)
        {
            if (this.start2bb.TryGetValue(addr, out BB cc))
            {
                if (!cc.addrtaken)
                {
                    cc.addrtaken = true;
                    Log.verbose(3, "marking addrtaken bb@0x{0:X16}", cc.start);
                }
            }
        }

void analyze_addrtaken_ppc()
{
#if NYI
            /* Instructions can get reordered, so we emulate the ISA subset relevant for the patterns below,
             * clearing the intermediate register values with with -1 if the result is irrelevant or undefined. */
            ulong [] registers = new ulong[32];
  Array.Fill(registers, ~0u);
  foreach (var kv in  this.start2bb) {
    var bb = kv.Value;
    foreach (var ins in bb.insns) {
      if(ins.Operands.Length < 2) {
        continue;
      }
      /* Pattern #1 (32-bit)
       * Load the address from its word halves. Following variants are supported:
       * - Using addis/addi (gcc):
       *     lis    rN, .L@ha
       *     addi   rN, rN, L@l
       * - Using addis/ori:
       *     lis    rN, .L@ha
       *     ori    rN, rN, .L@l */
      if(ins.MnemonicAsInteger == (int) Reko.Arch.PowerPC.Mnemonic.addis) {
        int dst = ((RegisterOperand)ins.Operands[0]).Register.Number;
        ulong imm = ((ImmediateOperand)ins.Operands[2]).Value.ToUInt32();
        Debug.Assert(dst < 32);
        registers[dst] = imm << 16;
      }
      else if (ins.MnemonicAsInteger == (int)Reko.Arch.PowerPC.Mnemonic.addi ||
               ins.MnemonicAsInteger == (int)Reko.Arch.PowerPC.Mnemonic.ori) {
        int lhs = ((RegisterOperand)ins.Operands[1]).Register.Number;
        ulong rhs = ((ImmediateOperand)ins.Operands[2]).Value.ToUInt32();
        Debug.Assert(lhs < 32);
        if (registers[lhs] != ~0u) {
          mark_addrtaken(registers[lhs] | rhs);
        }
      }
      else if (ins.Operands[0].type == Operand.OP_TYPE_REG
           && ins.Operands[0].ppc_value.reg >= PPC_REG_R0
           && ins.Operands[0].ppc_value.reg <= PPC_REG_R31) {
        uint dst = ins.Operands[0].ppc_value.reg - PPC_REG_R0;
        registers[dst] = ~0u;
      }
    }
  }
#endif
}


void 
analyze_addrtaken_x86()
{
#if NYI
            foreach (var kv in this.start2bb) {
    var bb = kv.Value;
    foreach (var ins in bb.insns) {
      if(ins.Operands.Length < 2) {
        continue;
      }
      var op_dst = ins.Operands[0];
      var op_src = ins.Operands[1];
      if(((op_dst is RegisterOperand) || (op_dst is Reko.Arch.X86.MemoryOperand))) {
        if (op_src is ImmediateOperand imm)
            mark_addrtaken(imm.Value.ToUInt64());
        else if (op_src is AddressOperand addr)
            mark_addrtaken(addr.Address.ToLinear());
      }
    }
  }
#endif
}




        void
        analyze_addrtaken()
        {
            Log.verbose(1, "starting address-taken analysis");

            switch (this.binary.arch)
            {
            case Binary.BinaryArch.ARCH_PPC:
                analyze_addrtaken_ppc();
                break;
            case Binary.BinaryArch.ARCH_X86:
                analyze_addrtaken_x86();
                break;
            default:
                Log.print_warn("address-taken analysis not yet supported for {0}", this.binary.arch_str);
                break;
            }

            Log.verbose(1, "address-taken analysis complete");
        }


        void mark_jmptab_as_data(ulong start, ulong end)
        {
            ulong addr;

            BB cc = null;
            for (addr = start; addr < end; addr++)
            {
                var bb = this.get_bb(addr, out var _);
                if (bb is null) continue;
                if (bb != cc)
                {
                    bb.invalid = true;
                    unlink_bb(bb);
                    bad_bbs[bb.start] = bb;
                    cc = bb;
                }
            }
        }


void
find_switches_aarch64()
{
#if NYI
            BB bb, cc;
    Edge conflict_edge;
    Section target_sec;
    int scale;
    uint offset;
    ulong jmptab_addr, jmptab_idx, jmptab_end;
    ulong case_addr, case_addr_abs, case_addr_rel;

    /* Instructions can get reordered, so we emulate the ISA subset relevant for the patterns below,
     * clearing the intermediate register values with with -1 if the result is irrelevant or undefined. */
    ulong [] registers = new ulong[32];
    Array.Fill(registers, ~0ul);

    /* Trying to determine the size of the jump table entries by looking
     * at the instruction immediately following the described pattern.
     * - scale <= 0: signals the scale could not be determined.
     * - scale == 0: signals the current instruction may tell the scale. */
    scale = -1;

    foreach (var kv in this.start2bb)
    {
        bb = kv.Value;
        jmptab_addr = 0;
        target_sec = null;
        /* If this BB ends in an indirect jmp, scan the BB for what looks like
         * instructions loading a target from a jump table */
        if (bb.insns[^1].edge_type() == Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT)
        {
            target_sec = bb.section;
            foreach (var ins in bb.insns)
            {
                if (ins.Operands.Length < 2)
                {
                    continue;
                }
                /* Pattern #1
                 * Loading jump table address relative to the `pc` register.
                 *   adrp    x0, #:pg_hi21:.L
                 *   add     x0, x0, #:lo12:.L
                 *   ldr/ldrh/ldrb ...
                 */

                /* detect scale */
                if (scale == 0)
                {
                    if (ins.MnemonicAsInteger == (uint)Reko.Arch.Arm.AArch64.Mnemonic.ldrb)
                    {
                        scale = 1;
                    }
                    else if (ins.MnemonicAsInteger == (uint)Reko.Arch.Arm.AArch64.Mnemonic.ldrh)
                    {
                        scale = 2;
                    }
                    else if (ins.MnemonicAsInteger == (uint)Reko.Arch.Arm.AArch64.Mnemonic.ldr
                     && Reg(ins.Operands[0]) >= ARM64_REG_W0
                     && Reg(ins.Operands[0]) <= ARM64_REG_W28)
                    {
                        scale = 4;
                    }
                    else if (ins.id == Reko.Arch.Arm.AArch64.Mnemonic.LDR
                     && ins.Operands[0].aarch64_value.reg >= ARM64_REG_X0
                     && ins.Operands[0].aarch64_value.reg <= ARM64_REG_X28)
                    {
                        scale = 8;
                    }
                }
                /* detect jump-table address loading */
                if (ins.id == Reko.Arch.Arm.AArch64.Mnemonic.adrp)
                {
                    int64_t dst = ins.Operands[0].aarch64_value.reg - ARM64_REG_X0;
                    int64_t imm = ins.Operands[1].aarch64_value.imm;
                    assert(dst < 29);
                    registers[dst] = imm;
                }
                else if (ins.id == Reko.Arch.Arm.AArch64.Mnemonic.ADD
                     && ins.Operands[1].type == Operand::OP_TYPE_REG
                     && ins.Operands[2].type == Operand::OP_TYPE_IMM)
                {
                    int64_t dst = ins.Operands[0].aarch64_value.reg - ARM64_REG_X0;
                    int64_t lhs = ins.Operands[1].aarch64_value.reg - ARM64_REG_X0;
                    int64_t rhs = ins.Operands[2].aarch64_value.imm & 0xFFF;
                    assert(dst < 29 && lhs < 29);
                    registers[dst] = registers[lhs] + rhs;
                    if (registers[dst] != -1)
                    {
                        jmptab_addr = (uint64_t)(registers[dst]);
                        scale = 0;
                    }
                }
                else if (ins.Operands[0].type == Operand::OP_TYPE_REG
                     && ins.Operands[0].aarch64_value.reg >= ARM64_REG_X0
                     && ins.Operands[0].aarch64_value.reg <= ARM64_REG_X28)
                {
                    int64_t dst = ins.Operands[0].aarch64_value.reg - ARM64_REG_X0;
                    registers[dst] = -1;
                }
            }
        }

        if (jmptab_addr != 0 && scale > 0)
        {
            jmptab_end = 0;
            foreach (var sec in this.binary.sections)
            {
                if (sec.contains(jmptab_addr))
                {
                    Log.verbose(4, "parsing jump table at 0x{0:X16} (jump at 0x{1:X16})",
                            jmptab_addr, bb.insns[^1].Address);
                    jmptab_idx = jmptab_addr - sec.vma;
                    jmptab_end = jmptab_addr;
                    var jmptab8 =  (EndianImageReader)&sec.bytes[jmptab_idx];
                    var jmptab16 = (EndianImageReader)&sec.bytes[jmptab_idx];
                    var jmptab32 = (EndianImageReader)&sec.bytes[jmptab_idx];
                    var jmptab64 = (EndianImageReader)&sec.bytes[jmptab_idx];
                    while (true)
                    {
                        if ((jmptab_idx + (uint) scale) > sec.size) break;
                        jmptab_end += (uint)scale;
                        jmptab_idx += (uint)scale;
                        switch (scale)
                        {
                        case 1:
                            case_addr_abs = uint8_t(*jmptab8++);
                            break;
                        case 2:
                            case_addr_abs = uint16_t(read_le_i16(jmptab16++));
                            break;
                        case 4:
                            case_addr_abs = uint32_t(read_le_i32(jmptab32++));
                            break;
                        case 8:
                            case_addr_abs = uint64_t(read_le_i64(jmptab64++));
                            break;
                        default:
                            Log.print_warn("Unexpected scale factor in memory operand: %d", scale);
                            case_addr_abs = 0;
                            break;
                        }
                        case_addr_rel = case_addr_abs + jmptab_addr;
                        if (target_sec.contains(case_addr_abs))
                        {
                            case_addr = case_addr_abs;
                        }
                        else if (target_sec.contains(case_addr_rel))
                        {
                            case_addr = case_addr_rel;
                        }
                        else
                        {
                            break;
                        }
                        /* add target block */
                        cc = this.get_bb(case_addr, &offset);
                        if (!cc) break;
                        conflict_edge = NULL;
                        for (auto & e: cc.ancestors)
                        {
                            if (e.is_switch)
                            {
                                conflict_edge = &e;
                                break;
                            }
                        }
                        if (conflict_edge && (conflict_edge.jmptab <= jmptab_addr))
                        {
                            verbose(3, "removing switch edge 0x%016jx . 0x%016jx (detected overlapping jump table or case)",
                                    conflict_edge.src.insns[^1].start, case_addr);
                            unlink_edge(conflict_edge.src, cc);
                            conflict_edge = NULL;
                        }
                        if (!conflict_edge)
                        {
                            verbose(3, "adding switch edge 0x%016jx . 0x%016jx", bb.insns[^1].start, case_addr);
                            link_bbs(Edge::EDGE_TYPE_JMP_INDIRECT, bb, case_addr, jmptab_addr);
                        }
                    }
                    break;
                }
            }

            if (jmptab_addr && jmptab_end)
            {
                mark_jmptab_as_data(jmptab_addr, jmptab_end);
            }
        }
    }
#endif
}


void
find_switches_arm()
{
#if NYI
            int scale = 4;
    ulong jmptab_addr, jmptab_idx, jmptab_end, case_addr;

    foreach (var bb in this.start2bb.Values)
    {
        jmptab_addr = 0;
        Section target_sec = null;
        /* If this BB ends in an indirect jmp, scan the BB for what looks like
         * instructions loading a target from a jump table */
        if (bb.insns[^1].edge_type() == Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT)
        {
            target_sec = bb.section;
            for (int rit = bb.insns.Count - 1; rit >= 0; --rit)
            {
                var ins = bb.insns[rit];
                if (ins.Operands.Length < 2)
                {
                    continue;
                }
                /* Pattern #1
                 * Load the address relative to `pc`. Following variants are supported:
                 * - Using add (clang):
                 *     add     rN, pc, .L
                 * - Using adr (clang, shorthand):
                 *     adr     rN, .L
                 * - Using ldrls (gcc)
                 *     ldrls   pc, [pc, rN, lsl#2]
                 */
                if (ins.MnemonicAsInteger == (int)Reko.Arch.Arm.AArch32.Mnemonic.add &&
                   ins.Operands[1] is RegisterOperand reg &&
                   reg.Register.Number == 15 &&  // PC register
                   ins.Operands[2] is ImmediateOperand imm)
                {
                    jmptab_addr = (ins.Address.ToLinear() + 8) + (ulong)imm.Value.ToInt64();
                    break;
                }
                else if (ins.MnemonicAsInteger == (int)Reko.Arch.Arm.AArch32.Mnemonic.adr &&
                         ((RegisterOperand)ins.Operands[0]).Register.Number == 15) // PC register
                {
                    ulong immv = (ulong) ((ImmediateOperand)ins.Operands[1]).Value.ToInt64();
                    jmptab_addr = (ins.Address.ToLinear() + 8) + immv;
                    break;
                }
                else if (ins.MnemonicAsInteger == (int)Reko.Arch.Arm.AArch32.Mnemonic.ldr &&
                     && ins.Operands[0].arm_value.reg == ARM_REG_PC
                     && ins.Operands[1].arm_value.reg == ARM_REG_PC)
                {
                    jmptab_addr = (ins.start + 8);
                    break;
                }
            }
        }

        if (jmptab_addr != 0)
        {
            jmptab_end = 0;
            foreach (var sec in this.binary.sections)
            {
                if (sec.contains(jmptab_addr))
                {
                    Log.verbose(4, "parsing jump table at 0x%016jx (jump at 0x%016jx)",
                            jmptab_addr, bb.insns[^1].Address);
                    jmptab_idx = jmptab_addr - sec.vma;
                    jmptab_end = jmptab_addr;
                    var jmptab = (EndianImageReader)sec.bytes[jmptab_idx];
                    while (true)
                    {
                        if ((jmptab_idx + scale) > sec.size) break;
                        jmptab_end += scale;
                        jmptab_idx += scale;
                        case_addr = uint32_t(read_le_i32(jmptab++));
                        if (!case_addr) break;
                        if (!target_sec.contains(case_addr))
                        {
                            break;
                        }
                        else
                        {
                            cc = this.get_bb(case_addr, &offset);
                            if (!cc) break;
                            conflict_edge = NULL;
                            for (auto & e: cc.ancestors)
                            {
                                if (e.is_switch)
                                {
                                    conflict_edge = &e;
                                    break;
                                }
                            }
                            if (conflict_edge && (conflict_edge.jmptab <= jmptab_addr))
                            {
                                verbose(3, "removing switch edge 0x%016jx . 0x%016jx (detected overlapping jump table or case)",
                                        conflict_edge.src.insns[^1].start, case_addr);
                                unlink_edge(conflict_edge.src, cc);
                                conflict_edge = NULL;
                            }
                            if (!conflict_edge)
                            {
                                verbose(3, "adding switch edge 0x%016jx . 0x%016jx", bb.insns[^1].start, case_addr);
                                link_bbs(Edge::EDGE_TYPE_JMP_INDIRECT, bb, case_addr, jmptab_addr);
                            }
                        }
                    }
                    break;
                }
            }

            if (jmptab_addr && jmptab_end)
            {
                mark_jmptab_as_data(jmptab_addr, jmptab_end);
            }
        }
    }
#endif
}


void find_switches_mips()
{
#if NYI
            int scale;
    ulong jmptab_addr, jmptab_idx, jmptab_end, case_addr;

    /* Instructions can get reordered, so we emulate the ISA subset relevant for the patterns below,
     * clearing the intermediate register values with with -1 if the result is irrelevant or undefined. */
    ulong [] registers = new ulong[32];
    Array.Fill(registers, ~0ul);

    /* Assume the jump-table entries are the same width as the GPRs */
    scale = (int) this.binary.bits / 8;

    foreach (var bb in this.start2bb.Values)
    {
        jmptab_addr = 0;
        Section target_sec = null;
        /* If this BB ends in an indirect jmp, scan the BB for what looks like
         * instructions loading a target from a jump table */
        if (bb.insns[^1].edge_type() == Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT)
        {
            target_sec = bb.section;
            foreach (var ins in bb.insns)
            {
                if (ins.Operands.Length < 2)
                {
                    continue;
                }
                /* Pattern #1
                 * Load the address from its word halves. Following variants are supported:
                 * - MIPS / 32-bit / non-PIC (clang):
                 *     lui     $A, %hi(.L)
                 *     addiu   $A, $A, %lo(.L)
                 * - MIPS / 32-bit / non-PIC (gcc):
                 *     lui     $A, %hi(.L)
                 *     addu    $T, $A
                 *     lw      $T, %lo(.L)($T)
                 * - MIPS / 64-bit / non-PIC:
                 *     lui     $A, %highest(.L)
                 *     daddiu  $A, $A, %higher(.L)
                 *     dsll32  $A, $A, 0
                 *     lui     $B, %hi(.L)
                 *     daddiu  $B, $B, %lo(.L)
                 *     daddu   $A, $A, $B
                 */
                var mnem = ins.MnemonicAsInteger;
                if (mnem == (int) Reko.Arch.Mips.Mnemonic.lui)
                {
                    int64_t dst = ins.Operands[0].mips_value.reg - MIPS_REG_0;
                    int64_t imm = ins.Operands[1].mips_value.imm;
                    assert(dst < 32);
                    registers[dst] = imm << 16;
                }
                else if (mnem == (int) Reko.Arch.Mips.Mnemonic.addiu || 
                         mnem == (int) Reko.Arch.Mips.Mnemonic.daddiu)
                {
                    int dst = ((RegisterOperand)ins.Operands[0]).Register.Number;
                    int lhs = ins.Operands[1].mips_value.reg - MIPS_REG_0;
                    int64_t rhs = ins.Operands[2].mips_value.imm;
                    assert(dst < 32 && lhs < 32);
                    registers[dst] = registers[lhs] + rhs;
                    if (registers[dst] != -1)
                    {
                        jmptab_addr = (uint64_t)(registers[dst]);
                    }
                }
                else if (ins.id == Reko.Arch.Mips.Mnemonic.ADDU)
                {
                    int64_t dst = ins.Operands[0].mips_value.reg - MIPS_REG_0;
                    int64_t lhs = ins.Operands[1].mips_value.reg - MIPS_REG_0;
                    int64_t rhs = ins.Operands[2].mips_value.reg - MIPS_REG_0;
                    assert(dst < 32 && lhs < 32 && rhs < 32);
                    /* addu emulation is intentionally wrong. the goal is replacing:
                     * - `dst = jumptable + offset` => `dst = jumptable`
                     * - `dst = offset + jumptable` => `dst = jumptable` */
                    if (registers[lhs] != -1)
                    {
                        registers[dst] = registers[lhs];
                    }
                    else
                    {
                        registers[dst] = registers[rhs];
                    }
                }
                else if (ins.id == Reko.Arch.Mips.Mnemonic.LW)
                {
                    int64_t reg = ins.Operands[1].mips_value.mem.@base - MIPS_REG_0;
                    int64_t imm = ins.Operands[1].mips_value.mem.disp;
                    assert(reg < 32);
                    if (registers[reg] != -1)
                    {
                        jmptab_addr = (uint64_t)(registers[reg] + imm);
                    }
                }
                else if (ins.id == Reko.Arch.Mips.Mnemonic.DADDU)
                {
                    int64_t dst = ins.Operands[0].mips_value.reg - MIPS_REG_0;
                    int64_t lhs = ins.Operands[1].mips_value.reg - MIPS_REG_0;
                    int64_t rhs = ins.Operands[2].mips_value.reg - MIPS_REG_0;
                    assert(dst < 32 && lhs < 32 && rhs < 32);
                    registers[dst] = registers[lhs] + registers[rhs];
                    if (registers[dst] != -1)
                    {
                        jmptab_addr = (uint64_t)(registers[dst]);
                    }
                }
                else if (ins.id == Reko.Arch.Mips.Mnemonic.DSLL32 && ins.Operands[2].mips_value.reg == 0)
                {
                    int64_t dst = ins.Operands[0].mips_value.reg - MIPS_REG_0;
                    int64_t src = ins.Operands[1].mips_value.reg - MIPS_REG_0;
                    assert(dst < 32 && src < 32);
                    registers[dst] = src << 32;
                }
                else if (ins.Operands[0].type == Operand::OP_TYPE_REG
                     && ins.Operands[0].mips_value.reg >= MIPS_REG_0
                     && ins.Operands[0].mips_value.reg <= MIPS_REG_31)
                {
                    int64_t dst = ins.Operands[0].mips_value.reg - MIPS_REG_0;
                    registers[dst] = -1;
                }
            }
        }

        if (jmptab_addr != 0)
        {
            jmptab_end = 0;
            foreach (var sec in this.binary.sections)
            {
                if (sec.contains(jmptab_addr))
                {
                    Log.verbose(4, "parsing jump table at 0x%016jx (jump at 0x%016jx)",
                            jmptab_addr, bb.insns[^1].start);
                    jmptab_idx = jmptab_addr - sec.vma;
                    jmptab_end = jmptab_addr;
                    jmptab32 = (uint32_t*)&sec.bytes[jmptab_idx];
                    jmptab64 = (uint64_t*)&sec.bytes[jmptab_idx];
                    while (true)
                    {
                        if ((jmptab_idx + scale) > sec.size) break;
                        jmptab_end += scale;
                        jmptab_idx += scale;
                        switch (scale)
                        {
                        case 4:
                            case_addr = uint32_t(read_be_i32(jmptab32++));
                            break;
                        case 8:
                            case_addr = uint64_t(read_be_i64(jmptab64++));
                            break;
                        default:
                            print_warn("Unexpected scale factor in memory operand: %d", scale);
                            case_addr = 0;
                            break;
                        }
                        if (!case_addr) break;
                        if (!target_sec.contains(case_addr))
                        {
                            break;
                        }
                        else
                        {
                            cc = this.get_bb(case_addr, &offset);
                            if (!cc) break;
                            conflict_edge = NULL;
                            for (auto & e: cc.ancestors)
                            {
                                if (e.is_switch)
                                {
                                    conflict_edge = &e;
                                    break;
                                }
                            }
                            if (conflict_edge && (conflict_edge.jmptab <= jmptab_addr))
                            {
                                verbose(3, "removing switch edge 0x%016jx . 0x%016jx (detected overlapping jump table or case)",
                                        conflict_edge.src.insns[^1].start, case_addr);
                                unlink_edge(conflict_edge.src, cc);
                                conflict_edge = NULL;
                            }
                            if (!conflict_edge)
                            {
                                verbose(3, "adding switch edge 0x%016jx . 0x%016jx", bb.insns[^1].start, case_addr);
                                link_bbs(Edge::EDGE_TYPE_JMP_INDIRECT, bb, case_addr, jmptab_addr);
                            }
                        }
                    }
                    break;
                }
            }

            if (jmptab_addr && jmptab_end)
            {
                mark_jmptab_as_data(jmptab_addr, jmptab_end);
            }
        }
    }
#endif
}


void
find_switches_ppc()
{
#if NYI
            int scale;
    ulong jmptab_addr, jmptab_idx, jmptab_end, case_addr;

    /* Instructions can get reordered, so we emulate the ISA subset relevant for the patterns below,
     * clearing the intermediate register values with with -1 if the result is irrelevant or undefined. */
    ulong [] registers = new ulong[32];
    Array.Fill(registers, ~0ul);

    /* Assume the jump-table entries are the same width as the GPRs */
    scale = (int)this.binary.bits / 8;

    foreach (var bb in this.start2bb.Values)
    {
        jmptab_addr = 0;
        Section target_sec = null;
        /* If this BB ends in an indirect jmp, scan the BB for what looks like
         * instructions loading a target from a jump table */
        if (bb.insns[^1].edge_type() == Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT)
        {
            target_sec = bb.section;
            foreach (var ins in bb.insns)
            {
                if (ins.Operands.Length < 2)
                {
                    continue;
                }
                /* Pattern #1 (32-bit)
                 * Load the address from its word halves. Following variants are supported:
                 * - Using addis/addi (gcc):
                 *     lis    rN, .L@ha
                 *     addi   rN, rN, L@l
                 * - Using addis/ori:
                 *     lis    rN, .L@ha
                 *     ori    rN, rN, .L@l */
                var mnem = ins.MnemonicAsInteger;
                if (mnem == (int) Reko.Arch.PowerPC.Mnemonic.oris)
                {
                    int dst = ((RegisterOperand)ins.Operands[0]).Register.Number;
                    uint imm = ((ImmediateOperand)ins.Operands[2]).Value.ToUInt32();
                    Debug.Assert(dst < 32);
                    registers[dst] = imm << 16;
                }
                else if (mnem == (int)Reko.Arch.PowerPC.Mnemonic.addi ||
                         mnem == (int)Reko.Arch.PowerPC.Mnemonic.ori)
                {
                    int lhs = ((RegisterOperand)ins.Operands[0]).Register.Number;
                    uint rhs = ((ImmediateOperand)ins.Operands[2]).Value.ToUInt32();
                    Debug.Assert(lhs < 32);
                    if (registers[lhs] != ~0ul)
                    {
                        jmptab_addr = (registers[lhs] | rhs);
                        break;
                    }
                }
                else if (ins.Operands[0] is RegisterOperand reg
                     && reg.Register.Number >= 0
                     && reg.Register.Number <= 31)
                {
                    registers[reg.Register.Number] = ~0ul;
                }
            }
        }

        if (jmptab_addr != 0)
        {
            jmptab_end = 0;
            foreach (var sec in this.binary.sections)
            {
                if (sec.contains(jmptab_addr))
                {
                    Log.verbose(4, "parsing jump table at 0x{0:X16} (jump at 0x{1})",
                            jmptab_addr, bb.insns[^1].Address);
                    jmptab_idx = jmptab_addr - sec.vma;
                    jmptab_end = jmptab_addr;
                    EndianImageReader jmptab32 = (EndianImageReader) sec.bytes[jmptab_idx];
                    EndianImageReader jmptab64 = (EndianImageReader) sec.bytes[jmptab_idx];
                    while (true)
                    {
                        if ((jmptab_idx + (uint) scale) > sec.size) break;
                        jmptab_end += (uint)scale;
                        jmptab_idx += (uint) scale;
                        switch (scale)
                        {
                        case 4:
                            case_addr = jmptab32.ReadUInt32() + jmptab_addr;
                            break;
                        case 8:
                            case_addr = jmptab64.ReadUInt64() + jmptab_addr;
                            break;
                        default:
                            Log.print_warn("Unexpected scale factor in memory operand: {0}", scale);
                            case_addr = 0;
                            break;
                        }
                        if (case_addr == 0) break;
                        if (!target_sec.contains(case_addr))
                        {
                            break;
                        }
                        else
                        {
                            var cc = this.get_bb(case_addr, out var offset);
                            if (cc is null) break;
                            Edge conflict_edge = null;
                            foreach (var e in cc.ancestors)
                            {
                                if (e.is_switch)
                                {
                                    conflict_edge = e;
                                    break;
                                }
                            }
                            if (conflict_edge is not null && (conflict_edge.jmptab <= jmptab_addr))
                            {
                                Log.verbose(3, "removing switch edge 0x{0} -> 0x{1:X16} (detected overlapping jump table or case)",
                                        conflict_edge.src.insns[^1].Address, case_addr);
                                unlink_edge(conflict_edge.src, cc);
                                conflict_edge = null;
                            }
                            if (conflict_edge is null)
                            {
                                Log.verbose(3, "adding switch edge 0x{0} -> 0x{1:X16}", bb.insns[^1].Address, case_addr);
                                link_bbs(Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT, bb, case_addr, jmptab_addr);
                            }
                        }
                    }
                    break;
                }
            }

            if (jmptab_addr != 0 && jmptab_end != 0)
            {
                mark_jmptab_as_data(jmptab_addr, jmptab_end);
            }
        }
    }
#endif
}


void
find_switches_x86()
{
#if NYI
            Edge conflict_edge;
    NOperand op_reg, op_mem;
    ulong jmptab_addr, jmptab_idx, jmptab_end, case_addr;
    int scale = 0;
    foreach (var bb in this.start2bb.Values)
    {
        jmptab_addr = 0;
        Section target_sec = null;
        /* If this BB ends in an indirect jmp, scan the BB for what looks like
         * an instruction loading a target from a jump table */
        if (bb.insns[^1].edge_type() == Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT)
        {
            if (bb.insns[^1].Operands.Length < 1)
            {
                Log.print_warn("Indirect jump has no target operand");
                continue;
            }
            target_sec = bb.section;
            var op_target = bb.insns[^1].Operands[0];
            if (op_target is Reko.Arch.X86.MemoryOperand x86Mem)
            {
                jmptab_addr = x86Mem.Offset != null ? x86Mem.Offset.ToUInt32() : 0;
                scale = x86Mem.Scale;
            }
            else if (op_target is RegisterOperand reg_target)
            {
                int ix = bb.insns.Count - 1;/* Skip the jmp itself */
                while (ix > 0)
                {
                    ix--;
                    var ins = bb.insns[ix];
                    if (ins.Operands.Length == 0)
                    {
                        continue;
                    }
                    op_reg = ins.Operands[0];
                    if (op_reg is not RegisterOperand reg)
                    {
                        continue;
                    }
                    else if (reg.Register != reg_target.Register)
                    {
                        continue;
                    }
                    else
                    {
                        /* This is the last instruction that loads the jump target register,
                         * see if we can find a jump table address from it */
                        if (ins.Operands.Length >= 2)
                        {
                            op_mem = ins.Operands[1];
                            if (op_mem is Reko.Arch.X86.MemoryOperand x86mem)
                            {
                                        jmptab_addr = x86mem.Offset is not null
                                                    ? x86mem.Offset.ToUInt64()
                                                    : 0;
                                scale = x86mem.Scale;
                            }
                        }
                        else
                        {
                            /* No luck :-( */
                        }
                        break;
                    }
                }
            }
        }

        if (jmptab_addr != 0)
        {
            jmptab_end = 0;
            foreach (var sec in this.binary.sections)
            {
                if (sec.contains(jmptab_addr))
                {
                    Log.verbose(4, "parsing jump table at 0x{0:X16} (jump at 0x{1})",
                               jmptab_addr, bb.insns[^1].Address);
                    jmptab_idx = jmptab_addr - sec.vma;
                    jmptab_end = jmptab_addr;
                    var jmptab8 =  (EndianImageReader) sec.bytes[jmptab_idx];
                    var jmptab16 = (EndianImageReader) sec.bytes[jmptab_idx];
                    var jmptab32 = (EndianImageReader) sec.bytes[jmptab_idx];
                    var jmptab64 = (EndianImageReader) sec.bytes[jmptab_idx];
                    while (true)
                    {
                        if ((jmptab_idx + (uint)scale) >= sec.size) break;
                        jmptab_end += (uint) scale;
                        jmptab_idx += (uint) scale;
                        switch (scale)
                        {
                        case 1:
                            case_addr = jmptab8.ReadByte();
                            break;
                        case 2:
                            case_addr = jmptab16.ReadUInt16();
                            break;
                        case 4:
                            case_addr = jmptab32.ReadUInt32();
                            break;
                        case 8:
                            case_addr = jmptab64.ReadUInt64();
                            break;
                        default:
                            Log.print_warn("Unexpected scale factor in memory operand: %d", scale);
                            case_addr = 0;
                            break;
                        }
                        if (case_addr == 0) break;
                        if (!target_sec.contains(case_addr))
                        {
                            break;
                        }
                        else
                        {
                            var cc = this.get_bb(case_addr, out var offset);
                            if (cc is null) break;
                            conflict_edge = null;
                            foreach (var e in cc.ancestors)
                            {
                                if (e.is_switch)
                                {
                                    conflict_edge = e;
                                    break;
                                }
                            }
                            if (conflict_edge != null && (conflict_edge.jmptab <= jmptab_addr))
                            {
                                Log.verbose(3, "removing switch edge 0x{0} -> 0x{1:X16} (detected overlapping jump table or case)",
                                           conflict_edge.src.insns[^1].Address, case_addr);
                                unlink_edge(conflict_edge.src, cc);
                                conflict_edge = null;
                            }
                            if (conflict_edge is null)
                            {
                                Log.verbose(3, "adding switch edge 0x%016jx -> 0x%016jx", bb.insns[^1].Address, case_addr);
                                link_bbs(Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT, bb, case_addr, jmptab_addr);
                            }
                        }
                    }
                    break;
                }
            }

            if (jmptab_addr != 0 && jmptab_end != 0)
            {
                mark_jmptab_as_data(jmptab_addr, jmptab_end);
            }
        }
    }
#endif
}


        void find_switches()
        {
            Log.verbose(1, "starting switch analysis");

            switch (this.binary.arch) {
    case Binary.BinaryArch.ARCH_AARCH64:
        find_switches_aarch64();
        break;
    case Binary.BinaryArch.ARCH_ARM:
        find_switches_arm();
        break;
    case Binary.BinaryArch.ARCH_MIPS:
        find_switches_mips();
        break;
    case Binary.BinaryArch.ARCH_PPC:
        find_switches_ppc();
        break;
    case Binary.BinaryArch.ARCH_X86:
        find_switches_x86();
        break;
    default:
        Log.print_warn("switch analysis not yet supported for %s", this.binary.arch_str);
        break;
    }

    Log.verbose(1, "switch analysis complete");
}


void expand_function(Function f, BB bb)
{
    if (bb is null)
    {
        bb = f.BBs[0];
    }
    else
    {
        if (bb.section.is_import_table() || bb.is_invalid())
        {
            return;
        }
        else if (bb.function is not null)
        {
            return;
        }
        f.add_bb(bb);
    }

    /* XXX: follow links to ancestor blocks, but NOT if this BB is called;
     * in that case it is an entry point, and we don't want to backtrack along
     * inbound edges because that causes issues with tailcalls */
            if (!bb.is_called()) {
                foreach (var e in bb.ancestors) {
                    if ((e.type == Edge.EdgeType.EDGE_TYPE_CALL)
                       || (e.type == Edge.EdgeType.EDGE_TYPE_CALL_INDIRECT)
                       || (e.type == Edge.EdgeType.EDGE_TYPE_RET)) {
                continue;
            }
            expand_function(f, e.src);
        }
    }

    /* Follow links to target blocks */
            foreach (var e in bb.targets) {
                if ((e.type == Edge.EdgeType.EDGE_TYPE_CALL)
                   || (e.type == Edge.EdgeType.EDGE_TYPE_CALL_INDIRECT)
                   || (e.type == Edge.EdgeType.EDGE_TYPE_RET)) {
                    continue;
                }
                expand_function(f, e.dst);
            }
        }


        public void find_functions()
        {
            Log.verbose(1, "starting function analysis");

            /* Create function headers for all BBs that are called directly */
            foreach (var bb in this.start2bb.Values)
            {
                if (bb.section.is_import_table() || bb.is_padding())
                {
                    continue;
                }
                if (bb.is_called())
                {
                    var f = new Function();
                    this.functions.Add(f);
                    f.cfg = this;
                    f.add_bb(bb);
                }
            }

            /* Expand functions for the directly-called header BBs */
            foreach (var f in this.functions) {
                expand_function(f, null);
                f.find_entry();
            }

            /* Detect functions for remaining BBs through connected-component analysis */
            foreach (var kv in this.start2bb) {
                var bb = kv.Value;
                if (bb.section.is_import_table() || bb.is_padding() || bb.is_invalid()) {
                    continue;
                } else if (bb.function != null) {
                    continue;
                }
                var f = new Function();
                this.functions.Add(f);
                f.cfg = this;
                expand_function(f, bb);
                f.find_entry();
            }

            Log.verbose(1, "function analysis complete");
        }


        void find_entry()
        {
            ulong entry;

            if (this.entry.Count > 0) {
        /* entry point already known */
                Log.verbose(3, "cfg entry point@0x{0:X16}", this.entry.First().start);
                return;
            }

            Log.verbose(1, "scanning for cfg entry point");

            entry = 0;
            Log.verbose(1, "cfg entry point@0x{0:X16}", entry);
        }


        void verify_padding()
        {
            /* Fix incorrectly identified padding blocks (they turned out to be reachable) */
            foreach (var kv in this.start2bb) {
                var bb = kv.Value;
                if (bb.trap) continue;
                if (bb.padding && bb.ancestors.Count > 0) {
                    bool call_fallthrough = false;
                    ulong noplen = (bb.end - bb.start);
                    foreach (var e in bb.ancestors) {
                        if ((e.type == Edge.EdgeType.EDGE_TYPE_FALLTHROUGH)
                           && ((e.src.insns[^1].InstructionClass & InstrClass.Call) != 0)) {
                    /* This padding block may not be truly reachable; the preceding
                     * call may be non-returning */
                    call_fallthrough = true;
                    break;
                }
            }
            if (call_fallthrough && (noplen > 1)) continue;
                    bb.padding = false;
                    link_bbs(Edge.EdgeType.EDGE_TYPE_FALLTHROUGH, bb, bb.end);
                }
            }
        }


        void detect_bad_bbs()
        {
            /* This improves accuracy for code with inline data (otherwise it does nothing) */

            List<BB> blacklist = this.bad_bbs.Values
                .Concat(this.start2bb.Values.Where(bb => bb.trap))
                .ToList();

            /* Mark BBs that may fall through to a blacklisted block as invalid */
            foreach (var bb in blacklist) {
                bool invalid = true;
                BB cc = bb;
                while (invalid) {
                    cc = get_bb(cc.start - 1, out int offset);
                    if (cc == null)
                        break;
                    var flags = cc.insns[^1].flags();
                    if ((flags & InstructionFlags.INS_FLAG_CFLOW) != 0 && (InstructionFlags.INS_FLAG_INDIRECT) != 0)
                    {
                        invalid = false;
                    }
                    else if ((flags & InstructionFlags.INS_FLAG_CALL) != 0 || (flags & InstructionFlags.INS_FLAG_JMP) != 0)
                    {
                        invalid = (get_bb(cc.insns[^1].target(), out offset) == null);
                    }
                    else if ((flags & InstructionFlags.INS_FLAG_RET) != 0)
                    {
                        invalid = false;
                    }
                    if (invalid) {
                        cc.invalid = true;
                        unlink_bb(cc);
                        bad_bbs[cc.start] = cc;
                    }
                }
            }

            /* Remove bad BBs from the CFG map */
            foreach (var bb in this.bad_bbs.Values) {
                if (this.start2bb.ContainsKey(bb.start)) {
                    this.start2bb.Remove(bb.start);
                }
            }
        }

        BB get_bb(Address addr, out int offset)
        {
            if (addr is null)
            {
                offset = 0;
                return null;
            }
            return get_bb(addr.ToLinear(), out offset);
        }

        BB get_bb(ulong addr, out int offset)
        {
            if (this.start2bb.ContainsKey(addr)) {
                offset = 0;
                return this.start2bb[addr];
            } else if (start2bb.Count == 0) {
                offset = 0;
                return null;
            }

            int lo = 0;
            int hi = this.start2bb.Count - 1;
            while (lo <= hi)
            {
                int mid = lo + (hi - lo) / 2;
                BB bb = this.start2bb.Values[mid];
                if (bb.start < addr)
                {
                    hi = mid - 1;
                }
                else if (bb.end >= addr)
                {
                    lo = mid + 1;
                }
                else
                {
                    if ((addr >= bb.start) && (addr < bb.end))
                    {
                        offset = (int)(addr - bb.start);
                        return bb;
                    }
                }
            }
            offset = 0;
            return null;
        }

        void link_bbs(Edge.EdgeType type, BB bb, ulong target, ulong jmptab = 0)
        {
            Debug.Assert(type != Edge.EdgeType.EDGE_TYPE_NONE);
            bool is_switch = (jmptab > 0);
            BB cc = this.get_bb(target, out int offset);
            if (cc!= null) {
                bb.targets.Add(new Edge(type, bb, cc, is_switch, jmptab, offset));
                cc.ancestors.Add(new Edge(type, bb, cc, is_switch, jmptab, offset));
            }
        }


        void unlink_bb(BB bb)
        {
            BB cc;
            //std::list<Edge>::iterator f;

            foreach (var e in bb.ancestors) {
                cc = e.src;
                cc.targets.RemoveAll(f => f.dst == bb);
            }
            foreach (var e in bb.targets) {
                cc = e.dst;
                cc.ancestors.RemoveAll(f => f.src == bb);
            }

            bb.ancestors.Clear();
            bb.targets.Clear();
        }


        static void unlink_edge(BB bb, BB cc)
        {
            bb.targets.RemoveAll(f => f.dst == cc);
            cc.ancestors.RemoveAll(f => f.src == bb);
        }


        public int make_cfg(Binary bin, List<DisasmSection> disasm)
        {
            Log.verbose(1, "generating cfg");

            this.binary = bin;

            foreach (var dis in disasm)
            {
                int nvalid = dis.BBs.Count(b => !b.invalid);

                foreach (var bb in dis.BBs)
                {
                    if (bb.invalid)
                    {
                        this.bad_bbs[bb.start] = bb;
                        continue;
                    }
                    if (bb.start == bin.entry)
                    {
                        this.entry.Add(bb);
                    }
                    if (this.start2bb.ContainsKey(bb.start))
                    {
                        Log.print_warn("conflicting BBs at 0x{0:X16}", bb.start);
                    }
                    this.start2bb[bb.start] = bb;
                }
            }

            /* Link basic blocks by direct and fallthrough edges */
            foreach (var dis in disasm) {
                foreach (var bb in dis.BBs) {
                    if (bb.insns.Count == 0)
                        continue;
                    var last = bb.insns[^1];
                    var flags = last.flags();
                    if ((flags & (InstructionFlags.INS_FLAG_CALL|InstructionFlags.INS_FLAG_JMP)) != 0) {
                        if ((flags & InstructionFlags.INS_FLAG_INDIRECT) == 0) {
                            var aaddr = bb.insns[^1].target();
                            if (aaddr is not null) //$BUG: x86 return statements 
                            {
                                link_bbs(bb.insns[^1].edge_type(), bb, aaddr.ToLinear());
                            }
                        }
                        if ((flags & InstructionFlags.INS_FLAG_CALL) != 0 || (flags & InstructionFlags.INS_FLAG_COND) != 0) {
                            link_bbs(Edge.EdgeType.EDGE_TYPE_FALLTHROUGH, bb, bb.end);
                        }
                    } else if ((flags & InstructionFlags.INS_FLAG_CFLOW) == 0 && !bb.padding) {
                        /* A block that doesn't have a control flow instruction at the end;
                         * this can happen if the next block is a nop block */
                        link_bbs(Edge.EdgeType.EDGE_TYPE_FALLTHROUGH, bb, bb.end);
            }
        }
    }

            analyze_addrtaken();
            find_switches();
            verify_padding();
            detect_bad_bbs();

            find_functions();
            find_entry();

            Log.verbose(1, "cfg generation complete");

            return 0;
        }
    }
}

