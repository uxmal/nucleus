#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <list>
#include <map>
#include <queue>

#include "bb.h"
#include "edge.h"
#include "function.h"
#include "disasm.h"
#include "loader.h"
#include "cfg.h"
#include "log.h"
#include "options.h"
#include "endian.h"


void
CFG::print_functions(FILE *out)
{
  for(auto &f: this->functions) {
    f.print(out);
  }
}


void
CFG::print_function_summaries(FILE *out)
{
  for(auto &f: this->functions) {
    f.print_summary(out);
  }
}


void
CFG::mark_addrtaken(uint64_t addr)
{
  BB *cc;

  if (this->start2bb.count(addr)) {
    cc = this->start2bb[addr];
    if (!cc->addrtaken) {
      cc->addrtaken = true;
      verbose(3, "marking addrtaken bb@0x%016jx", cc->start);
    }
  }
}


void
CFG::analyze_addrtaken_ppc()
{
  BB *bb;

  /* Instructions can get reordered, so we emulate the ISA subset relevant for the patterns below,
   * clearing the intermediate register values with with -1 if the result is irrelevant or undefined. */
  int64_t registers[32];

  for(auto &kv: this->start2bb) {
    bb = kv.second;
    for(auto &ins: bb->insns) {
      if(ins.operands.size() < 2) {
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
      if(ins.id == PPC_INS_LIS) {
        int64_t dst = ins.operands[0].ppc_value.reg - PPC_REG_R0;
        int64_t imm = ins.operands[1].ppc_value.imm;
        assert(dst < 32);
        registers[dst] = imm << 16;
      }
      else if(ins.id == PPC_INS_ADDI || ins.id == PPC_INS_ORI) {
        int64_t lhs = ins.operands[1].ppc_value.reg - PPC_REG_R0;
        int64_t rhs = ins.operands[2].ppc_value.imm;
        assert(lhs < 32);
        if (registers[lhs] != -1) {
          mark_addrtaken(registers[lhs] | rhs);
        }
      }
      else if(ins.operands[0].type == Operand::OP_TYPE_REG
           && ins.operands[0].ppc_value.reg >= PPC_REG_R0
           && ins.operands[0].ppc_value.reg <= PPC_REG_R31) {
        int64_t dst = ins.operands[0].ppc_value.reg - PPC_REG_R0;
        registers[dst] = -1;
      }
    }
  }
}


void
CFG::analyze_addrtaken_x86()
{
  BB *bb;
  Operand *op_src, *op_dst;

  for(auto &kv: this->start2bb) {
    bb = kv.second;
    for(auto &ins: bb->insns) {
      if(ins.operands.size() < 2) {
        continue;
      }
      op_dst = &ins.operands[0];
      op_src = &ins.operands[1];
      if(((op_dst->type == Operand::OP_TYPE_REG) || (op_dst->type == Operand::OP_TYPE_MEM))
         && (op_src->type == Operand::OP_TYPE_IMM)) {
        mark_addrtaken(op_src->x86_value.imm);
      }
    }
  }
}


void
CFG::analyze_addrtaken()
{
  verbose(1, "starting address-taken analysis");

  switch(this->binary->arch) {
  case Binary::ARCH_PPC:
    analyze_addrtaken_ppc();
    break;
  case Binary::ARCH_X86:
    analyze_addrtaken_x86();
    break;
  default:
    print_warn("address-taken analysis not yet supported for %s", this->binary->arch_str.c_str());
    break;
  }

  verbose(1, "address-taken analysis complete");
}


void
CFG::mark_jmptab_as_data(uint64_t start, uint64_t end)
{
  uint64_t addr;
  BB *bb, *cc;

  bb = NULL;
  cc = NULL;
  for(addr = start; addr < end; addr++) {
    bb = this->get_bb(addr, NULL);
    if(!bb) continue;
    if(bb != cc) {
      bb->invalid = true;
      unlink_bb(bb);
      bad_bbs[bb->start] = bb;
      cc = bb;
    }
  }
}


void
CFG::find_switches_aarch64(){
  BB *bb, *cc;
  Edge *conflict_edge;
  Section *target_sec;
  int scale;
  unsigned offset;
  uint64_t jmptab_addr, jmptab_idx, jmptab_end;
  uint64_t case_addr, case_addr_abs, case_addr_rel;
  uint8_t *jmptab8;
  uint16_t *jmptab16;
  uint32_t *jmptab32;
  uint64_t *jmptab64;

  /* Instructions can get reordered, so we emulate the ISA subset relevant for the patterns below,
   * clearing the intermediate register values with with -1 if the result is irrelevant or undefined. */
  int64_t registers[32];
  for (size_t i = 0; i < 32; i++) {
    registers[i] = -1LL;
  }

  /* Trying to determine the size of the jump table entries by looking
   * at the instruction immediately following the described pattern.
   * - scale <= 0: signals the scale could not be determined.
   * - scale == 0: signals the current instruction may tell the scale. */
  scale = -1;

  for(auto &kv: this->start2bb) {
    bb = kv.second;
    jmptab_addr = 0;
    target_sec  = NULL;
    /* If this BB ends in an indirect jmp, scan the BB for what looks like
     * instructions loading a target from a jump table */
    if(bb->insns.back().edge_type() == Edge::EDGE_TYPE_JMP_INDIRECT) {
      target_sec = bb->section;
      for(auto &ins: bb->insns) {
        if(ins.operands.size() < 2) {
          continue;
        }
        /* Pattern #1
         * Loading jump table address relative to the `pc` register.
         *   adrp    x0, #:pg_hi21:.L
         *   add     x0, x0, #:lo12:.L
         *   ldr/ldrh/ldrb ...
         */

        /* detect scale */
        if (scale == 0) {
          if (ins.id == ARM64_INS_LDRB) {
            scale = 1;
          }
          else if (ins.id == ARM64_INS_LDRH) {
            scale = 2;
          }
          else if (ins.id == ARM64_INS_LDR
           && ins.operands[0].aarch64_value.reg >= ARM64_REG_W0
           && ins.operands[0].aarch64_value.reg <= ARM64_REG_W28) {
            scale = 4;
          }
          else if (ins.id == ARM64_INS_LDR
           && ins.operands[0].aarch64_value.reg >= ARM64_REG_X0
           && ins.operands[0].aarch64_value.reg <= ARM64_REG_X28) {
            scale = 8;
          }
        }
        /* detect jump-table address loading */
        if(ins.id == ARM64_INS_ADRP) {
          int64_t dst = ins.operands[0].aarch64_value.reg - ARM64_REG_X0;
          int64_t imm = ins.operands[1].aarch64_value.imm;
          assert(dst < 29);
          registers[dst] = imm;
        }
        else if(ins.id == ARM64_INS_ADD
             && ins.operands[1].type == Operand::OP_TYPE_REG
             && ins.operands[2].type == Operand::OP_TYPE_IMM) {
          int64_t dst = ins.operands[0].aarch64_value.reg - ARM64_REG_X0;
          int64_t lhs = ins.operands[1].aarch64_value.reg - ARM64_REG_X0;
          int64_t rhs = ins.operands[2].aarch64_value.imm & 0xFFF;
          assert(dst < 29 && lhs < 29);
          registers[dst] = registers[lhs] + rhs;
          if (registers[dst] != -1) {
            jmptab_addr = (uint64_t)(registers[dst]);
            scale = 0;
          }
        }
        else if(ins.operands[0].type == Operand::OP_TYPE_REG
             && ins.operands[0].aarch64_value.reg >= ARM64_REG_X0
             && ins.operands[0].aarch64_value.reg <= ARM64_REG_X28) {
          int64_t dst = ins.operands[0].aarch64_value.reg - ARM64_REG_X0;
          registers[dst] = -1;
        }
      }
    }

    if(jmptab_addr && scale > 0) {
      jmptab_end = 0;
      for(auto &sec: this->binary->sections) {
        if(sec.contains(jmptab_addr)) {
          verbose(4, "parsing jump table at 0x%016jx (jump at 0x%016jx)",
                  jmptab_addr, bb->insns.back().start);
          jmptab_idx = jmptab_addr-sec.vma;
          jmptab_end = jmptab_addr;
          jmptab8 = (uint8_t*)&sec.bytes[jmptab_idx];
          jmptab16 = (uint16_t*)&sec.bytes[jmptab_idx];
          jmptab32 = (uint32_t*)&sec.bytes[jmptab_idx];
          jmptab64 = (uint64_t*)&sec.bytes[jmptab_idx];
          while(1) {
            if((jmptab_idx+scale) > sec.size) break;
            jmptab_end += scale;
            jmptab_idx += scale;
            switch(scale) {
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
                print_warn("Unexpected scale factor in memory operand: %d", scale);
                case_addr_abs = 0;
                break;
            }
            case_addr_rel = case_addr_abs + jmptab_addr;
            if(target_sec->contains(case_addr_abs)) {
              case_addr = case_addr_abs;
            } else if(target_sec->contains(case_addr_rel)) {
              case_addr = case_addr_rel;
            } else {
              break;
            }
            /* add target block */
            cc = this->get_bb(case_addr, &offset);
            if(!cc) break;
            conflict_edge = NULL;
            for(auto &e: cc->ancestors) {
              if(e.is_switch) {
                conflict_edge = &e;
                break;
              }
            }
            if(conflict_edge && (conflict_edge->jmptab <= jmptab_addr)) {
              verbose(3, "removing switch edge 0x%016jx -> 0x%016jx (detected overlapping jump table or case)",
                      conflict_edge->src->insns.back().start, case_addr);
              unlink_edge(conflict_edge->src, cc);
              conflict_edge = NULL;
            }
            if(!conflict_edge) {
              verbose(3, "adding switch edge 0x%016jx -> 0x%016jx", bb->insns.back().start, case_addr);
              link_bbs(Edge::EDGE_TYPE_JMP_INDIRECT, bb, case_addr, jmptab_addr);
            }
          }
          break;
        }
      }

      if(jmptab_addr && jmptab_end) {
        mark_jmptab_as_data(jmptab_addr, jmptab_end);
      }
    }
  }
}


void
CFG::find_switches_arm()
{
  BB *bb, *cc;
  Edge *conflict_edge;
  Section *target_sec;
  int scale = 4;
  unsigned offset;
  uint64_t jmptab_addr, jmptab_idx, jmptab_end, case_addr;
  uint32_t *jmptab;

  for(auto &kv: this->start2bb) {
    bb = kv.second;
    jmptab_addr = 0;
    target_sec  = NULL;
    /* If this BB ends in an indirect jmp, scan the BB for what looks like
     * instructions loading a target from a jump table */
    if(bb->insns.back().edge_type() == Edge::EDGE_TYPE_JMP_INDIRECT) {
      target_sec = bb->section;
      for(auto rit = bb->insns.rbegin(); rit != bb->insns.rend(); ++rit) {
        const auto& ins = *rit;
        if(ins.operands.size() < 2) {
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
        if(ins.id == ARM_INS_ADD &&
           ins.operands[1].type == Operand::OP_TYPE_REG &&
           ins.operands[1].arm_value.reg == ARM_REG_PC &&
           ins.operands[2].type == Operand::OP_TYPE_IMM) {
          int64_t imm = ins.operands[2].arm_value.imm;
          jmptab_addr = (ins.start + 8) + imm;
          break;
        }
        else if(ins.id == ARM_INS_ADR && ins.operands[0].arm_value.reg == ARM_REG_PC) {
          int64_t imm = ins.operands[1].arm_value.imm;
          jmptab_addr = (ins.start + 8) + imm;
          break;
        }
        else if(ins.id == ARM_INS_LDR
             && ins.operands[0].arm_value.reg == ARM_REG_PC
             && ins.operands[1].arm_value.reg == ARM_REG_PC) {
          jmptab_addr = (ins.start + 8);
          break;
        }
      }
    }

    if(jmptab_addr) {
      jmptab_end = 0;
      for(auto &sec: this->binary->sections) {
        if(sec.contains(jmptab_addr)) {
          verbose(4, "parsing jump table at 0x%016jx (jump at 0x%016jx)",
                  jmptab_addr, bb->insns.back().start);
          jmptab_idx = jmptab_addr-sec.vma;
          jmptab_end = jmptab_addr;
          jmptab = (uint32_t*)&sec.bytes[jmptab_idx];
          while(1) {
            if((jmptab_idx+scale) > sec.size) break;
            jmptab_end += scale;
            jmptab_idx += scale;
            case_addr = uint32_t(read_le_i32(jmptab++));
            if(!case_addr) break;
            if(!target_sec->contains(case_addr)) {
              break;
            } else {
              cc = this->get_bb(case_addr, &offset);
              if(!cc) break;
              conflict_edge = NULL;
              for(auto &e: cc->ancestors) {
                if(e.is_switch) {
                  conflict_edge = &e;
                  break;
                }
              }
              if(conflict_edge && (conflict_edge->jmptab <= jmptab_addr)) {
                verbose(3, "removing switch edge 0x%016jx -> 0x%016jx (detected overlapping jump table or case)",
                        conflict_edge->src->insns.back().start, case_addr);
                unlink_edge(conflict_edge->src, cc);
                conflict_edge = NULL;
              }
              if(!conflict_edge) {
                verbose(3, "adding switch edge 0x%016jx -> 0x%016jx", bb->insns.back().start, case_addr);
                link_bbs(Edge::EDGE_TYPE_JMP_INDIRECT, bb, case_addr, jmptab_addr);
              }
            }
          }
          break;
        }
      }

      if(jmptab_addr && jmptab_end) {
        mark_jmptab_as_data(jmptab_addr, jmptab_end);
      }
    }
  }
}


void
CFG::find_switches_mips()
{
  BB *bb, *cc;
  Edge *conflict_edge;
  Section *target_sec;
  int scale;
  unsigned offset;
  uint64_t jmptab_addr, jmptab_idx, jmptab_end, case_addr;
  uint32_t *jmptab32;
  uint64_t *jmptab64;

  /* Instructions can get reordered, so we emulate the ISA subset relevant for the patterns below,
   * clearing the intermediate register values with with -1 if the result is irrelevant or undefined. */
  int64_t registers[32];
  for (size_t i = 0; i < 32; i++) {
    registers[i] = -1LL;
  }

  /* Assume the jump-table entries are the same width as the GPRs */
  scale = this->binary->bits / 8;

  for(auto &kv: this->start2bb) {
    bb = kv.second;
    jmptab_addr = 0;
    target_sec  = NULL;
    /* If this BB ends in an indirect jmp, scan the BB for what looks like
     * instructions loading a target from a jump table */
    if(bb->insns.back().edge_type() == Edge::EDGE_TYPE_JMP_INDIRECT) {
      target_sec = bb->section;
      for(auto &ins: bb->insns) {
        if(ins.operands.size() < 2) {
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
        if(ins.id == MIPS_INS_LUI) {
          int64_t dst = ins.operands[0].mips_value.reg - MIPS_REG_0;
          int64_t imm = ins.operands[1].mips_value.imm;
          assert(dst < 32);
          registers[dst] = imm << 16;
        }
        else if(ins.id == MIPS_INS_ADDIU || ins.id == MIPS_INS_DADDIU) {
          int64_t dst = ins.operands[0].mips_value.reg - MIPS_REG_0;
          int64_t lhs = ins.operands[1].mips_value.reg - MIPS_REG_0;
          int64_t rhs = ins.operands[2].mips_value.imm;
          assert(dst < 32 && lhs < 32);
          registers[dst] = registers[lhs] + rhs;
          if (registers[dst] != -1) {
            jmptab_addr =  (uint64_t)(registers[dst]);
          }
        }
        else if(ins.id == MIPS_INS_ADDU) {
          int64_t dst = ins.operands[0].mips_value.reg - MIPS_REG_0;
          int64_t lhs = ins.operands[1].mips_value.reg - MIPS_REG_0;
          int64_t rhs = ins.operands[2].mips_value.reg - MIPS_REG_0;
          assert(dst < 32 && lhs < 32 && rhs < 32);
          /* addu emulation is intentionally wrong. the goal is replacing:
           * - `dst = jumptable + offset` => `dst = jumptable`
           * - `dst = offset + jumptable` => `dst = jumptable` */
          if (registers[lhs] != -1) {
            registers[dst] = registers[lhs];
          } else {
            registers[dst] = registers[rhs];
          }
        }
        else if(ins.id == MIPS_INS_LW) {
          int64_t reg = ins.operands[1].mips_value.mem.base - MIPS_REG_0;
          int64_t imm = ins.operands[1].mips_value.mem.disp;
          assert(reg < 32);
          if (registers[reg] != -1) {
            jmptab_addr = (uint64_t)(registers[reg] + imm);
          }
        }
        else if(ins.id == MIPS_INS_DADDU) {
          int64_t dst = ins.operands[0].mips_value.reg - MIPS_REG_0;
          int64_t lhs = ins.operands[1].mips_value.reg - MIPS_REG_0;
          int64_t rhs = ins.operands[2].mips_value.reg - MIPS_REG_0;
          assert(dst < 32 && lhs < 32 && rhs < 32);
          registers[dst] = registers[lhs] + registers[rhs];
          if (registers[dst] != -1) {
            jmptab_addr = (uint64_t)(registers[dst]);
          }
        }
        else if(ins.id == MIPS_INS_DSLL32 && ins.operands[2].mips_value.reg == 0) {
          int64_t dst = ins.operands[0].mips_value.reg - MIPS_REG_0;
          int64_t src = ins.operands[1].mips_value.reg - MIPS_REG_0;
          assert(dst < 32 && src < 32);
          registers[dst] = src << 32;
        }
        else if(ins.operands[0].type == Operand::OP_TYPE_REG
             && ins.operands[0].mips_value.reg >= MIPS_REG_0
             && ins.operands[0].mips_value.reg <= MIPS_REG_31) {
          int64_t dst = ins.operands[0].mips_value.reg - MIPS_REG_0;
          registers[dst] = -1;
        }
      }
    }

    if(jmptab_addr) {
      jmptab_end = 0;
      for(auto &sec: this->binary->sections) {
        if(sec.contains(jmptab_addr)) {
          verbose(4, "parsing jump table at 0x%016jx (jump at 0x%016jx)",
                  jmptab_addr, bb->insns.back().start);
          jmptab_idx = jmptab_addr-sec.vma;
          jmptab_end = jmptab_addr;
          jmptab32 = (uint32_t*)&sec.bytes[jmptab_idx];
          jmptab64 = (uint64_t*)&sec.bytes[jmptab_idx];
          while(1) {
            if((jmptab_idx+scale) > sec.size) break;
            jmptab_end += scale;
            jmptab_idx += scale;
            switch(scale) {
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
            if(!case_addr) break;
            if(!target_sec->contains(case_addr)) {
              break;
            } else {
              cc = this->get_bb(case_addr, &offset);
              if(!cc) break;
              conflict_edge = NULL;
              for(auto &e: cc->ancestors) {
                if(e.is_switch) {
                  conflict_edge = &e;
                  break;
                }
              }
              if(conflict_edge && (conflict_edge->jmptab <= jmptab_addr)) {
                verbose(3, "removing switch edge 0x%016jx -> 0x%016jx (detected overlapping jump table or case)",
                        conflict_edge->src->insns.back().start, case_addr);
                unlink_edge(conflict_edge->src, cc);
                conflict_edge = NULL;
              }
              if(!conflict_edge) {
                verbose(3, "adding switch edge 0x%016jx -> 0x%016jx", bb->insns.back().start, case_addr);
                link_bbs(Edge::EDGE_TYPE_JMP_INDIRECT, bb, case_addr, jmptab_addr);
              }
            }
          }
          break;
        }
      }

      if(jmptab_addr && jmptab_end) {
        mark_jmptab_as_data(jmptab_addr, jmptab_end);
      }
    }
  }
}


void
CFG::find_switches_ppc()
{
  BB *bb, *cc;
  Edge *conflict_edge;
  Section *target_sec;
  int scale;
  unsigned offset;
  uint64_t jmptab_addr, jmptab_idx, jmptab_end, case_addr;
  uint32_t *jmptab32;
  uint64_t *jmptab64;

  /* Instructions can get reordered, so we emulate the ISA subset relevant for the patterns below,
   * clearing the intermediate register values with with -1 if the result is irrelevant or undefined. */
  int64_t registers[32];

  /* Assume the jump-table entries are the same width as the GPRs */
  scale = this->binary->bits / 8;

  for(auto &kv: this->start2bb) {
    bb = kv.second;
    jmptab_addr = 0;
    target_sec  = NULL;
    /* If this BB ends in an indirect jmp, scan the BB for what looks like
     * instructions loading a target from a jump table */
    if(bb->insns.back().edge_type() == Edge::EDGE_TYPE_JMP_INDIRECT) {
      target_sec = bb->section;
      for(auto &ins: bb->insns) {
        if(ins.operands.size() < 2) {
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
        if(ins.id == PPC_INS_LIS) {
          int64_t dst = ins.operands[0].ppc_value.reg - PPC_REG_R0;
          int64_t imm = ins.operands[1].ppc_value.imm;
          assert(dst < 32);
          registers[dst] = imm << 16;
        }
        else if(ins.id == PPC_INS_ADDI || ins.id == PPC_INS_ORI) {
          int64_t lhs = ins.operands[1].ppc_value.reg - PPC_REG_R0;
          int64_t rhs = ins.operands[2].ppc_value.imm;
          assert(lhs < 32);
          if (registers[lhs] != -1) {
            jmptab_addr = (uint64_t)(registers[lhs] | rhs);
            break;
          }
        }
        else if(ins.operands[0].type == Operand::OP_TYPE_REG
             && ins.operands[0].ppc_value.reg >= PPC_REG_R0
             && ins.operands[0].ppc_value.reg <= PPC_REG_R31) {
          int64_t dst = ins.operands[0].ppc_value.reg - PPC_REG_R0;
          registers[dst] = -1;
        }
      }
    }

    if(jmptab_addr) {
      jmptab_end = 0;
      for(auto &sec: this->binary->sections) {
        if(sec.contains(jmptab_addr)) {
          verbose(4, "parsing jump table at 0x%016jx (jump at 0x%016jx)",
                  jmptab_addr, bb->insns.back().start);
          jmptab_idx = jmptab_addr-sec.vma;
          jmptab_end = jmptab_addr;
          jmptab32 = (uint32_t*)&sec.bytes[jmptab_idx];
          jmptab64 = (uint64_t*)&sec.bytes[jmptab_idx];
          while(1) {
            if((jmptab_idx+scale) > sec.size) break;
            jmptab_end += scale;
            jmptab_idx += scale;
            switch(scale) {
            case 4:
              case_addr = uint32_t(read_be_i32(jmptab32++) + jmptab_addr);
              break;
            case 8:
              case_addr = uint64_t(read_be_i64(jmptab64++) + jmptab_addr);
              break;
            default:
              print_warn("Unexpected scale factor in memory operand: %d", scale);
              case_addr = 0;
              break;
            }
            if(!case_addr) break;
            if(!target_sec->contains(case_addr)) {
              break;
            } else {
              cc = this->get_bb(case_addr, &offset);
              if(!cc) break;
              conflict_edge = NULL;
              for(auto &e: cc->ancestors) {
                if(e.is_switch) {
                  conflict_edge = &e;
                  break;
                }
              }
              if(conflict_edge && (conflict_edge->jmptab <= jmptab_addr)) {
                verbose(3, "removing switch edge 0x%016jx -> 0x%016jx (detected overlapping jump table or case)",
                        conflict_edge->src->insns.back().start, case_addr);
                unlink_edge(conflict_edge->src, cc);
                conflict_edge = NULL;
              }
              if(!conflict_edge) {
                verbose(3, "adding switch edge 0x%016jx -> 0x%016jx", bb->insns.back().start, case_addr);
                link_bbs(Edge::EDGE_TYPE_JMP_INDIRECT, bb, case_addr, jmptab_addr);
              }
            }
          }
          break;
        }
      }

      if(jmptab_addr && jmptab_end) {
        mark_jmptab_as_data(jmptab_addr, jmptab_end);
      }
    }
  }
}


void
CFG::find_switches_x86()
{
  BB *bb, *cc;
  Edge *conflict_edge;
  Section *target_sec;
  Operand *op_target, *op_reg, *op_mem;
  int scale;
  unsigned offset;
  uint64_t jmptab_addr, jmptab_idx, jmptab_end, case_addr;
  uint8_t *jmptab8;
  uint16_t *jmptab16;
  uint32_t *jmptab32;
  uint64_t *jmptab64;
  std::list<Instruction>::iterator ins;

  for(auto &kv: this->start2bb) {
    bb = kv.second;
    jmptab_addr = 0;
    target_sec  = NULL;
    /* If this BB ends in an indirect jmp, scan the BB for what looks like
     * an instruction loading a target from a jump table */
    if(bb->insns.back().edge_type() == Edge::EDGE_TYPE_JMP_INDIRECT) {
      if(bb->insns.back().operands.size() < 1) {
        print_warn("Indirect jump has no target operand");
        continue;
      }
      target_sec = bb->section;
      op_target  = &bb->insns.back().operands[0];
      if(op_target->type == Operand::OP_TYPE_MEM) {
        jmptab_addr = (uint64_t)op_target->x86_value.mem.disp;
        scale = op_target->x86_value.mem.scale;
      } else if(op_target->type != Operand::OP_TYPE_REG) {
        ins = bb->insns.end();
        ins--; /* Skip the jmp itself */
        while(ins != bb->insns.begin()) {
          ins--;
          if(ins->operands.empty()) {
            continue;
          }
          op_reg = &ins->operands[0];
          if(op_reg->type != Operand::OP_TYPE_REG) {
            continue;
          } else if(op_reg->x86_value.reg != op_target->x86_value.reg) {
            continue;
          } else {
            /* This is the last instruction that loads the jump target register,
             * see if we can find a jump table address from it */
            if(ins->operands.size() >= 2) {
              op_mem = &ins->operands[1];
              if(op_mem->type == Operand::OP_TYPE_MEM) {
                jmptab_addr = (uint64_t)op_mem->x86_value.mem.disp;
                scale = op_mem->x86_value.mem.scale;
              }
            } else {
              /* No luck :-( */
            }
            break;
          }
        }
      }
    }

    if(jmptab_addr) {
      jmptab_end = 0;
      for(auto &sec: this->binary->sections) {
        if(sec.contains(jmptab_addr)) {
          verbose(4, "parsing jump table at 0x%016jx (jump at 0x%016jx)", 
                     jmptab_addr, bb->insns.back().start);
          jmptab_idx = jmptab_addr-sec.vma;
          jmptab_end = jmptab_addr;
          jmptab8  = (uint8_t*) &sec.bytes[jmptab_idx];
          jmptab16 = (uint16_t*)&sec.bytes[jmptab_idx];
          jmptab32 = (uint32_t*)&sec.bytes[jmptab_idx];
          jmptab64 = (uint64_t*)&sec.bytes[jmptab_idx];
          while(1) {
            if((jmptab_idx+scale) >= sec.size) break;
            jmptab_end += scale;
            jmptab_idx += scale;
            switch(scale) {
              case 1:
                case_addr = (*jmptab8++);
                break;
              case 2:
                case_addr = (*jmptab16++);
                break;
              case 4:
                case_addr = (*jmptab32++);
                break;
              case 8:
                case_addr = (*jmptab64++);
                break;
              default:
                print_warn("Unexpected scale factor in memory operand: %d", scale);
                case_addr = 0;
                break;
            }
            if(!case_addr) break;
            if(!target_sec->contains(case_addr)) {
              break;
            } else {
              cc = this->get_bb(case_addr, &offset);
              if(!cc) break;
              conflict_edge = NULL;
              for(auto &e: cc->ancestors) {
                if(e.is_switch) {
                  conflict_edge = &e;
                  break;
                }
              }
              if(conflict_edge && (conflict_edge->jmptab <= jmptab_addr)) {
                verbose(3, "removing switch edge 0x%016jx -> 0x%016jx (detected overlapping jump table or case)", 
                           conflict_edge->src->insns.back().start, case_addr);
                unlink_edge(conflict_edge->src, cc);
                conflict_edge = NULL;
              }
              if(!conflict_edge) {
                verbose(3, "adding switch edge 0x%016jx -> 0x%016jx", bb->insns.back().start, case_addr);
                link_bbs(Edge::EDGE_TYPE_JMP_INDIRECT, bb, case_addr, jmptab_addr);
              }
            }
          }
          break;
        }
      }

      if(jmptab_addr && jmptab_end) {
        mark_jmptab_as_data(jmptab_addr, jmptab_end);
      }
    }
  }
}


void
CFG::find_switches()
{
  verbose(1, "starting switch analysis");

  switch(this->binary->arch) {
  case Binary::ARCH_AARCH64:
    find_switches_aarch64();
    break;
  case Binary::ARCH_ARM:
    find_switches_arm();
    break;
  case Binary::ARCH_MIPS:
    find_switches_mips();
    break;
  case Binary::ARCH_PPC:
    find_switches_ppc();
    break;
  case Binary::ARCH_X86:
    find_switches_x86();
    break;
  default:
    print_warn("switch analysis not yet supported for %s", this->binary->arch_str.c_str());
    break;
  }

  verbose(1, "switch analysis complete");
}


void
CFG::expand_function(Function *f, BB *bb)
{
  if(!bb) {
    bb = f->BBs.front();
  } else {
    if(bb->section->is_import_table() || bb->is_invalid()) {
      return;
    } else if(bb->function) {
      return;
    }
    f->add_bb(bb);
  }

  /* XXX: follow links to ancestor blocks, but NOT if this BB is called;
   * in that case it is an entry point, and we don't want to backtrack along
   * inbound edges because that causes issues with tailcalls */
  if(!bb->is_called()) {
    for(auto &e: bb->ancestors) {
      if((e.type == Edge::EDGE_TYPE_CALL) 
         || (e.type == Edge::EDGE_TYPE_CALL_INDIRECT)
         || (e.type == Edge::EDGE_TYPE_RET)) {
        continue;
      }
      expand_function(f, e.src);
    }
  }

  /* Follow links to target blocks */
  for(auto &e: bb->targets) {
    if((e.type == Edge::EDGE_TYPE_CALL) 
       || (e.type == Edge::EDGE_TYPE_CALL_INDIRECT)
       || (e.type == Edge::EDGE_TYPE_RET)) {
      continue;
    }
    expand_function(f, e.dst);
  }
}


void
CFG::find_functions()
{
  BB *bb;

  verbose(1, "starting function analysis");

  /* Create function headers for all BBs that are called directly */
  for(auto &kv: this->start2bb) {
    bb = kv.second;
    if(bb->section->is_import_table() || bb->is_padding()) {
      continue;
    }
    if(bb->is_called()) {
      this->functions.push_back(Function());
      this->functions.back().cfg = this;
      this->functions.back().add_bb(bb);
    }
  }

  /* Expand functions for the directly-called header BBs */
  for(auto &f: this->functions) {
    expand_function(&f, NULL);
    f.find_entry();
  }

  /* Detect functions for remaining BBs through connected-component analysis */
  for(auto &kv: this->start2bb) {
    bb = kv.second;
    if(bb->section->is_import_table() || bb->is_padding() || bb->is_invalid()) {
      continue;
    } else if(bb->function) {
      continue;
    }
    this->functions.push_back(Function());
    this->functions.back().cfg = this;
    expand_function(&this->functions.back(), bb);
    this->functions.back().find_entry();
  }

  verbose(1, "function analysis complete");
}


void
CFG::find_entry()
{
  uint64_t entry;

  if(this->entry.size() > 0) {
    /* entry point already known */
    verbose(3, "cfg entry point@0x%016jx", this->entry.front()->start);
    return;
  }

  verbose(1, "scanning for cfg entry point");

  entry = 0;
  verbose(1, "cfg entry point@0x%016jx", entry);
}


void
CFG::verify_padding()
{
  BB *bb;
  bool call_fallthrough;
  unsigned noplen;

  /* Fix incorrectly identified padding blocks (they turned out to be reachable) */
  for(auto &kv: this->start2bb) {
    bb = kv.second;
    if(bb->trap) continue;
    if(bb->padding && !bb->ancestors.empty()) {
      call_fallthrough = false;
      noplen = (bb->end - bb->start);
      for(auto &e: bb->ancestors) {
        if((e.type == Edge::EDGE_TYPE_FALLTHROUGH) 
           && (e.src->insns.back().flags & Instruction::INS_FLAG_CALL)) {
          /* This padding block may not be truly reachable; the preceding
           * call may be non-returning */
          call_fallthrough = true;
          break;
        }
      }
      if(call_fallthrough && (noplen > 1)) continue;
      bb->padding = false;
      link_bbs(Edge::EDGE_TYPE_FALLTHROUGH, bb, bb->end);
    }
  }
}


void
CFG::detect_bad_bbs()
{
  BB *bb, *cc;
  bool invalid;
  unsigned flags, offset;
  std::list<BB*> blacklist;

  /* This improves accuracy for code with inline data (otherwise it does nothing) */

  for(auto &kv: this->bad_bbs) blacklist.push_back(kv.second);
  for(auto &kv: this->start2bb) {
    if(kv.second->trap) blacklist.push_back(kv.second);
  }

  /* Mark BBs that may fall through to a blacklisted block as invalid */
  for(auto bb: blacklist) {
    invalid = true;
    cc = bb;
    while(invalid) {
      cc = get_bb(cc->start-1, &offset);
      if(!cc) break;
      flags = cc->insns.back().flags;
      if((flags & Instruction::INS_FLAG_CFLOW) && (Instruction::INS_FLAG_INDIRECT)) {
        invalid = false;
      } else if((flags & Instruction::INS_FLAG_CALL) || (flags & Instruction::INS_FLAG_JMP)) {
        invalid = (get_bb(cc->insns.back().target, &offset) == NULL);
      } else if(flags & Instruction::INS_FLAG_RET) {
        invalid = false;
      }
      if(invalid) {
        cc->invalid = true;
        unlink_bb(cc);
        bad_bbs[cc->start] = cc;
      }
    }
  }

  /* Remove bad BBs from the CFG map */
  for(auto &kv: this->bad_bbs) {
    bb = kv.second;
    if(this->start2bb.count(bb->start)) {
      this->start2bb.erase(bb->start);
    }
  }
}


BB*
CFG::get_bb(uint64_t addr, unsigned *offset)
{
  BB *bb;
  std::map<uint64_t, BB*>::iterator it;

  if(this->start2bb.count(addr)) {
    if(offset) {
      (*offset) = 0;
    }
    return this->start2bb[addr];
  } else if(!offset) {
    return NULL;
  } else if(start2bb.empty()) {
    return NULL;
  }

  it = this->start2bb.upper_bound(addr);
  if(it == start2bb.begin()) {
    return NULL;
  }
  bb = (*(--it)).second;
  if((addr >= bb->start) && (addr < bb->end)) {
    (*offset) = addr - bb->start;
    return bb;
  }

  return NULL;
}


void
CFG::link_bbs(Edge::EdgeType type, BB *bb, uint64_t target, uint64_t jmptab)
{
  BB *cc;
  bool is_switch;
  unsigned offset;

  assert(type != Edge::EDGE_TYPE_NONE);

  is_switch = (jmptab > 0);
  cc = this->get_bb(target, &offset);
  if(cc) {
    bb->targets.push_back(Edge(type, bb, cc, is_switch, jmptab, offset));
    cc->ancestors.push_back(Edge(type, bb, cc, is_switch, jmptab, offset));
  }
}


void
CFG::unlink_bb(BB *bb)
{
  BB *cc;
  std::list<Edge>::iterator f;

  for(auto &e: bb->ancestors) {
    cc = e.src;
    for(f = cc->targets.begin(); f != cc->targets.end(); ) {
      if(f->dst == bb) f = cc->targets.erase(f);
      else f++;
    }
  }

  for(auto &e: bb->targets) {
    cc = e.dst;
    for(f = cc->ancestors.begin(); f != cc->ancestors.end(); ) {
      if(f->src == bb) f = cc->ancestors.erase(f);
      else f++;
    }
  }

  bb->ancestors.clear();
  bb->targets.clear();
}


void
CFG::unlink_edge(BB *bb, BB *cc)
{
  std::list<Edge>::iterator f;

  for(f = bb->targets.begin(); f != bb->targets.end(); ) {
    if(f->dst == cc) f = bb->targets.erase(f);
    else f++;
  }

  for(f = cc->ancestors.begin(); f != cc->ancestors.end(); ) {
    if(f->src == bb) f = cc->ancestors.erase(f);
    else f++;
  }
}


int
CFG::make_cfg(Binary *bin, std::list<DisasmSection> *disasm)
{
  uint64_t addr;
  unsigned flags;

  verbose(1, "generating cfg");

  this->binary = bin;

  for(auto &dis: (*disasm)) {
    for(auto &bb: dis.BBs) {
      if(bb.invalid) {
        this->bad_bbs[bb.start] = &bb;
        continue;
      }
      if(bb.start == bin->entry) {
        this->entry.push_back(&bb);
      }
      if(this->start2bb.count(bb.start) > 0) {
        print_warn("conflicting BBs at 0x%016jx", bb.start);
      }
      this->start2bb[bb.start] = &bb;
    }
  }

  /* Link basic blocks by direct and fallthrough edges */
  for(auto &dis: (*disasm)) {
    for(auto &bb: dis.BBs) {
      flags = bb.insns.back().flags;
      if((flags & Instruction::INS_FLAG_CALL) || (flags & Instruction::INS_FLAG_JMP)) {
        if(!(flags & Instruction::INS_FLAG_INDIRECT)) {
          addr = bb.insns.back().target;
          link_bbs(bb.insns.back().edge_type(), &bb, addr);
        }
        if((flags & Instruction::INS_FLAG_CALL) || (flags & Instruction::INS_FLAG_COND)) {
          link_bbs(Edge::EDGE_TYPE_FALLTHROUGH, &bb, bb.end);
        }
      } else if(!(flags & Instruction::INS_FLAG_CFLOW) && !bb.padding) {
        /* A block that doesn't have a control flow instruction at the end;
         * this can happen if the next block is a nop block */
        link_bbs(Edge::EDGE_TYPE_FALLTHROUGH, &bb, bb.end);
      }
    }
  }

  analyze_addrtaken();
  find_switches();
  verify_padding();
  detect_bad_bbs();

  find_functions();
  find_entry();

  verbose(1, "cfg generation complete");

  return 0;
}

