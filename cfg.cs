using System.Collections.Generic;
using System.Linq;

namespace Nucleus
{
    public partial class CFG
    {

        void
        CFG::print_functions(FILE*out)
        {
            foreach (var f in this.functions) {
                f.print(out);
            }
        }


        void
        CFG::print_function_summaries(FILE*out)
        {
            foreach (var f in this.functions) {
                f.print_summary(out);
            }
        }


        void
        CFG::analyze_addrtaken_x86()
        {
            BB* bb, *cc;
            Operand* op_src, *op_dst;

            foreach (var kv in this.start2bb) {
                bb = kv.second;
                foreach (var ins in bb.insns) {
                    if (ins.operands.Count < 2) {
                        continue;
                    }
                    op_dst = &ins.operands[0];
                    op_src = &ins.operands[1];
                    if (((op_dst.type == Operand::OP_TYPE_REG) || (op_dst.type == Operand::OP_TYPE_MEM))
                       && (op_src.type == Operand::OP_TYPE_IMM)) {
                        if (this.start2bb.count(op_src.x86_value.imm)) {
                            cc = this.start2bb[op_src.x86_value.imm];
                            if (!cc.addrtaken) {
                                cc.addrtaken = true;
                                verbose(3, "marking addrtaken bb@0x%016jx", cc.start);
                            }
                        }
                    }
                }
            }
        }


        void
        CFG::analyze_addrtaken()
        {
            verbose(1, "starting address-taken analysis");

            switch (this.binary.arch) {
            case Binary::ARCH_X86:
                analyze_addrtaken_x86();
                break;
            default:
                verbose(1, "address-taken analysis not supported for %s", this.binary.arch_str.c_str());
                break;
            }

            verbose(1, "address-taken analysis complete");
        }


        void
        CFG::find_switches_x86()
        {
            BB* bb, *cc;
            Edge* conflict_edge;
            Section* target_sec;
            Operand* op_target, *op_reg, *op_mem;
            int scale;
            unsigned offset;
            ulong jmptab_addr, jmptab_idx, case_addr;
            uint8_t* jmptab8;
            uint16_t* jmptab16;
            uint32_t* jmptab32;
            ulong* jmptab64;
            std::list<Instruction>::iterator ins;

            /* FIXME: get rid of the assumption that the instruction loading the
             *        jump table entry is separate from the indirect jump itself;
             *        this is often not the case in optimized binaries. For instance,
             *        in xalan compiled with gcc/x64 at O3, we currently miss instructions
             *        that index a jump table like this:
             *            jmpq   *0x7a1ae8(,%rcx,8)
             */
            foreach (var kv in this.start2bb) {
                bb = kv.second;
                jmptab_addr = 0;
                target_sec = NULL;
                /* If this BB ends in an indirect jmp, scan the BB for what looks like
                 * an instruction loading a target from a jump table */
                if (bb.insns.back().edge_type() == Edge::EDGE_TYPE_JMP_INDIRECT) {
                    if (bb.insns.back().operands.Count < 1) {
                        print_warn("Indirect jump has no target operand");
                        continue;
                    }
                    target_sec = bb.section;
                    op_target = &bb.insns.back().operands[0];
                    if (op_target.type != Operand::OP_TYPE_REG) {
                        continue;
                    }
                    ins = bb.insns.end();
                    ins--; /* Skip the jmp itself */
                    while (ins != bb.insns.begin()) {
                        ins--;
                        if (ins.operands.empty()) {
                            continue;
                        }
                        op_reg = &ins.operands[0];
                        if (op_reg.type != Operand::OP_TYPE_REG) {
                            continue;
                        } else if (op_reg.x86_value.reg != op_target.x86_value.reg) {
                            continue;
                        } else {
                            /* This is the last instruction that loads the jump target register,
                             * see if we can find a jump table address from it */
                            if (ins.operands.Count >= 2) {
                                op_mem = &ins.operands[1];
                                if (op_mem.type == Operand::OP_TYPE_MEM) {
                                    jmptab_addr = (ulong)op_mem.x86_value.mem.disp;
                                    scale = op_mem.x86_value.mem.scale;
                                }
                            } else {
                                /* No luck :-( */
                            }
                            break;
                        }
                    }
                }

                if (jmptab_addr) {
                    foreach (var sec in this.binary.sections) {
                        if (sec.contains(jmptab_addr)) {
                            verbose(4, "parsing jump table at 0x%016jx (jump at 0x%016jx)",
                                       jmptab_addr, bb.insns.back().start);
                            jmptab_idx = jmptab_addr - sec.vma;
                            jmptab8 = (uint8_t*)&sec.bytes[jmptab_idx];
                            jmptab16 = (uint16_t*)&sec.bytes[jmptab_idx];
                            jmptab32 = (uint32_t*)&sec.bytes[jmptab_idx];
                            jmptab64 = (ulong*)&sec.bytes[jmptab_idx];
                            while (1) {
                                if ((jmptab_idx + scale) >= sec.size) break;
                                jmptab_idx += scale;
                                switch (scale) {
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
                                if (!case_addr) break;
                                if (!target_sec.contains(case_addr)) {
                                    break;
                                } else {
                                    cc = this.get_bb(case_addr, &offset);
                                    if (!cc) break;
                                    conflict_edge = NULL;
                                    foreach (var e in cc.ancestors) {
                                        if (e.is_switch) {
                                            conflict_edge = &e;
                                            break;
                                        }
                                    }
                                    if (conflict_edge && (conflict_edge.jmptab <= jmptab_addr)) {
                                        verbose(3, "removing switch edge 0x%016jx . 0x%016jx (detected overlapping jump table or case)",
                                                   conflict_edge.src.insns.back().start, case_addr);
                                        unlink_edge(conflict_edge.src, cc);
                                        conflict_edge = NULL;
                                    }
                                    if (!conflict_edge) {
                                        verbose(3, "adding switch edge 0x%016jx . 0x%016jx", bb.insns.back().start, case_addr);
                                        link_bbs(Edge::EDGE_TYPE_JMP_INDIRECT, bb, case_addr, jmptab_addr);
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }


        void
        CFG::find_switches()
        {
            verbose(1, "starting switch analysis");

            switch (this.binary.arch) {
            case Binary::ARCH_X86:
                find_switches_x86();
                break;
            default:
                verbose(1, "switch analysis not supported for %s", this.binary.arch_str.c_str());
                break;
            }

            verbose(1, "switch analysis complete");
        }


        void
        CFG::expand_function(Function* f, BB* bb)
        {
            if (!bb) {
                bb = f.BBs.front();
            } else {
                if (bb.section.is_import_table()) {
                    return;
                } else if (bb.function) {
                    return;
                }
                f.add_bb(bb);
            }

            /* XXX: follow links to ancestor blocks, but NOT if this BB is called;
             * in that case it is an entry point, and we don't want to backtrack along
             * inbound edges because that causes issues with tailcalls */
            if (!bb.is_called()) {
                foreach (var e in bb.ancestors) {
                    if ((e.type == Edge::EDGE_TYPE_CALL)
                       || (e.type == Edge::EDGE_TYPE_CALL_INDIRECT)
                       || (e.type == Edge::EDGE_TYPE_RET)) {
                        continue;
                    }
                    expand_function(f, e.src);
                }
            }

            /* Follow links to target blocks */
            foreach (var e in bb.targets) {
                if ((e.type == Edge::EDGE_TYPE_CALL)
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
            BB* bb;

            verbose(1, "starting function analysis");

            /* Create function headers for all BBs that are called directly */
            foreach (var kv in this.start2bb) {
                bb = kv.second;
                if (bb.section.is_import_table() || bb.is_padding()) {
                    continue;
                }
                if (bb.is_called()) {
                    this.functions.push_back(Function());
                    this.functions.back().cfg = this;
                    this.functions.back().add_bb(bb);
                }
            }

            /* Expand functions for the directly-called header BBs */
            foreach (var f in this.functions) {
                expand_function(&f, NULL);
                f.find_entry();
            }

            /* Detect functions for remaining BBs through connected-component analysis */
            foreach (var kv in this.start2bb) {
                bb = kv.second;
                if (bb.section.is_import_table() || bb.is_padding()) {
                    continue;
                } else if (bb.function) {
                    continue;
                }
                this.functions.push_back(Function());
                this.functions.back().cfg = this;
                expand_function(&this.functions.back(), bb);
                this.functions.back().find_entry();
            }

            verbose(1, "function analysis complete");
        }


        void
        CFG::find_entry()
        {
            ulong entry;

            if (this.entry.Count > 0) {
                /* entry point already known */
                verbose(3, "cfg entry point@0x%016jx", this.entry.front().start);
                return;
            }

            verbose(1, "scanning for cfg entry point");

            entry = 0;
            verbose(1, "cfg entry point@0x%016jx", entry);
        }


        void
        CFG::verify_padding()
        {
            BB* bb;
            bool call_fallthrough;
            unsigned noplen;

            /* Fix incorrectly identified padding blocks (they turned out to be reachable) */
            foreach (var kv in this.start2bb) {
                bb = kv.second;
                if (bb.trap) continue;
                if (bb.padding && !bb.ancestors.empty()) {
                    call_fallthrough = false;
                    noplen = (bb.end - bb.start);
                    foreach (var e in bb.ancestors) {
                        if ((e.type == Edge::EDGE_TYPE_FALLTHROUGH)
                           && (e.src.insns.back().flags & Instruction::INS_FLAG_CALL)) {
                            /* This padding block may not be truly reachable; the preceding
                             * call may be non-returning */
                            call_fallthrough = true;
                            break;
                        }
                    }
                    if (call_fallthrough && (noplen > 1)) continue;
                    bb.padding = false;
                    link_bbs(Edge::EDGE_TYPE_FALLTHROUGH, bb, bb.end);
                }
            }
        }


        void
        detect_bad_bbs()
        {
            BB bb, cc;
            bool invalid;
            unsigned flags, offset;
            List<BB> blacklist = new List<BB>();

            /* This improves accuracy for code with inline data (otherwise it does nothing) */

            foreach (var kv in this.bad_bbs) blacklist.Add(kv.Value);
            foreach (var kv in this.start2bb) {
                if (kv.Value.trap) blacklist.Add(kv.Value);
            }

            /* Mark BBs that may fall through to a blacklisted block as invalid */
            foreach (var bb in blacklist) {
                invalid = true;
                cc = bb;
                while (invalid) {
                    cc = get_bb(cc.start - 1, &offset);
                    if (!cc) break;
                    flags = cc.insns.back().flags;
                    if ((flags & Instruction::INS_FLAG_CFLOW) && (Instruction::INS_FLAG_INDIRECT)) {
                        invalid = false;
                    } else if ((flags & Instruction::INS_FLAG_CALL) || (flags & Instruction::INS_FLAG_JMP)) {
                        invalid = (get_bb(cc.insns.back().target, &offset) == NULL);
                    } else if (flags & Instruction::INS_FLAG_RET) {
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
            foreach (var kv in this.bad_bbs) {
                bb = kv.second;
                if (this.start2bb.count(bb.start)) {
                    this.start2bb.erase(bb.start);
                }
            }
        }


        BB
        get_bb(ulong addr, out uint offset)
        {
            BB bb;
            std::map<ulong, BB*>::iterator it;

            if (this.start2bb.ContainsKey(addr)) {
                    offset = 0;
                return this.start2bb[addr];
            } else if (start2bb.Count == 0) {
                offset = 0;
                return null;
            }

            it = this.start2bb.upper_bound(addr);
            if (it == start2bb.begin()) {
                return NULL;
            }
            bb = (*(--it)).second;
            if ((addr >= bb.start) && (addr < bb.end)) {
                (*offset) = addr - bb.start;
                return bb;
            }

            return NULL;
        }


        void
        link_bbs(Edge.EdgeType type, BB bb, ulong target, ulong jmptab)
        {
            BB cc;
            bool is_switch;
            unsigned offset;

            assert(type != Edge::EDGE_TYPE_NONE);

            is_switch = (jmptab > 0);
            cc = this.get_bb(target, &offset);
            if (cc) {
                bb.targets.push_back(Edge(type, bb, cc, is_switch, jmptab, offset));
                cc.ancestors.push_back(Edge(type, bb, cc, is_switch, jmptab, offset));
            }
        }


        void
        CFG::unlink_bb(BB* bb)
        {
            BB* cc;
            std::list<Edge>::iterator f;

            foreach (var e in bb.ancestors) {
                cc = e.src;
                for (f = cc.targets.begin(); f != cc.targets.end();) {
                    if (f.dst == bb) f = cc.targets.erase(f);
                    else f++;
                }
            }

            foreach (var e in bb.targets) {
                cc = e.dst;
                for (f = cc.ancestors.begin(); f != cc.ancestors.end();) {
                    if (f.src == bb) f = cc.ancestors.erase(f);
                    else f++;
                }
            }

            bb.ancestors.clear();
            bb.targets.clear();
        }


        void
        unlink_edge(BB bb, BB cc)
        {
            //std::list<Edge>::iterator f;

            bb.targets.RemoveAll(f => f.dst == cc);
            cc.ancestors.RemoveAll(f => f.src == bb);
        }


        int
        make_cfg(Binary bin, List<DisasmSection> disasm)
        {
            ulong addr;
            unsigned flags;

            Log.verbose(1, "generating cfg");

            this.binary = bin;

            foreach (var dis in disasm) {
                foreach (var bb in dis.BBs) {
                    if (bb.invalid) {
                        this.bad_bbs[bb.start] = bb;
                        continue;
                    }
                    if (bb.start == bin.entry) {
                        this.entry.Add(bb);
                    }
                    if (this.start2bb.ContainsKey(bb.start)) {
                        Log.print_warn("conflicting BBs at 0x{0:X16}", bb.start);
                    }
                    this.start2bb[bb.start] = bb;
                }
            }

            /* Link basic blocks by direct and fallthrough edges */
            foreach (var dis in disasm) {
                foreach (var bb in dis.BBs) {
                    flags = bb.insns.Last().flags;
                    if ((flags & Instruction.InstructionFlags.INS_FLAG_CALL) != 0 || (flags & Instruction.InstructionFlags.INS_FLAG_JMP) != 0) {
                        if ((flags & Instruction.InstructionFlags.INS_FLAG_INDIRECT) == 0) {
                            addr = bb.insns.Last().target;
                            link_bbs(bb.insns.Last().edge_type(), bb, addr);
                        }
                        if ((flags & Instruction.InstructionFlags.INS_FLAG_CALL) != 0 || (flags & Instruction.InstructionFlags.INS_FLAG_COND)) {
                            link_bbs(Edge.EdgeType.EDGE_TYPE_FALLTHROUGH, bb, bb.end);
                        }
                    } else if ((flags & Instruction.InstructionFlags.INS_FLAG_CFLOW) == 0 && !bb.padding) {
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

            verbose(1, "cfg generation complete");

            return 0;
        }
    }
}

