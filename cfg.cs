using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

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

        public void
        print_function_summaries(TextWriter @out)
        {
            foreach (var f in this.functions) {
                f.print_summary(@out);
            }
        }

        void
        analyze_addrtaken_x86()
        {
            BB bb, cc;
            Operand op_src, op_dst;

            foreach (var kv in this.start2bb) {
                bb = kv.Value;
                foreach (var ins in bb.insns) {
                    if (ins.operands.Count < 2) {
                        continue;
                    }
                    op_dst = ins.operands[0];
                    op_src = ins.operands[1];
                    if (((op_dst.type == Operand.OperandType.OP_TYPE_REG) || (op_dst.type == Operand.OperandType.OP_TYPE_MEM))
                       && (op_src.type == Operand.OperandType.OP_TYPE_IMM)) {
                        if (this.start2bb.ContainsKey((ulong)op_src.x86_value.imm)) {
                            cc = this.start2bb[(ulong)op_src.x86_value.imm];
                            if (!cc.addrtaken) {
                                cc.addrtaken = true;
                                Log.verbose(3, "marking addrtaken bb@0x%016jx", cc.start);
                            }
                        }
                    }
                }
            }
        }


        void
        analyze_addrtaken()
        {
            Log.verbose(1, "starting address-taken analysis");

            switch (this.binary.arch) {
            case Binary.BinaryArch.ARCH_X86:
                analyze_addrtaken_x86();
                break;
            default:
                Log.verbose(1, "address-taken analysis not supported for %s", this.binary.arch_str);
                break;
            }

            Log.verbose(1, "address-taken analysis complete");
        }

        private IEnumerator<T> read<T>(byte[] bytes, ulong offset)
        {
            throw new NotImplementedException();
        }

        private T moar<T>(IEnumerator<T> e)
        {
            e.MoveNext();
            return e.Current;
        }

        void
        find_switches_x86()
        {
            BB bb, cc;
            Edge conflict_edge;
            Section target_sec;
            Operand op_target, op_reg, op_mem;
            int scale = 0;
            int offset;
            ulong jmptab_addr, jmptab_idx, case_addr;
            Instruction ins;
            ///*/*std::*/*/list<Instruction>::iterator ins;

            /* FIXME: get rid of the assumption that the instruction loading the
             *        jump table entry is separate from the indirect jump itself;
             *        this is often not the case in optimized binaries. For instance,
             *        in xalan compiled with gcc/x64 at O3, we currently miss instructions
             *        that index a jump table like this:
             *            jmpq   *0x7a1ae8(,%rcx,8)
             */
            foreach (var kv in this.start2bb) {
                bb = kv.Value;
                jmptab_addr = 0;
                target_sec = null;
                /* If this BB ends in an indirect jmp, scan the BB for what looks like
                 * an instruction loading a target from a jump table */
                if (bb.insns.Last().edge_type() == Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT) {
                    if (bb.insns.Last().operands.Count < 1) {
                        Log.print_warn("Indirect jump has no target operand");
                        continue;
                    }
                    target_sec = bb.section;
                    op_target = bb.insns.Last().operands[0];
                    if (op_target.type != Operand.OperandType.OP_TYPE_REG) {
                        continue;
                    }
                    int iins = bb.insns.Count;
                    iins--; /* Skip the jmp itself */
                    while (iins > 0) {
                        iins--;
                        ins = bb.insns[iins];
                        if (ins.operands.Count == 0) {
                            continue;
                        }
                        op_reg = ins.operands[0];
                        if (op_reg.type != Operand.OperandType.OP_TYPE_REG) {
                            continue;
                        } else if (op_reg.x86_value.reg != op_target.x86_value.reg) {
                            continue;
                        } else {
                            /* This is the last instruction that loads the jump target register,
                             * see if we can find a jump table address from it */
                            if (ins.operands.Count >= 2) {
                                op_mem = ins.operands[1];
                                if (op_mem.type == Operand.OperandType.OP_TYPE_MEM) {
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

                if (jmptab_addr != 0) {
                    foreach (var sec in this.binary.sections) {
                        if (sec.contains(jmptab_addr)) {
                            Log.verbose(4, "parsing jump table at 0x%016jx (jump at 0x%016jx)",
                                       jmptab_addr, bb.insns.Last().start);
                            jmptab_idx = jmptab_addr - sec.vma;
                            var jmptab8 =  read<byte>(sec.bytes,jmptab_idx);
                            var jmptab16 = read<ushort>(sec.bytes,jmptab_idx);
                            var jmptab32 = read<uint>(sec.bytes,jmptab_idx);
                            var jmptab64 = read<ulong>(sec.bytes,jmptab_idx);
                            while (true) {
                                if ((jmptab_idx + (ulong)scale) >= sec.size) break;
                                jmptab_idx += (uint)scale;
                                switch (scale) {
                                case 1:
                                    case_addr =  moar(jmptab8);
                                    break;
                                case 2:
                                    case_addr = moar(jmptab16);
                                    break;
                                case 4:
                                    case_addr = moar(jmptab32);
                                    break;
                                case 8:
                                    case_addr = moar(jmptab64);
                                    break;
                                default:
                                    Log.print_warn("Unexpected scale factor in memory operand: %d", scale);
                                    case_addr = 0;
                                    break;
                                }
                                if (case_addr == 0) break;
                                if (!target_sec.contains(case_addr)) {
                                    break;
                                } else {
                                    cc = this.get_bb(case_addr, out offset);
                                    if (cc == null) break;
                                    conflict_edge = null;
                                    foreach (var e in cc.ancestors) {
                                        if (e.is_switch) {
                                            conflict_edge = e;
                                            break;
                                        }
                                    }
                                    if (conflict_edge != null && (conflict_edge.jmptab <= jmptab_addr)) {
                                        Log.verbose(3, "removing switch edge 0x%016jx -> 0x%016jx (detected overlapping jump table or case)",
                                                   conflict_edge.src.insns.Last().start, case_addr);
                                        unlink_edge(conflict_edge.src, cc);
                                        conflict_edge = null;
                                    }
                                    if (conflict_edge == null) {
                                        Log.verbose(3, "adding switch edge 0x%016jx . 0x%016jx", bb.insns.Last().start, case_addr);
                                        link_bbs(Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT, bb, case_addr, jmptab_addr);
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
        find_switches()
        {
            Log.verbose(1, "starting switch analysis");

            switch (this.binary.arch) {
            case Binary.BinaryArch.ARCH_X86:
                find_switches_x86();
                break;
            default:
                Log.verbose(1, "switch analysis not supported for %s", this.binary.arch_str);
                break;
            }

            Log.verbose(1, "switch analysis complete");
        }


        void
        expand_function(Function f, BB bb)
        {
            if (bb == null) {
                bb = f.BBs[0];
            } else {
                if (bb.section.is_import_table()) {
                    return;
                } else if (bb.function != null) {
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


        public void
        find_functions()
        {
            Log.verbose(1, "starting function analysis");

            /* Create function headers for all BBs that are called directly */
            foreach (var kv in this.start2bb) {
                var bb = kv.Value;
                if (bb.section.is_import_table() || bb.is_padding()) {
                    continue;
                }
                if (bb.is_called()) {
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
                if (bb.section.is_import_table() || bb.is_padding()) {
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


        void
        find_entry()
        {
            ulong entry;

            if (this.entry.Count > 0) {
                /* entry point already known */
                Log.verbose(3, "cfg entry point@0x%016jx", this.entry.First().start);
                return;
            }

            Log.verbose(1, "scanning for cfg entry point");

            entry = 0;
            Log.verbose(1, "cfg entry point@0x%016jx", entry);
        }


        void
        verify_padding()
        {
            bool call_fallthrough;
            ulong noplen;

            /* Fix incorrectly identified padding blocks (they turned out to be reachable) */
            foreach (var kv in this.start2bb) {
                var bb = kv.Value;
                if (bb.trap) continue;
                if (bb.padding && bb.ancestors.Count > 0) {
                    call_fallthrough = false;
                    noplen = (bb.end - bb.start);
                    foreach (var e in bb.ancestors) {
                        if ((e.type == Edge.EdgeType.EDGE_TYPE_FALLTHROUGH)
                           && (e.src.insns.Last().flags & Instruction.InstructionFlags.INS_FLAG_CALL) != 0) {
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


        void
        detect_bad_bbs()
        {
            BB cc;
            bool invalid;
            int offset;
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
                    cc = get_bb(cc.start - 1, out offset);
                    if (cc == null)
                        break;
                    var flags = cc.insns.Last().flags;
                    if ((flags & Instruction.InstructionFlags.INS_FLAG_CFLOW) != 0 && (Instruction.InstructionFlags.INS_FLAG_INDIRECT) != 0) {
                        invalid = false;
                    } else if ((flags & Instruction.InstructionFlags.INS_FLAG_CALL) !=0 || (flags & Instruction.InstructionFlags.INS_FLAG_JMP) !=0) {
                        invalid = (get_bb(cc.insns.Last().target, out offset) == null);
                    } else if ((flags & Instruction.InstructionFlags.INS_FLAG_RET) != 0) {
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


        BB
        get_bb(ulong addr, out int offset)
        {
            BB bb;
            ///*std::*/map<ulong, BB>::iterator it;

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
                bb = this.start2bb.Values[mid];
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


        void
        link_bbs(Edge.EdgeType type, BB bb, ulong target, ulong jmptab = 0)
        {
            BB cc;
            bool is_switch;
            int offset;

            Debug.Assert(type != Edge.EdgeType.EDGE_TYPE_NONE);

            is_switch = (jmptab > 0);
            cc = this.get_bb(target, out offset);
            if (cc!= null) {
                bb.targets.Add(new Edge(type, bb, cc, is_switch, jmptab, offset));
                cc.ancestors.Add(new Edge(type, bb, cc, is_switch, jmptab, offset));
            }
        }


        void
        unlink_bb(BB bb)
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


        void
        unlink_edge(BB bb, BB cc)
        {
            //std::list<Edge>::iterator f;

            bb.targets.RemoveAll(f => f.dst == cc);
            cc.ancestors.RemoveAll(f => f.src == bb);
        }


        public int
        make_cfg(Binary bin, List<DisasmSection> disasm)
        {
            ulong addr;

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
                    var flags = bb.insns.Last().flags;
                    if ((flags & Instruction.InstructionFlags.INS_FLAG_CALL) != 0 || (flags & Instruction.InstructionFlags.INS_FLAG_JMP) != 0) {
                        if ((flags & Instruction.InstructionFlags.INS_FLAG_INDIRECT) == 0) {
                            addr = bb.insns.Last().target;
                            link_bbs(bb.insns.Last().edge_type(), bb, addr);
                        }
                        if ((flags & Instruction.InstructionFlags.INS_FLAG_CALL) != 0 || (flags & Instruction.InstructionFlags.INS_FLAG_COND) != 0) {
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

            Log.verbose(1, "cfg generation complete");

            return 0;
        }
    }
}

