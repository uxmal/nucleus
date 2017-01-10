using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Nucleus
{

    public partial class AddressMap
    {
        [Flags]
        public enum DisasmRegion
        {
            DISASM_REGION_UNMAPPED = 0x0000,
            DISASM_REGION_CODE = 0x0001,
            DISASM_REGION_DATA = 0x0002,
            DISASM_REGION_INS_START = 0x0100,
            DISASM_REGION_BB_START = 0x0200,
            DISASM_REGION_FUNC_START = 0x0400
        };

        AddressMap() { }

        //void insert(ulong addr);
        //bool contains(ulong addr);
        //unsigned get_addr_type(ulong addr);
        //void set_addr_type(ulong addr, unsigned type);
        //void add_addr_flag(ulong addr, unsigned flag);
        //unsigned addr_type(ulong addr);

        //uint unmapped_count();
        //ulong get_unmapped(uint i);
        //void erase(ulong addr);
        //void erase_unmapped(ulong addr);

        private SortedList<ulong, DisasmRegion> addrmap;
        private List<ulong> unmapped;
        private SortedList<ulong, uint> unmapped_lookup;
    }
    public partial class DisasmSection
    {
        public DisasmSection() { section = null; }

        //void print_BBs(FILE*out);

        public Section section;
        public AddressMap addrmap;
        public List<BB> BBs;
        public List<DataRegion> data;

        //int nucleus_disasm(Binary* bin, std::list<DisasmSection>* disasm);


        public void print_BBs(TextWriter @out)
        {
            @out.WriteLine("<Section {0} {1} @0x{2:X16} (size %{3})>",
                    section.name, (section.type == Section.SectionType.SEC_TYPE_CODE) ? "C" : "D",
                    section.vma, section.size);
            @out.WriteLine();
            sort_BBs();
            foreach (var bb in BBs) {
                bb.print(@out);
            }
        }


        void
        sort_BBs()
        {
            BBs.Sort(BB.comparator);
        }
    }

    public partial class AddressMap
    {
        public void
        insert(ulong addr)
        {
            if (!contains(addr)) {
                unmapped.Add(addr);
                unmapped_lookup[addr] = (uint)unmapped.Count - 1;
            }
        }


        bool
        contains(ulong addr)
        {
            return addrmap.ContainsKey(addr) || unmapped_lookup.ContainsKey(addr);
        }


        DisasmRegion
        get_addr_type(ulong addr)
        {
            Debug.Assert(contains(addr));
            if (!contains(addr)) {
                return AddressMap.DisasmRegion.DISASM_REGION_UNMAPPED;
            } else {
                return addrmap[addr];
            }
        }
        public DisasmRegion addr_type(ulong addr) { return get_addr_type(addr); }


        void
        set_addr_type(ulong addr, AddressMap.DisasmRegion type)
        {
            Debug.Assert(contains(addr));
            if (contains(addr)) {
                if (type != AddressMap.DisasmRegion.DISASM_REGION_UNMAPPED) {
                    erase_unmapped(addr);
                }
                addrmap[addr] = type;
            }
        }


        public void
        add_addr_flag(ulong addr, DisasmRegion flag)
        {
            Debug.Assert(contains(addr));
            if (contains(addr)) {
                if (flag != DisasmRegion.DISASM_REGION_UNMAPPED) {
                    erase_unmapped(addr);
                }
                addrmap[addr] |= flag;
            }
        }


        uint
        unmapped_count()
        {
            return (uint)unmapped.Count;
        }


        ulong
        get_unmapped(int i)
        {
            return unmapped[i];
        }


        void
        erase(ulong addr)
        {
            if (addrmap.ContainsKey(addr)) {
                addrmap.Remove(addr);
            }
            erase_unmapped(addr);
        }


        void erase_unmapped(ulong addr)
        {
            uint i;

            if (unmapped_lookup.ContainsKey(addr)) {
                if (unmapped_count() > 1) {
                    i = unmapped_lookup[addr];
                    unmapped[(int)i] = unmapped[unmapped.Count - 1];
                    unmapped_lookup[unmapped[unmapped.Count - 1]] = i;
                }
                unmapped_lookup.Remove(addr);
                unmapped.RemoveAt(unmapped.Count - 1);
            }
        }
    }

    public partial class Nucleus
    {
        /*******************************************************************************
         **                            Disassembly engine                             **
         ******************************************************************************/
        public static int
init_disasm(Binary bin, List<DisasmSection> disasm)
        {

            disasm.Clear();
            for (var i = 0; i < bin.sections.Count; i++) {
                var sec = bin.sections[i];
                if ((sec.type != Section.SectionType.SEC_TYPE_CODE)
                   && !(!options.only_code_sections && (sec.type == Section.SectionType.SEC_TYPE_DATA))) continue;

                var dis = new DisasmSection();
                disasm.Add(dis);

                dis.section = sec;
                for (var vma = sec.vma; vma < (sec.vma + sec.size); vma++) {
                    dis.addrmap.insert(vma);
                }
            }
            Log.verbose(1, "disassembler initialized");

            return 0;
        }


        static int
        fini_disasm(Binary bin, List<DisasmSection> disasm)
        {
            Log.verbose(1, "disassembly complete");

            return 0;
        }


        static bool
        is_cs_nop_ins(cs_insn ins)
        {
            switch (ins.id) {
            case x86_insn.X86_INS_NOP:
            case x86_insn.X86_INS_FNOP:
                return true;;
            default:
                return false;
            }
        }


        static bool
        is_cs_semantic_nop_ins(cs_insn ins)
        {
            cs_x86 x86;

            /* XXX: to make this truly platform-independent, we need some real
             * semantic analysis, but for now checking known cases is sufficient */

            x86 = ins.detail.x86;
            switch (ins.id) {
            case x86_insn.X86_INS_MOV:
                /* mov reg,reg */
                if ((x86.op_count == 2)
                   && (x86.operands[0].type == x86_op_type.X86_OP_REG)
                   && (x86.operands[1].type == x86_op_type.X86_OP_REG)
                   && (x86.operands[0].reg == x86.operands[1].reg)) {
                    return true;;
                }
                return false;
            case x86_insn.X86_INS_XCHG:
                /* xchg reg,reg */
                if ((x86.op_count == 2)
                   && (x86.operands[0].type == x86_op_type.X86_OP_REG)
                   && (x86.operands[1].type == x86_op_type.X86_OP_REG)
                   && (x86.operands[0].reg == x86.operands[1].reg)) {
                    return true;;
                }
                return false;
            case x86_insn.X86_INS_LEA:
                /* lea    reg,[reg + 0x0] */
                if ((x86.op_count == 2)
                   && (x86.operands[0].type == x86_op_type.X86_OP_REG)
                   && (x86.operands[1].type == x86_op_type.X86_OP_MEM)
                   && (x86.operands[1].mem.segment == x86_reg.X86_REG_INVALID)
                   && (x86.operands[1].mem.@base == x86.operands[0].reg)
       && (x86.operands[1].mem.index == x86_reg.X86_REG_INVALID)
       /* mem.scale is irrelevant since index is not used */
       && (x86.operands[1].mem.disp == 0)) {
                    return true;;
                }
                /* lea    reg,[reg + eiz*x + 0x0] */
                if ((x86.op_count == 2)
                   && (x86.operands[0].type == x86_op_type.X86_OP_REG)
                   && (x86.operands[1].type == x86_op_type.X86_OP_MEM)
                   && (x86.operands[1].mem.segment == x86_reg.X86_REG_INVALID)
                   && (x86.operands[1].mem.@base == x86.operands[0].reg)
       && (x86.operands[1].mem.index == x86_reg.X86_REG_EIZ)
       /* mem.scale is irrelevant since index is the zero-register */
       && (x86.operands[1].mem.disp == 0)) {
                    return true;;
                }
                return false;
            default:
                return false;
            }
        }


        static bool
        is_cs_trap_ins(cs_insn ins)
        {
            switch (ins.id) {
            case x86_insn.X86_INS_INT3:
            case x86_insn.X86_INS_UD2:
                return true;
            default:
                return false;
            }
        }


        static bool
        is_cs_cflow_group(byte g)
        {
            return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL) || (g == CS_GRP_RET) || (g == CS_GRP_IRET);
        }


        static bool
        is_cs_cflow_ins(cs_insn ins)
        {
            uint i;

            for (i = 0; i < ins.detail.groups_count; i++) {
                if (is_cs_cflow_group(ins.detail.groups[i])) {
                    return true;;
                }
            }

            return false;
        }


        static bool 
        is_cs_call_ins(cs_insn ins)
        {
            switch (ins.id) {
            case x86_insn.X86_INS_CALL:
            case x86_insn.X86_INS_LCALL:
                return true;;
            default:
                return false;
            }
        }


        static bool
        is_cs_ret_ins(cs_insn ins)
        {
            switch (ins.id) {
            case x86_insn.X86_INS_RET:
            case x86_insn.X86_INS_RETF:
                return true;;
            default:
                return false;
            }
        }


        static bool
        is_cs_unconditional_jmp_ins(cs_insn ins)
        {
            switch (ins.id) {
            case x86_insn.X86_INS_JMP:
                return true;
            default:
                return false;
            }
        }


        static bool
        is_cs_conditional_cflow_ins(cs_insn ins)
        {
            switch (ins.id) {
            case x86_insn.X86_INS_JAE:
            case x86_insn.X86_INS_JA:
            case x86_insn.X86_INS_JBE:
            case x86_insn.X86_INS_JB:
            case x86_insn.X86_INS_JCXZ:
            case x86_insn.X86_INS_JECXZ:
            case x86_insn.X86_INS_JE:
            case x86_insn.X86_INS_JGE:
            case x86_insn.X86_INS_JG:
            case x86_insn.X86_INS_JLE:
            case x86_insn.X86_INS_JL:
            case x86_insn.X86_INS_JNE:
            case x86_insn.X86_INS_JNO:
            case x86_insn.X86_INS_JNP:
            case x86_insn.X86_INS_JNS:
            case x86_insn.X86_INS_JO:
            case x86_insn.X86_INS_JP:
            case x86_insn.X86_INS_JRCXZ:
            case x86_insn.X86_INS_JS:
                return true;
            case x86_insn.X86_INS_JMP:
            default:
                return false;
            }
        }


        static bool
        is_cs_privileged_ins(cs_insn ins)
        {
            switch (ins.id) {
            case x86_insn.X86_INS_HLT:
            case x86_insn.X86_INS_IN:
            case x86_insn.X86_INS_INSB:
            case x86_insn.X86_INS_INSW:
            case x86_insn.X86_INS_INSD:
            case x86_insn.X86_INS_OUT:
            case x86_insn.X86_INS_OUTSB:
            case x86_insn.X86_INS_OUTSW:
            case x86_insn.X86_INS_OUTSD:
            case x86_insn.X86_INS_RDMSR:
            case x86_insn.X86_INS_WRMSR:
            case x86_insn.X86_INS_RDPMC:
            case x86_insn.X86_INS_RDTSC:
            case x86_insn.X86_INS_LGDT:
            case x86_insn.X86_INS_LLDT:
            case x86_insn.X86_INS_LTR:
            case x86_insn.X86_INS_LMSW:
            case x86_insn.X86_INS_CLTS:
            case x86_insn.X86_INS_INVD:
            case x86_insn.X86_INS_INVLPG:
            case x86_insn.X86_INS_WBINVD:
                return true;
            default:
                return false;
            }
        }


        static Operand.OperandType
        cs_to_nucleus_op_type(x86_op_type op)
        {
            switch (op) {
            case x86_op_type.X86_OP_REG:
                return Operand.OperandType.OP_TYPE_REG;
            case x86_op_type.X86_OP_IMM:
                return Operand.OperandType.OP_TYPE_IMM;
            case x86_op_type.X86_OP_MEM:
                return Operand.OperandType.OP_TYPE_MEM;
            case x86_op_type.X86_OP_FP:
                return Operand.OperandType.OP_TYPE_FP;
            case x86_op_type.X86_OP_INVALID:
            default:
                return Operand.OperandType.OP_TYPE_NONE;
            }
        }

        #region Capston simulator 
        public enum cs_mode {
            CS_MODE_64 = 64,
            CS_MODE_32 = 32,
            CS_MODE_16 = 16,
        }

        static byte CS_GRP_JUMP;
        static byte CS_GRP_CALL;
        static byte CS_GRP_RET;
        static byte CS_GRP_IRET;


        public static int CS_ARCH_X86 = 0x86;

        public const int CS_ERR_OK = 0;

        public class csh
        {
            internal static void cs_option(csh cs_dis, object cS_OPT_DETAIL, object cS_OPT_ON)
            {
                throw new NotImplementedException();
            }

            internal static int cs_open(int cS_ARCH_X86, cs_mode cs_mode, out csh cs_dis)
            {
                throw new NotImplementedException();
            }

            internal static cs_insn cs_malloc(csh cs_dis)
            {
                throw new NotImplementedException();
            }

            internal bool cs_disasm_iter(ref ulong pc, ref ulong n, ref ulong pc_addr, cs_insn cs_ins)
            {
                throw new NotImplementedException();
            }

            internal static void cs_free(cs_insn cs_ins, int v)
            {
                throw new NotImplementedException();
            }

            internal void cs_close()
            {
                throw new NotImplementedException();
            }
        }

        public class cs_insn {
            internal ulong address;
            public x86_insn id;
            public byte size;
            internal string mnemonic;
            public cs_detail detail;
            internal string op_str;
        }

        public class cs_detail
        {
            public cs_x86 x86;
            internal uint groups_count;
            public byte[] groups;
        }
        public class cs_x86
        {
            public cs_x86_op[] operands;
            internal byte addr_size;
            internal int op_count;
        }

        public class cs_x86_op
        {
            internal x86_op_type type;
            public X86Value val;
            internal byte size;

            public x86_reg reg { get { return ((X86Reg)val).reg; } }
            public long imm { get { return ((X86Imm)val).imm; } }
            public double fp { get { return ((X87FP)val).fp; } }
            public X86OpMem mem { get { return ((X86OpMem)val); } }
        }

        public enum x86_insn : short
        {
            X86_INS_HLT,
            X86_INS_IN,
X86_INS_INSB,
X86_INS_INSW,
X86_INS_INSD,
X86_INS_OUT,
X86_INS_OUTSB,
X86_INS_OUTSW,
X86_INS_OUTSD,
X86_INS_RDMSR,
X86_INS_WRMSR,
X86_INS_RDPMC,
X86_INS_RDTSC,
X86_INS_LGDT,
X86_INS_LLDT,
X86_INS_LTR,
X86_INS_LMSW,
X86_INS_CLTS,
X86_INS_INVD,
X86_INS_INVLPG,
X86_INS_WBINVD,
            X86_INS_INVALID,

            X86_INS_JAE,
            X86_INS_JA,
            X86_INS_JBE,
            X86_INS_JB,
            X86_INS_JCXZ,
            X86_INS_JECXZ,
            X86_INS_JE,
            X86_INS_JGE,
            X86_INS_JG,
            X86_INS_JLE,
            X86_INS_JL,
            X86_INS_JNE,
            X86_INS_JNO,
            X86_INS_JNP,
            X86_INS_JNS,
            X86_INS_JO,
            X86_INS_JP,
            X86_INS_JRCXZ,
            X86_INS_JS,
            X86_INS_JMP,
            X86_INS_NOP,
            X86_INS_FNOP,
            X86_INS_LEA,
            X86_INS_XCHG,
            X86_INS_MOV,
            X86_INS_INT3,
            X86_INS_UD2,
            X86_INS_CALL,
            X86_INS_LCALL,
            X86_INS_RET,
            X86_INS_RETF,
        }

        public enum x86_op_type : byte
        {
            X86_OP_IMM,
            X86_OP_REG,
            X86_OP_MEM,
            X86_OP_FP,
            X86_OP_INVALID
        }

        public static int CS_OPT_DETAIL;
        public static int CS_OPT_ON;
        public static int CS_OPT_SYNTAX;
        public static int CS_OPT_SYNTAX_INTEL;

        public const int X86_INS_INVALID = -1;
        #endregion

        static int
        nucleus_disasm_bb_x86(Binary bin, DisasmSection dis, BB bb)
        {
            int ret;
            bool init, cflow, cond, call;
            bool nop, trap, only_nop, priv, jmp;
            int ndisassembled;
            csh cs_dis = null;
            cs_mode cs_mode;
            cs_insn cs_ins;
            cs_x86_op cs_op;
            ulong pc;
            ulong pc_addr, offset;
            uint i, j;
            ulong n;
            Instruction ins;
            Operand op;

            init = false;
            cs_ins = null;

            switch (bin.bits) {
            case 64:
                cs_mode = cs_mode.CS_MODE_64;
                break;
            case 32:
                cs_mode = cs_mode.CS_MODE_32;
                break;
            case 16:
                cs_mode = cs_mode.CS_MODE_16;
                break;
            default:
                Log.print_err("unsupported bit width %u for architecture %s", bin.bits, bin.arch_str);
                goto fail;
            }

            if (csh.cs_open(CS_ARCH_X86, cs_mode, out cs_dis) != CS_ERR_OK) {
                Log.print_err("failed to initialize libcapstone");
                goto fail;
            }
            init = true;
            csh.cs_option(cs_dis, CS_OPT_DETAIL, CS_OPT_ON);
            csh.cs_option(cs_dis, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

            cs_ins = csh.cs_malloc(cs_dis);
            if (cs_ins == null) {
                Log.print_err("out of memory");
                goto fail;
            }

            offset = bb.start - dis.section.vma;
            if ((bb.start < dis.section.vma) || (offset >= dis.section.size)) {
                Log.print_err("basic block address points outside of section '%s'", dis.section.name);
                goto fail;
            }

            pc = /*dis.section.bytes +*/ offset;
            n = dis.section.size - offset;
            pc_addr = bb.start;
            bb.end = bb.start;
            bb.section = dis.section;
            ndisassembled = 0;
            only_nop = false;
            while (cs_dis.cs_disasm_iter(ref pc, ref n, ref pc_addr, cs_ins)) {
                if (cs_ins.id == x86_insn.X86_INS_INVALID) {
                    bb.invalid = true;
                    bb.end += 1;
                    break;
                }
                if (cs_ins.size == 0) {
                    break;
                }

                trap = is_cs_trap_ins(cs_ins);
                nop = is_cs_nop_ins(cs_ins)
                        /* Visual Studio sometimes places semantic nops at the function start */
                        || (is_cs_semantic_nop_ins(cs_ins) && (bin.type != Binary.BinaryType.BIN_TYPE_PE))
                        /* Visual Studio uses int3 for padding */
                        || (trap && (bin.type == Binary.BinaryType.BIN_TYPE_PE));
                ret = is_cs_ret_ins(cs_ins) ? 1 : 0;
                jmp = is_cs_unconditional_jmp_ins(cs_ins) || is_cs_conditional_cflow_ins(cs_ins);
                cond = is_cs_conditional_cflow_ins(cs_ins);
                cflow = is_cs_cflow_ins(cs_ins);
                call = is_cs_call_ins(cs_ins);
                priv = is_cs_privileged_ins(cs_ins);

                if (ndisassembled == 0 && nop) only_nop = true; /* group nop instructions together */
                if (!only_nop && nop) break;
                if (only_nop && !nop) break;

                ndisassembled++;

                bb.end += (ulong) cs_ins.size;
                ins = new Instruction();
                bb.insns.Add(ins);
                if (priv) {
                    bb.privileged = true;
                }
                if (nop) {
                    bb.padding = true;
                }
                if (trap) {
                    bb.trap = true;
                }

                ins.start = cs_ins.address;
                ins.size = cs_ins.size;
                ins.addr_size = cs_ins.detail.x86.addr_size;
                ins.mnem = cs_ins.mnemonic;
                ins.op_str = cs_ins.op_str;
                ins.privileged = priv;
                ins.trap = trap;
                if (nop) ins.flags |= Instruction.InstructionFlags.INS_FLAG_NOP;
                if (ret != 0) ins.flags |= Instruction.InstructionFlags.INS_FLAG_RET;
                if (jmp) ins.flags |= Instruction.InstructionFlags.INS_FLAG_JMP;
                if (cond) ins.flags |= Instruction.InstructionFlags.INS_FLAG_COND;
                if (cflow) ins.flags |= Instruction.InstructionFlags.INS_FLAG_CFLOW;
                if (call) ins.flags |= Instruction.InstructionFlags.INS_FLAG_CALL;

                for (i = 0; i < cs_ins.detail.x86.op_count; i++) {
                    cs_op = cs_ins.detail.x86.operands[i];
                    op = new Operand();
                    ins.operands.Add(op);
                    op.type = cs_to_nucleus_op_type(cs_op.type);
                    op.size = cs_op.size;
                    if (op.type == Operand.OperandType.OP_TYPE_IMM) {
                        op.x86_value.imm = cs_op.imm;
                    } else if (op.type == Operand.OperandType.OP_TYPE_REG) {
                        op.x86_value.reg = cs_op.reg;
                        if (cflow) ins.flags |= Instruction.InstructionFlags.INS_FLAG_INDIRECT;
                    } else if (op.type == Operand.OperandType.OP_TYPE_FP) {
                        op.x86_value.fp = cs_op.fp;
                    } else if (op.type == Operand.OperandType.OP_TYPE_MEM) {
                        op.x86_value.mem.segment = cs_op.mem.segment;
                        op.x86_value.mem.@base = cs_op.mem.@base;
                        op.x86_value.mem.index = cs_op.mem.index;
                        op.x86_value.mem.scale = cs_op.mem.scale;
                        op.x86_value.mem.disp = cs_op.mem.disp;
                        if (cflow) ins.flags |= Instruction.InstructionFlags.INS_FLAG_INDIRECT;
                    }
                }

                for (i = 0; i < cs_ins.detail.groups_count; i++) {
                    if (is_cs_cflow_group(cs_ins.detail.groups[i])) {
                        for (j = 0; j < cs_ins.detail.x86.op_count; j++) {
                            cs_op = cs_ins.detail.x86.operands[j];
                            if (cs_op.type == x86_op_type.X86_OP_IMM) {
                                ins.target = (ulong) cs_op.imm;
                            }
                        }
                    }
                }

                if (cflow) {
                    /* end of basic block */
                    break;
                }
            }

            if (ndisassembled == 0) {
                bb.invalid = false;
                bb.end += 1; /* ensure forward progress */
            }

            ret = ndisassembled;
            goto cleanup;

            fail:
            ret = -1;

            cleanup:
            if (cs_ins != null) {
                csh.cs_free(cs_ins, 1);
            }
            if (init) {
                cs_dis.cs_close();
            }
            return ret;
        }

        static int
        nucleus_disasm_bb(Binary bin, DisasmSection dis, BB bb)
        {
            switch (bin.arch) {
            case Binary.BinaryArch.ARCH_X86:
                return nucleus_disasm_bb_x86(bin, dis, bb);
            default:
                Log.print_err("disassembly for architecture {0} is not supported", bin.arch_str);
                return -1;
            }
        }


        static int
        nucleus_disasm_section(Binary bin, DisasmSection dis)
        {
            int ret;
            uint i, n;
            ulong vma;
            double s;
            BB [] mutants;
            Queue<BB> Q = new Queue<BB>();

            mutants = null;

            if ((dis.section.type != Section.SectionType.SEC_TYPE_CODE) && options.only_code_sections) {
                Log.print_warn("skipping non-code section '{0}'", dis.section.name);
                return 0;
            }

            Log.verbose(2, "disassembling section '%s'", dis.section.name);

            Q.Enqueue(null);
            while (Q.Count != 0) {
                n = bb_mutate(dis, Q.Peek(), mutants);
                Q.Dequeue();
                for (i = 0; i < n; i++) {
                    if (nucleus_disasm_bb(bin, dis, mutants[i]) < 0) {
                        goto fail;
                    }
                    if ((s = bb_score(dis, mutants[i])) < 0) {
                        goto fail;
                    }
                }
                if ((n = (uint) bb_select(dis, mutants, (int) n)) < 0) {
                    goto fail;
                }
                for (i = 0; i < n; i++) {
                    if (mutants[i].alive) {
                        dis.addrmap.add_addr_flag(mutants[i].start, AddressMap.DisasmRegion.DISASM_REGION_BB_START);
                        foreach (var ins in mutants[i].insns) {
                            dis.addrmap.add_addr_flag(ins.start, AddressMap.DisasmRegion.DISASM_REGION_INS_START);
                        }
                        for (vma = mutants[i].start; vma < mutants[i].end; vma++) {
                            dis.addrmap.add_addr_flag(vma, AddressMap.DisasmRegion.DISASM_REGION_CODE);
                        }
                        var bb = new BB(mutants[i]);
                        dis.BBs.Add(bb);
                        Q.Enqueue(bb);
                    }
                }
            }

            ret = 0;
            goto cleanup;

            fail:
            ret = -1;

            cleanup:
            //if (mutants) {
            //    delete[] mutants;
            //}
            return ret;
        }


        static int
        nucleus_disasm(Binary bin, List<DisasmSection> disasm)
        {
            int ret;

            if (init_disasm(bin, disasm) < 0) {
                goto fail;
            }

            foreach (var dis in disasm) {
                if (nucleus_disasm_section(bin, dis) < 0) {
                    goto fail;
                }
            }

            if (fini_disasm(bin, disasm) < 0) {
                goto fail;
            }

            ret = 0;
            goto cleanup;

            fail:
            ret = -1;

            cleanup:
            return ret;
        }
    }
}

