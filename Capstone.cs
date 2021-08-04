using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nucleus
{
    public static class capstone
    {
        #region Capstone simulator 
        public enum cs_mode
        {
            CS_MODE_64 = 64,
            CS_MODE_32 = 32,
            CS_MODE_16 = 16,
        }

        public static byte CS_GRP_JUMP;
        public static byte CS_GRP_CALL;
        public static byte CS_GRP_RET;
        public static byte CS_GRP_IRET;


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

        public class cs_insn
        {
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
    }
}