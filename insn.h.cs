using System;

namespace Nucleus
{
    using System.Collections.Generic;
    using System.IO;

    public partial class Operand {
        public
          enum OperandType : byte {
            OP_TYPE_NONE = 0,
            OP_TYPE_REG = 1,
            OP_TYPE_IMM = 2,
            OP_TYPE_MEM = 3,
            OP_TYPE_FP = 4
        };

        public Operand() { type = OperandType.OP_TYPE_NONE; size=0; x86_value = new X86Value(); }
        public Operand(Operand op) {  type = op.type; size=op.size; x86_value = op.x86_value.Clone(); }

        public OperandType type;
        public byte size;

        public X86Value x86_value;
        //union X86Value {
        //  X86Value() { mem.segment = 0; mem.base = 0; mem.index = 0; mem.scale = 0; mem.disp = 0; }
        //  X86Value(const X86Value &v) { mem.segment = v.mem.segment; mem.base = v.mem.base;
        //                                mem.index = v.mem.index; mem.scale = v.mem.scale; 
        //                                mem.disp = v.mem.disp; }

        //  x86_reg    reg;
        //  int64_t    imm;
        //  double     fp;
        //  x86_op_mem mem;
        //} x86_value; /* Only set if the arch is x86 */
    }

    public enum x86_reg
    {
        eax, ecx, edx, ebx,
        X86_REG_INVALID,
        X86_REG_EIZ
    }

    public class X86Value
    {
        public X86Value value;
        public virtual X86Value Clone() { return this; }

        public x86_reg reg { get { return ((X86Reg)value).reg; } set { this.value = new X86Reg { reg = value }; } }
        public long imm { get { return ((X86Imm)value).imm; } set { this.value = new X86Imm { imm = value }; } }
        public double fp { get { return ((X87FP)value).fp; } set { this.value = new X87FP { fp = value }; } }
        public X86OpMem mem { get { return (X86OpMem)value; } set { this.value = value; } }
    }

    public class X86Reg : X86Value
    {
        public new x86_reg reg { get { return base.reg; } set { base.reg = value; } }
    }

    public class X86Imm : X86Value
    {
        public new long imm { get { return base.imm; } set { base.imm = value; } }
    }

    public class X87FP : X86Value
    {
    }

    public class X86OpMem : X86Value
    {
        public x86_reg segment;
        public x86_reg @base;
        public x86_reg index;
        public int disp;
        public byte scale;
    }

    [Flags]
    public enum InstructionFlags : short
    {
        INS_FLAG_CFLOW = 0x001,
        INS_FLAG_COND = 0x002,
        INS_FLAG_INDIRECT = 0x004,
        INS_FLAG_JMP = 0x008,
        INS_FLAG_CALL = 0x010,
        INS_FLAG_RET = 0x020,
        INS_FLAG_NOP = 0x040
    }

    /*
    public partial class Instruction {



        public Instruction() { id = 0;  start = 0; size = 0; addr_size = 0; target = 0; flags = 0; invalid = false; privileged = false; trap = false; }
        public Instruction(Instruction i) {
            id = i.id; start = i.start; size = i.size; addr_size = i.addr_size; target = i.target; flags = i.flags;
            mnem = i.mnem; op_str = i.op_str; operands = i.operands; invalid = i.invalid; privileged = i.privileged; trap = i.trap; }

        public uint id;
        public ulong start;
        public byte size;
        public byte addr_size;
        public ulong target;
        public InstructionFlags flags;
        public string mnem;
        public string op_str;
        public List<Operand> operands = new List<Operand>();
        public bool invalid;
        public bool privileged;
        public bool trap;
    }
    */
}

