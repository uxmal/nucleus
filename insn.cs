using Reko.Core;
using Reko.Core.Machine;
using System;
using System.IO;

namespace Nucleus
{
    partial class Instruction
    {
        public void print(TextWriter @out)
        {
            @out.WriteLine("  0x{0:X16}  {1}\t{0}", start, mnem, op_str);
        }
    }

    public static class InstructionExtensions
    {
        public static Address target(this MachineInstruction self)
        {
            var iLast = self.Operands.Length - 1;
            if (iLast < 0)
                return null;
            if (self.Operands[iLast] is AddressOperand addr)
                return addr.Address;
            return null;
        }

        public static Instruction.InstructionFlags flags(this MachineInstruction self)
        {
            throw new NotImplementedException();
        }

        public static Edge.EdgeType edge_type(this MachineInstruction self)
        {
            switch (self.InstructionClass & InstrClass.Transfer | InstrClass.Call) {
            case InstrClass.Transfer:
                return self.Operands[^1] is ImmediateOperand ||
                    self.Operands[^1] is AddressOperand
                    ? Edge.EdgeType.EDGE_TYPE_JMP
                    : Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT;
            case InstrClass.Transfer | InstrClass.Call:
                return self.Operands[^1] is ImmediateOperand ||
                    self.Operands[^1] is AddressOperand
                    ? Edge.EdgeType.EDGE_TYPE_CALL
                    : Edge.EdgeType.EDGE_TYPE_CALL_INDIRECT;
            //case InstrClass.Return:
            default:
                return Edge.EdgeType.EDGE_TYPE_NONE;
            }
        }

        public static Edge.EdgeType edge_type(this Instruction self)
        {
            if ((self.flags & Instruction.InstructionFlags.INS_FLAG_JMP) != 0)
            {
                return ((self.flags & Instruction.InstructionFlags.INS_FLAG_INDIRECT) != 0) ? Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT : Edge.EdgeType.EDGE_TYPE_JMP;
            }
            else if ((self.flags & Instruction.InstructionFlags.INS_FLAG_CALL) != 0)
            {
                return ((self.flags & Instruction.InstructionFlags.INS_FLAG_INDIRECT) != 0) ? Edge.EdgeType.EDGE_TYPE_CALL_INDIRECT : Edge.EdgeType.EDGE_TYPE_CALL;
            }
            else if ((self.flags & Instruction.InstructionFlags.INS_FLAG_RET) != 0)
            {
                return Edge.EdgeType.EDGE_TYPE_RET;
            }
            else
            {
                return Edge.EdgeType.EDGE_TYPE_NONE;
            }
        }
    }
}

