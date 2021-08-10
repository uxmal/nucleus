using Reko.Core;
using Reko.Core.Machine;
using System;
using System.IO;

namespace Nucleus
{
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

        public static InstructionFlags flags(this MachineInstruction self)
        {
            InstructionFlags f = 0;
            if ((self.InstructionClass & InstrClass.Transfer) == InstrClass.Transfer)
                f |= InstructionFlags.INS_FLAG_CFLOW;
            switch (self.InstructionClass & (InstrClass.Call|InstrClass.Transfer|InstrClass.Return))
            {
            case InstrClass.Transfer:
                f |= InstructionFlags.INS_FLAG_JMP; break;
            case InstrClass.Transfer|InstrClass.Call:
                f |= InstructionFlags.INS_FLAG_CALL; break;
            case InstrClass.Transfer | InstrClass.Return:
                f |= InstructionFlags.INS_FLAG_RET; break;
            }
            if ((self.InstructionClass & InstrClass.ConditionalTransfer) == InstrClass.ConditionalTransfer)
                f |= InstructionFlags.INS_FLAG_COND;
            return f;
        }

        public static Edge.EdgeType edge_type(this MachineInstruction self)
        {
            var last_op = self.Operands[^1];
            switch (self.InstructionClass & InstrClass.Transfer | InstrClass.Call) {
            case InstrClass.Transfer:
                return last_op is ImmediateOperand ||
                       last_op is AddressOperand
                    ? Edge.EdgeType.EDGE_TYPE_JMP
                    : Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT;
            case InstrClass.Transfer | InstrClass.Call:
                if (self.Operands.Length == 0)
                    return Edge.EdgeType.EDGE_TYPE_RET;
                return last_op switch
                {
                    AddressOperand _ => Edge.EdgeType.EDGE_TYPE_CALL,
                    ImmediateOperand _ => Edge.EdgeType.EDGE_TYPE_CALL,
                    _ => Edge.EdgeType.EDGE_TYPE_CALL_INDIRECT
                };
            //case InstrClass.Return:
            default:
                return Edge.EdgeType.EDGE_TYPE_NONE;
            }
        }

        /*
        public static Edge.EdgeType edge_type(this Instruction self)
        {
            if ((self.flags & InstructionFlags.INS_FLAG_JMP) != 0)
            {
                return ((self.flags & InstructionFlags.INS_FLAG_INDIRECT) != 0) ? Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT : Edge.EdgeType.EDGE_TYPE_JMP;
            }
            else if ((self.flags & InstructionFlags.INS_FLAG_CALL) != 0)
            {
                return ((self.flags & InstructionFlags.INS_FLAG_INDIRECT) != 0) ? Edge.EdgeType.EDGE_TYPE_CALL_INDIRECT : Edge.EdgeType.EDGE_TYPE_CALL;
            }
            else if ((self.flags & InstructionFlags.INS_FLAG_RET) != 0)
            {
                return Edge.EdgeType.EDGE_TYPE_RET;
            }
            else
            {
                return Edge.EdgeType.EDGE_TYPE_NONE;
            }
        }
        */
    }
}

