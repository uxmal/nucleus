using System;
using System.IO;

namespace Nucleus
{
    partial class Instruction
    {
        public void
        print(TextWriter @out)
        {
            @out.WriteLine("  0x{0:X16}  {1}\t{0}", start, mnem, op_str);
        }

        public Edge.EdgeType edge_type()
        {
            if ((flags & InstructionFlags.INS_FLAG_JMP) != 0)
            {
                return ((flags & InstructionFlags.INS_FLAG_INDIRECT) != 0) ? Edge.EdgeType.EDGE_TYPE_JMP_INDIRECT : Edge.EdgeType.EDGE_TYPE_JMP;
            }
            else if ((flags & InstructionFlags.INS_FLAG_CALL) != 0)
            {
                return ((flags & InstructionFlags.INS_FLAG_INDIRECT) != 0) ? Edge.EdgeType.EDGE_TYPE_CALL_INDIRECT : Edge.EdgeType.EDGE_TYPE_CALL;
            }
            else if ((flags & InstructionFlags.INS_FLAG_RET) != 0)
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

