using System.IO;
using System.Linq;

namespace Nucleus
{
    public partial class BB
    {
        public void print(TextWriter @out)
        {
            @out.WriteLine("BB @0x{0:X16} (score {1,10} {2}{3}{4}{5}{6} {{",
                    start, score, invalid ? "i" : "-", privileged ? "p" : "-",
                    addrtaken ? "a" : "-", padding ? "n" : "-");
            if (invalid)
            {
                @out.Write("  0x%016jx  (bad)", start);
            }
            else
            {
                foreach (var ins in insns)
                {
                    @out.WriteLine(ins.ToString());
                }
            }
            if (ancestors.Count > 0)
            {
                @out.Write("--A ancestors:\n");
                foreach (var e in ancestors)
                {
                    @out.Write("--A 0x{0} ({1})\n", e.src.insns.Last().Address, e.type2str());
                }
            }
            if (targets.Count > 0)
            {
                @out.Write("--T targets:\n");
                foreach (var e in targets)
                {
                    @out.Write("--T 0x%016jx (%s)\n", e.dst.start + (uint) e.offset, e.type2str());
                }
            }
            @out.Write("}\n\n");
        }


        public bool is_called()
        {
            foreach (var e in ancestors)
            {
                if ((e.type == Edge.EdgeType.EDGE_TYPE_CALL)
                   || (e.type == Edge.EdgeType.EDGE_TYPE_CALL_INDIRECT))
                {
                    return true;
                }
            }

            return false;
        }


        bool returns()
        {
            return (insns[^1].flags() & Instruction.InstructionFlags.INS_FLAG_RET) != 0;
        }
    }
}

