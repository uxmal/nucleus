using System.IO;
using System.Linq;
using System.Collections.Generic;
using Reko.Core.Machine;

namespace Nucleus
{

    public partial class BB
    {
        public BB()
        {
            start = 0; end = 0; function = null; section = null; score = 0.0;
            alive = false; invalid = false; privileged = false; addrtaken = false; padding = false; trap = false;
            insns = new List<MachineInstruction>();
            ancestors = new List<Edge>();
            targets = new List<Edge>();
        }

        public BB(BB bb)
        {
            start = bb.start; end = bb.end; function = bb.function; section = bb.section; score = bb.score;
            alive = bb.alive; invalid = bb.invalid; privileged = bb.privileged; addrtaken = bb.addrtaken; padding = bb.padding; trap = bb.trap;
            insns = new List<MachineInstruction>(bb.insns);
            ancestors = new List<Edge>(bb.ancestors);
            targets = new List<Edge>(bb.targets);
        }

        public void reset()
        {
            start = 0; end = 0; function = null; section = null; score = 0.0;
            alive = false; invalid = false; privileged = false; addrtaken = false; padding = false; trap = false;
            insns.Clear(); 
            ancestors.Clear();
            targets.Clear();
        }

        public void set(ulong start, ulong end) { reset(); this.start = start; this.end = end; }

        public bool is_addrtaken() { return addrtaken; }
        public bool is_invalid() { return invalid; }
        public bool is_padding() { return padding; }
        public bool is_trap() { return trap; }

        public static int comparator(BB bb, BB cc) { return bb.start.CompareTo(cc.start); }

        public ulong start;
        public ulong end;
        public List<MachineInstruction> insns;
        public Function function;
        public Section section;

        public double score;
        public bool alive;
        public bool invalid;
        public bool privileged;
        public bool addrtaken;
        public bool padding;
        public bool trap;

        public List<Edge> ancestors;
        public List<Edge> targets;

        public override string ToString()
        {
            return summary();
        }

        private string summary()
        {
            return string.Format("BB @0x{0:X16} (score {1,6}) {2}{3}{4}{5} {{",
                    start,
                    score,
                    invalid ? "i" : "-",
                    privileged ? "p" : "-",
                    addrtaken ? "a" : "-",
                    padding ? "n" : "-");
        }

        public void print(TextWriter @out)
        {
            @out.WriteLine(summary());
            if (invalid)
            {
                @out.WriteLine("  0x{0:X16}  (bad)", start);
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
                @out.WriteLine("--A ancestors:");
                foreach (var e in ancestors)
                {
                    @out.WriteLine("--A 0x{0} ({1})", e.src.insns.Last().Address, e.type2str());
                }
            }
            if (targets.Count > 0)
            {
                @out.WriteLine("--T targets:");
                foreach (var e in targets)
                {
                    @out.WriteLine("--T 0x{0} ({1})", e.dst.start + (uint) e.offset, e.type2str());
                }
            }
            @out.WriteLine("}");
            @out.WriteLine();
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
            return (insns[^1].flags() & InstructionFlags.INS_FLAG_RET) != 0;
        }
    }
}

