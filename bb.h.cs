using System.Collections.Generic;

namespace Nucleus
{
    using NInstruction = Reko.Core.Machine.MachineInstruction;

    public partial class BB
    {
        public BB()
        {
            start = 0; end = 0; function = null; section = null; score = 0.0;
            alive = false; invalid = false; privileged = false; addrtaken = false; padding = false; trap = false;
        }

        public BB(BB bb)
        {
            start = bb.start; end = bb.end; insns = bb.insns; function = bb.function; section = bb.section; score = bb.score;
            alive = bb.alive; invalid = bb.invalid; privileged = bb.privileged; addrtaken = bb.addrtaken; padding = bb.padding; trap = bb.trap;
            ancestors = bb.ancestors; targets = bb.targets;
        }

	    public void reset()
	    {
	        start = 0; end = 0; insns.Clear(); function = null; section = null; score = 0.0;
	        alive = false; invalid = false; privileged = false; addrtaken = false; padding = false; trap = false;
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
        public List<NInstruction> insns = new();
        public Function function;
        public Section section;

        public double score;
        public bool alive;
        public bool invalid;
        public bool privileged;
        public bool addrtaken;
        public bool padding;
        public bool trap;

        public List<Edge> ancestors = new();
        public List<Edge> targets = new();
    }
}
