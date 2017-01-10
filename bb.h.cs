using System.Collections.Generic;

namespace Nucleus
{
    public partial class BB {
        public
          BB() { start = (0); end = (0); function = (null); section = (null); score = (0.0);
            alive = (false); invalid = (false); privileged = (false); addrtaken = (false); padding = (false); trap = (false); }

        public BB(BB bb) { start = bb.start; end = bb.end; insns = bb.insns; function = bb.function; section = bb.section; score = bb.score;
            alive = bb.alive; invalid = bb.invalid; privileged = bb.privileged; addrtaken = bb.addrtaken; padding = bb.padding; trap = bb.trap;
            ancestors = bb.ancestors; targets = bb.targets;
        }

        void reset() { start = 0; end = 0; insns.Clear(); function = null; section = null; score = 0.0;
            alive = false; invalid = false; privileged = false; addrtaken = false; padding = false; trap = false;
            ancestors.Clear(); targets.Clear(); }
        public void set(ulong start, ulong end) { reset(); this.start = start; this.end = end; }

        bool is_addrtaken() { return addrtaken; }
        bool is_padding() { return padding; }
        bool is_trap() { return trap; }
        //bool is_called    ();
        //bool returns      ();

        //void print(FILE *out);

        public static int comparator(BB bb, BB cc) { return bb.start.CompareTo(cc.start); }
        //inline bool operator<  (const BB& cc) const { return this.start < cc.start; }

        public ulong start;
        public ulong end;
        public List<Instruction> insns;
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
    }
}
