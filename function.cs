using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Nucleus
{
    public partial class Function
    {
        private static ulong global_id = 0;

        public CFG cfg;
        public ulong id;
        public ulong start;
        public ulong end;
        public List<BB> entry = new List<BB>();
        public List<BB> BBs = new List<BB>();

        public Function() { cfg = null; start = 0; end = 0; id = global_id++; }

        public void print(TextWriter @out)
        {
            uint i;
            uint offset;

            if (entry.Count == 0)
            {
                @out.WriteLine("function %ju: start@0x%016jx end@0x%016jx (entry point unknown)", id, start, end);
            }
            else
            {
                i = 0;
                foreach (var entry_bb in entry)
                {
                    offset = 0;
                    foreach (var e in entry_bb.ancestors)
                    {
                        if (e.type == Edge.EdgeType.EDGE_TYPE_CALL) offset =(uint) e.offset;
                    }
                    if (i == 0)
                    {
                        @out.WriteLine("function {0}: entry@0x{1:X16} {2} bytes", id, entry_bb.start + offset, (end - entry_bb.start));
                        if (entry.Count > 1)
                        {
                            @out.WriteLine("/-- alternative entry points:");
                        }
                    }
                    else
                    {
                        @out.WriteLine("/-- 0x%016jx", entry_bb.start + offset);
                    }
                    i++;
                }
            }
            foreach (var bb in BBs)
            {
                @out.WriteLine("    BB@0x%016jx\n", bb.start);
            }
        }


        public void print_summary(TextWriter @out)
        {
            BB entry_bb;
            int offset;

            if (entry.Count == 0)
            {
                @out.WriteLine("0x0\t\t\t%ju", end - start);
            }
            else
            {
                entry_bb = entry[0];
                offset = 0;
                foreach (var e in entry_bb.ancestors)
                {
                    if (e.type == Edge.EdgeType.EDGE_TYPE_CALL) offset = e.offset;
                }
                @out.WriteLine("0x%016jx\t%ju", entry_bb.start + (uint)offset, (end - entry_bb.start));
            }
        }


        public void find_entry()
        {
            bool reached_directly;
            List<BB> called = new List<BB>();
            List<BB> headers = new List<BB>();

            /* Entries are sorted by priority as follows:
             * (1) Called BBs in order of increasing address
             * (2) Ancestor-less BBs in order of increasing address
             * (3) Starting address of the function (only if no other entry found)
             */

            foreach (var bb in this.BBs)
            {
                if (bb.is_called())
                {
                    called.Add(bb);
                }
            }

            called.Sort((a, b) => a.start.CompareTo(b.start));
            foreach (var bb in called) this.entry.Add(bb);

            foreach (var bb in this.BBs)
            {
                reached_directly = false;
                foreach (var e in bb.ancestors)
                {
                    if (e.offset == 0) reached_directly = true;
                }
                if (!reached_directly)
                {
                    headers.Add(bb);
                }
            }

            headers.Sort((a, b) => a.start.CompareTo(b.start));
            foreach (var bb in headers) this.entry.Add(bb);

            if (this.entry.Count == 0)
            {
                if (this.cfg.start2bb.ContainsKey(start))
                {
                    this.entry.Add(this.cfg.start2bb[start]);
                }
            }
        }


        public void add_bb(BB bb)
        {
            this.BBs.Add(bb);
            if (this.start == 0 || (bb.start < this.start))
            {
                this.start = bb.start;
            }
            if (this.end  == 0 || (bb.end > this.end))
            {
                if ((bb.insns[^1].flags() & InstructionFlags.INS_FLAG_NOP) == 0) this.end = bb.end;
            }
            bb.function = this;
        }
    }
}
