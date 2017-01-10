using System.Collections.Generic;

namespace Nucleus
{

    public partial class Function {
        public Function() { cfg = null; start = 0; end = 0; id = global_id++; }

        //void print(FILE*out);
        //void print_summary(FILE*out);

        //void find_entry();
        //void add_bb(BB* bb);

        public CFG cfg;
        public ulong id;
        public ulong start;
        public ulong end;
        public List<BB> entry;
        public List<BB> BBs;

        private
          static ulong global_id;

    }
}

