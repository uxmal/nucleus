using System.Collections.Generic;

namespace Nucleus
{

    public partial class CFG {
        public CFG() { }

        //int make_cfg (Binary *bin, std::list<DisasmSection> *disasm);

        //BB *get_bb (uint64_t addr, unsigned *offset = NULL);

        //void print_functions (FILE *out);
        //void print_function_summaries (FILE *out);

        public Binary binary;
        public List<BB> entry;
        public List<Function> functions;
        public SortedList<ulong, BB> start2bb;
        public SortedList<ulong, BB> bad_bbs;

        //private:
        //  void analyze_addrtaken_x86 ();
        //  void analyze_addrtaken     ();
        //  void find_switches_x86     ();
        //  void find_switches         ();
        //  void expand_function       (Function *f, BB *bb);
        //  void find_functions        ();
        //  void find_entry            ();
        //  void verify_padding        ();
        //  void detect_bad_bbs        ();
        //  void link_bbs              (Edge::EdgeType type, BB *bb, uint64_t target, uint64_t jmptab = 0);
        //  void unlink_bb             (BB *bb);
        //  void unlink_edge           (BB *bb, BB *cc);
    }
}
