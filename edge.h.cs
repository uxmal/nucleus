namespace Nucleus
{

    public partial class Edge {
        public enum EdgeType
        {
            EDGE_TYPE_NONE,
            EDGE_TYPE_JMP,
            EDGE_TYPE_JMP_INDIRECT,
            EDGE_TYPE_CALL,
            EDGE_TYPE_CALL_INDIRECT,
            EDGE_TYPE_RET,
            EDGE_TYPE_FALLTHROUGH
        }

        public Edge(Edge.EdgeType type_, BB src_, BB dst_) { 
            type = type_; src = src_; dst = dst_; is_switch = false; jmptab = 0; offset = 0; }
        public Edge(Edge.EdgeType type_, BB src_, BB dst_, bool is_switch_, ulong jmptab_, int offset_) {
            type = type_; src = src_; dst = dst_; is_switch = is_switch_; jmptab = jmptab_; offset = offset_; }

        //string type2str ();

        public EdgeType type;
        public BB src;
        public BB dst;
        public bool is_switch;
        public ulong jmptab;
        public int offset;
    }
}

