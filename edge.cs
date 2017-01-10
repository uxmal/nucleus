namespace Nucleus
{
    partial class Edge
    {
        public string type2str()
        {
            string s;

            switch (this.type)
            {
            case EdgeType.EDGE_TYPE_JMP:
                s = "jmp";
                break;
            case EdgeType.EDGE_TYPE_JMP_INDIRECT:
                s = "ijmp";
                break;
            case EdgeType.EDGE_TYPE_CALL:
                s = "call";
                break;
            case EdgeType.EDGE_TYPE_CALL_INDIRECT:
                s = "icall";
                break;
            case EdgeType.EDGE_TYPE_RET:
                s = "ret";
                break;
            case EdgeType.EDGE_TYPE_FALLTHROUGH:
                s = "fallthrough";
                break;
            default:
                s = "none";
                break;
            }

            if (this.is_switch)
            {
                s += "/switch";
            }
            if (this.offset != 0)
            {
                s += "/+" + this.offset.ToString();
            }

            return s;
        }
    }
}
