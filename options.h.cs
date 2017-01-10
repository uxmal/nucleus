namespace Nucleus
{
    public class options {
        public int verbosity;
        public bool warnings;
        public bool only_code_sections;
        public int allow_privileged;
        public bool summarize_functions;

        public struct path_options {
            string real;
            string dir;
            string @base;
        }
        public path_options nucleuspath;

        public struct export_options {
            public string ida;
            public string dot;
        }
        public export_options exports;

        public struct binary_options {
            public string filename;
            public Binary.BinaryType type;
            public Binary.BinaryArch arch;
            public uint bits;
            public ulong base_vma;
        }
        public binary_options binary;

        public struct strategy_options
        {
            public string name;
            public Strategy function;
        }
        public strategy_options strategy;
    }

    //static int parse_options(string[] args);
}
