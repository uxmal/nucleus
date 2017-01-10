using System.Collections.Generic;

namespace Nucleus
{
    public class Symbol
    {
        public
          enum SymbolType
        {
            SYM_TYPE_UKN = 0x000,
            SYM_TYPE_FUNC = 0x001
        };

        public Symbol() { type = SymbolType.SYM_TYPE_UKN; name = null; addr = 0; }

        public SymbolType type;
        public string name;
        public ulong addr;
    };

    public partial class Section
    {
        public
          enum SectionType
        {
            SEC_TYPE_NONE = 0,
            SEC_TYPE_CODE = 1,
            SEC_TYPE_DATA = 2
        };

        public Section() { binary = (null); type = (0); vma = (0); size = (0); bytes = (null); }

        public bool contains(ulong addr) { return (addr >= vma) && (addr - vma < size); }
        public bool is_import_table() { return name == ".plt"; }

        public Binary binary;
        public string name;
        public SectionType type;
        public ulong vma;
        public ulong size;
        public byte[] bytes;
    };

    public partial class Binary
    {
        public
          enum BinaryType
        {
            BIN_TYPE_AUTO = 0,
            BIN_TYPE_RAW = 1,
            BIN_TYPE_ELF = 2,
            BIN_TYPE_PE = 3
        };
        public enum BinaryArch
        {
            ARCH_NONE = 0,
            ARCH_X86 = 1
        };

        public Binary() { type = (0); arch = (0); bits = (0); entry = (0); }

        public string filename;
        public BinaryType type;
        public string type_str;
        public BinaryArch arch;
        public string arch_str;
        public uint bits;
        public ulong entry;
        public List<Section> sections;
        public List<Symbol> symbols;
    }

    //int  load_binary   (string &fname, Binary *bin, Binary::BinaryType type);
    //void unload_binary (Binary *bin);


}
