namespace Nucleus
{
    public partial class DataRegion
    {
        public DataRegion() { start = 0;  end = 0; }
        public DataRegion(DataRegion d) { start = d.start; end = d.end; }

        public readonly ulong start;
        public readonly ulong end;
    }
}
