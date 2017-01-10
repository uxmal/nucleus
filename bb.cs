using System.IO;

namespace Nucleus
{
    public partial class BB
    { 
        public void print(TextWriter @out)
{
  @out.WriteLine( "BB @0x{0:X16} (score {1,10} {2}{3}{4}{5}{6} {{", 
          start, score, invalid ? "i" : "-", privileged ? "p" : "-", 
          addrtaken ? "a" : "-", padding ? "n" : "-");
  if(invalid) {
    @out.Write( "  0x%016jx  (bad)", start);
  } else {
    foreach (var ins in  insns) {
      ins.print(@out);
    }
  }
  if(!ancestors.empty()) {
    @out.Write( "--A ancestors:\n");
    foreach (var e in  ancestors) {
      @out.Write( "--A 0x%016jx (%s)\n", e.src->insns.back().start, e.type2str().c_str());
    }
  }
  if(!targets.empty()) {
    @out.Write( "--T targets:\n");
    foreach (var e in  targets) {
      @out.Write( "--T 0x%016jx (%s)\n", e.dst->start+e.offset, e.type2str().c_str());
    }
  }
  @out.Write( "}\n\n");
}


bool
BB::is_called()
{
  foreach (var e in  ancestors) {
    if((e.type == Edge::EDGE_TYPE_CALL) 
       || (e.type == Edge::EDGE_TYPE_CALL_INDIRECT)) {
      return true;
    }
  }

  return false;
}


bool
BB::returns()
{
  return (insns.back().flags & Instruction::INS_FLAG_RET);
}

