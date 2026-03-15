using NUnit.Framework;
using Reko.Arch.X86;
using Reko.Arch.X86.Assembler;
using Reko.Core;
using Reko.Core.Loading;
using Reko.Core.Memory;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nucleus.UnitTests;

[TestFixture]
public class DisasmTests
{
    private void RunLinearTest(Action<X86Assembler> action)
    {
        RunTest(action, "linear");
    }

    private void RunTest(Action<X86Assembler> action, string strategy)
    {
        var sc = new ServiceContainer();
        var arch = new X86ArchitectureFlat32(sc, "x86", []);
        var eps = new List<ImageSymbol>();
        var m = new X86Assembler(arch, Address.Ptr32(0x10_0000), eps);
        action(m);
        var program = m.GetImage();
        var bin = new Binary();
        bin.sections = program.SegmentMap.Segments.Values.Select(s => Nucleus.mapRekoSection(s, bin))
            .ToList();
        bin.symbols = program.ImageSymbols.Values.Select(Nucleus.mapRekoSymbol)
            .ToList();
        bin.reko_arch = arch;
        bin.arch = Binary.BinaryArch.ARCH_X86;
        bin.bits = 32;
        bin.type = Binary.BinaryType.BIN_TYPE_AUTO;
        Nucleus.options.strategy.name = "linear";
        Nucleus.load_bb_strategy_functions();
        var disasm = new List<DisasmSection>();
        Nucleus.nucleus_disasm(bin, disasm);
    }



    [Test]
    public void Dasm_x86_block()
    {
        RunLinearTest(m =>
        {
            m.Mov(m.ax, m.Imm(0x42));
            m.Ret();
        });

    }
}
