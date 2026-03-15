using NUnit.Framework;
using System;
using System.Linq;

namespace Nucleus.UnitTests;

[TestFixture]
public class CfgTests
{
    private Binary bin;
    private DisasmSection disasm;
    private CFG cfg;

    [SetUp]
    public void Setup()
    {
        this.bin = new Binary();
        this.disasm = new DisasmSection();
    }

    private void Given_X86Code(Action<X86Emitter> generator)
    {
        bin.reko_arch = new Reko.Arch.X86.X86ArchitectureFlat32(null, "", []);
        var m = new X86Emitter(disasm);
        generator(m);
        this.cfg = new CFG();
        cfg.make_cfg(bin, [ disasm ]);
    }

    [Test]
    public void Cfg_Linear()
    {
        Given_X86Code(m =>
        {
            m.mov(m.eax, m.W32(0x1234));
            m.ret();
        });

        Assert.That(cfg.functions.Count, Is.EqualTo(1));
    }

    [Test]
    public void Cfg_Two_Procedures()
    {
        Given_X86Code(m =>
        {
            m.mov(m.eax, m.W32(0x1234));
            m.ret();
            m.mov(m.eax, m.W32(0x5678));
            m.ret();
        });

        Assert.That(cfg.functions.Count, Is.EqualTo(2));
    }

    [Test]
    public void Cfg_branch_to_procedure()
    {
        Given_X86Code(m =>
        {
            m.mov(m.eax, m.W32(0x1234));
            m.call("fn");
            m.mov(m.eax, m.W32(0x5678));

            m.label("fn");
            m.mov(m.eax, m.W32(0x5555));
            m.ret();
        });

        Assert.That(cfg.functions.Count, Is.EqualTo(2));
        var fn1 = cfg.functions.Single(f => f.start == 0x0000000000100000);
        Assert.That(fn1.BBs.Count, Is.EqualTo(2));
    }
}
