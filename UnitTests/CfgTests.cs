using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nucleus.UnitTests
{
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
            bin.reko_arch = new Reko.Arch.X86.X86ArchitectureFlat32(null, "", new Dictionary<string, object>());
            var m = new X86Emitter(disasm);
            generator(m);
            this.cfg = new CFG();
            cfg.make_cfg(bin, new List<DisasmSection> { disasm });
        }

        [Test]
        public void Cfg_Linear()
        {
            Given_X86Code(m =>
            {
                m.mov(m.eax, m.W32(0x1234));
                m.ret();
            });

            Assert.AreEqual(1, cfg.functions.Count);
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

            Assert.AreEqual(2, cfg.functions.Count);
        }

        [Test]
        [Ignore("This exposes a flaw in Nucleus out of the box")]
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

            Assert.AreEqual(2, cfg.functions.Count);
            var fn1 = cfg.functions[0];
            Assert.AreEqual(2, fn1.BBs.Count);
        }
    }
}
