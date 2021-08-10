using Reko.Arch.X86;
using Reko.Core;
using Reko.Core.Expressions;
using Reko.Core.Machine;
using Reko.Core.Types;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nucleus.UnitTests
{
    public class X86Emitter
    {
        private DisasmSection disasm;
        private BB bb;
        private Address addr;
        private Section section;
        private Dictionary<Address, MachineInstruction> instrs;
        private Dictionary<string, EmitterSymbol> symbols;

        public X86Emitter(DisasmSection disasm)
        {
            this.disasm = disasm;
            this.addr = Address.Ptr32(0x0010_0000);
            this.section = new Section();
            this.section.type = SectionType.CODE;
            this.symbols = new();
            this.instrs = new();
            StartBlock();
        }

        private void StartBlock()
        {
            this.bb = new BB();
            this.disasm.BBs.Add(bb);
            this.bb.start = addr.ToLinear();
            this.bb.section = section;
        }

        private void EndBlock()
        {
            this.bb = null;
        }

        public RegisterOperand eax { get; } = new RegisterOperand(Registers.eax);

        public void label(string label)
        {
            DefineSymbol(label);
        }


        public void call(string label)
        {
            var target = EnsureSymbolOperand(label, 0);
            var instr = new X86Instruction(Mnemonic.call, InstrClass.Transfer | InstrClass.Call, null, PrimitiveType.Ptr32, target);
            Emit(instr, 5);
            EndBlock();
        }

        public void mov(MachineOperand dst, MachineOperand src)
        {
            var instr = new X86Instruction(Mnemonic.mov, InstrClass.Linear, dst.Width, PrimitiveType.Ptr32, dst, src);
            Emit(instr, 2 + (src is MemoryOperand ? 4 : 1));
        }

        public void ret()
        {
            var instr = new X86Instruction(Mnemonic.ret, InstrClass.Transfer|InstrClass.Return, null, PrimitiveType.Ptr32);
            Emit(instr, 1);
            EndBlock();
        }


        private AddressOperand EnsureSymbolOperand(string label, int iop)
        {
            if (symbols.TryGetValue(label, out var symbol) && symbol.resolved)
            {
                return AddressOperand.Create(symbol.addr);
            }
            symbol = new EmitterSymbol();
            symbol.backpatches.Add((this.addr, iop));
            symbols[label] = symbol;
            return AddressOperand.Create(Address.Ptr64(~0u));
        }

        private void DefineSymbol(string label)
        {
            if (symbols.TryGetValue(label, out var symbol))
            {
                foreach (var (addr, iop) in symbol.backpatches)
                {
                    instrs[addr].Operands[iop] = AddressOperand.Create(this.addr);
                }
            }
            var sym = new EmitterSymbol { addr = this.addr, resolved = true };
            symbols[label] = sym;
        }

        public MemoryOperand W32(uint offset)
        {
            var w = PrimitiveType.Word32;
            return new MemoryOperand(w, Constant.Create(PrimitiveType.Word32, offset));
        }

        protected void Emit(X86Instruction instr, int length)
        {
            if (bb is null)
                StartBlock();

            instr.Length = length;
            instr.Address = this.addr;
            this.instrs[addr] = instr;
            bb.insns.Add(instr);
            this.addr += length;
        }

        class EmitterSymbol
        {
            public Address addr;
            public bool resolved;
            public List<(Address, int)> backpatches = new();
        }
    }
}
