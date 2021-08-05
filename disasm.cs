using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Nucleus
{
    using static capstone;

    [Flags]
    public enum DisasmRegion : ushort
    {
        UNMAPPED = 0x0000,
        CODE = 0x0001,
        DATA = 0x0002,
        INS_START = 0x0100,
        BB_START = 0x0200,
        FUNC_START = 0x0400
    }



    /*******************************************************************************
     **                              DisasmSection                                **
     ******************************************************************************/
    public partial class DisasmSection
    {
        public Section section;
        public AddressMap addrmap = new();
        public List<BB> BBs = new();
        public List<DataRegion> data = new();

        public void print_BBs(TextWriter @out)
        {
            @out.WriteLine("<Section {0} {1} @0x{2:X16} (size {3})>",
                    section.name, (section.type == SectionType.CODE) ? "C" : "D",
                    section.vma, section.size);
            @out.WriteLine();
            sort_BBs();
            foreach (var bb in BBs) {
                bb.print(@out);
            }
        }


        public void sort_BBs()
        {
            BBs.Sort(BB.comparator);
        } 
    }

    /*******************************************************************************
     **                                AddressMap                                 **
     ******************************************************************************/
    public partial class AddressMap
    {
        private SortedList<ulong, DisasmRegion> addrmap = new();
        private List<ulong> unmapped = new();
        private SortedList<ulong, int> unmapped_lookup = new();

        public void insert(ulong addr)
        {
            if (!contains(addr))
            {
                unmapped.Add(addr);
                unmapped_lookup[addr] = unmapped.Count - 1;
            }
        }


        public bool contains(ulong addr)
        {
            return addrmap.ContainsKey(addr) || unmapped_lookup.ContainsKey(addr);
        }


        public DisasmRegion get_addr_type(ulong addr)
        {
            Debug.Assert(contains(addr));
            if (!contains(addr))
            {
                return DisasmRegion.UNMAPPED;
            }
            else
            {
                return addrmap[addr];
            }
        }
        public DisasmRegion addr_type(ulong addr) { return get_addr_type(addr); }


        public void set_addr_type(ulong addr, DisasmRegion type)
        {
            Debug.Assert(contains(addr));
            if (contains(addr))
            {
                if (type != DisasmRegion.UNMAPPED)
                {
                    erase_unmapped(addr);
                }
                addrmap[addr] = type;
            }
        }


        public void add_addr_flag(ulong addr, DisasmRegion flag)
        {
            Debug.Assert(contains(addr));
            if (contains(addr))
            {
                if (flag != DisasmRegion.UNMAPPED)
                {
                    erase_unmapped(addr);
                }
                if (!addrmap.TryGetValue(addr, out var value))
                    value = 0;
                addrmap[addr] = value | flag;
            }
        }


        public int unmapped_count()
        {
            return unmapped.Count;
        }


        public ulong get_unmapped(int i)
        {
            return unmapped[i];
        }


        public void erase(ulong addr)
        {
            if (addrmap.ContainsKey(addr))
            {
                addrmap.Remove(addr);
            }
            erase_unmapped(addr);
        }


        public void erase_unmapped(ulong addr)
        {
            int i;

            if (unmapped_lookup.ContainsKey(addr))
            {
                if (unmapped_count() > 1)
                {
                    i = unmapped_lookup[addr];
                    unmapped[i] = unmapped[^1];
                    unmapped_lookup[unmapped[^1]] = i;
                }
                unmapped_lookup.Remove(addr);
                unmapped.RemoveAt(unmapped.Count - 1);
            }
        }
    }

    /*******************************************************************************
     **                            Disassembly engine                             **
     ******************************************************************************/
    public partial class Nucleus
    {
        public static int init_disasm(Binary bin, List<DisasmSection> disasm)
        {

            disasm.Clear();
            for (var i = 0; i < bin.sections.Count; i++)
            {
                var sec = bin.sections[i];
                if ((sec.type != SectionType.CODE)
                   && !(!Nucleus.options.only_code_sections && (sec.type == SectionType.DATA))) continue;

                var dis = new DisasmSection();
                disasm.Add(dis);

                dis.section = sec;
                for (var vma = sec.vma; vma < (sec.vma + sec.size); vma++)
                {
                    dis.addrmap.insert(vma);
                }
            }
            bin.create_reko_disassembler();
            Log.verbose(1, "disassembler initialized");

            return 0;
        }


        static int
        fini_disasm(Binary bin, List<DisasmSection> disasm)
        {
            Log.verbose(1, "disassembly complete");

            return 0;
        }


        static bool nucleus_disasm_bb(Binary bin, DisasmSection dis, BB bb)
        {
            switch (bin.arch)
            {
            case Binary.BinaryArch.ARCH_AARCH64:
                return AArch64.nucleus_disasm_bb_aarch64(bin, dis, bb);
/*            case Binary.BinaryArch.ARCH_ARM:
                 return nucleus_disasm_bb_arm(bin, dis, bb);
            case Binary.BinaryArch.ARCH_MIPS:
                return nucleus_disasm_bb_mips(bin, dis, bb);
            case Binary.BinaryArch.ARCH_PPC:
                return nucleus_disasm_bb_ppc(bin, dis, bb);
*/
            case Binary.BinaryArch.ARCH_X86:
                return X86.nucleus_disasm_bb_x86(bin, dis, bb);
            default:
                Log.print_err("disassembly for architecture {0} is not supported", bin.arch_str);
                return false;
            }
        }


        static int
        nucleus_disasm_section(Binary bin, DisasmSection dis)
        {
            int ret;
            uint i, n;
            ulong vma;
            double s;
            BB[] mutants = null;
            Queue<BB> Q = new();

            if ((dis.section.type != SectionType.CODE) && options.only_code_sections)
            {
                Log.print_warn("skipping non-code section '{0}'", dis.section.name);
                return 0;
            }

            Log.verbose(2, "disassembling section '{0}'", dis.section.name);

            Q.Enqueue(null);
            while (Q.Count > 0)
            {
                n = options.strategy.function.mutate_function(dis, Q.Dequeue(), ref mutants);
                for (i = 0; i < mutants.Length; i++)
                {
                    if (!nucleus_disasm_bb(bin, dis, mutants[i]))
                    {
                        goto fail;
                    }
                    if ((s = bb_score(dis, mutants[i])) < 0)
                    {
                        goto fail;
                    }
                }
                if ((n = (uint)options.strategy.function.select_function(dis, mutants, mutants.Length)) < 0)
                {
                    goto fail;
                }
                for (i = 0; i < n; i++)
                {
                    if (mutants[i].alive)
                    {
                        dis.addrmap.add_addr_flag(mutants[i].start, DisasmRegion.BB_START);
                        foreach (var ins in mutants[i].insns)
                        {
                            dis.addrmap.add_addr_flag(ins.Address.ToLinear(), DisasmRegion.INS_START);
                        }
                        for (vma = mutants[i].start; vma < mutants[i].end; vma++)
                        {
                            dis.addrmap.add_addr_flag(vma, DisasmRegion.CODE);
                        }
                        var bb = mutants[i];
                        dis.BBs.Add(new BB(bb));
                        Q.Enqueue(bb);
                    }
                }
            }

            ret = 0;
            goto cleanup;

            fail:
            ret = -1;

            cleanup:
            return ret;
        }


        static int
        nucleus_disasm(Binary bin, List<DisasmSection> disasm)
        {
            int ret;

            if (init_disasm(bin, disasm) < 0)
            {
                goto fail;
            }

            foreach (var dis in disasm)
            {
                if (nucleus_disasm_section(bin, dis) < 0)
                {
                    goto fail;
                }
            }

            if (fini_disasm(bin, disasm) < 0)
            {
                goto fail;
            }

            ret = 0;
            goto cleanup;

            fail:
            ret = -1;

            cleanup:
            return ret;
        }
    }
}

