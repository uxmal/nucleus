using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace Nucleus
{
    using static capstone;

    public partial class AddressMap
    {
        [Flags]
        public enum DisasmRegion
        {
            DISASM_REGION_UNMAPPED = 0x0000,
            DISASM_REGION_CODE = 0x0001,
            DISASM_REGION_DATA = 0x0002,
            DISASM_REGION_INS_START = 0x0100,
            DISASM_REGION_BB_START = 0x0200,
            DISASM_REGION_FUNC_START = 0x0400
        }


        private SortedList<ulong, DisasmRegion> addrmap = new();
        private List<ulong> unmapped = new();
        private SortedList<ulong, int> unmapped_lookup = new();
    };

    public partial class DisasmSection
    {

        public Section section;
        public AddressMap addrmap = new();
        public List<BB> BBs = new();
        public List<DataRegion> data = new();

    };



    /*******************************************************************************
     **                              DisasmSection                                **
     ******************************************************************************/
    public partial class DisasmSection
    {

        public void print_BBs(TextWriter @out)
        {
            @out.WriteLine("<Section {0} {1} @0x{2:X16} (size {3})>",
                    section.name, (section.type == Section.SectionType.SEC_TYPE_CODE) ? "C" : "D",
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
                return AddressMap.DisasmRegion.DISASM_REGION_UNMAPPED;
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
                if (type != AddressMap.DisasmRegion.DISASM_REGION_UNMAPPED)
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
                if (flag != DisasmRegion.DISASM_REGION_UNMAPPED)
                {
                    erase_unmapped(addr);
                }
                addrmap[addr] |= flag;
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
                if ((sec.type != Section.SectionType.SEC_TYPE_CODE)
                   && !(!Nucleus.options.only_code_sections && (sec.type == Section.SectionType.SEC_TYPE_DATA))) continue;

                var dis = new DisasmSection();
                disasm.Add(dis);

                dis.section = sec;
                for (var vma = sec.vma; vma < (sec.vma + sec.size); vma++)
                {
                    dis.addrmap.insert(vma);
                }
            }
            Log.verbose(1, "disassembler initialized");

            return 0;
        }


        static int
        fini_disasm(Binary bin, List<DisasmSection> disasm)
        {
            Log.verbose(1, "disassembly complete");

            return 0;
        }


        static bool
        nucleus_disasm_bb(Binary bin, DisasmSection dis, BB bb)
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
            case Binary.BinaryArch.ARCH_X86:
                return nucleus_disasm_bb_x86(bin, dis, bb);
*/
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

            if ((dis.section.type != Section.SectionType.SEC_TYPE_CODE) && options.only_code_sections)
            {
                Log.print_warn("skipping non-code section '{0}'", dis.section.name);
                return 0;
            }

            Log.verbose(2, "disassembling section '{0}'", dis.section.name);

            Q.Enqueue(null);
            while (Q.Count > 0)
            {
                n = bb_mutate(dis, Q.Dequeue(), mutants);
                for (i = 0; i < n; i++)
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
                if ((n = (uint)bb_select(dis, mutants, (int)n)) < 0)
                {
                    goto fail;
                }
                for (i = 0; i < n; i++)
                {
                    if (mutants[i].alive)
                    {
                        dis.addrmap.add_addr_flag(mutants[i].start, AddressMap.DisasmRegion.DISASM_REGION_BB_START);
                        foreach (var ins in mutants[i].insns)
                        {
                            dis.addrmap.add_addr_flag(ins.Address.ToLinear(), AddressMap.DisasmRegion.DISASM_REGION_INS_START);
                        }
                        for (vma = mutants[i].start; vma < mutants[i].end; vma++)
                        {
                            dis.addrmap.add_addr_flag(vma, AddressMap.DisasmRegion.DISASM_REGION_CODE);
                        }
                        var bb = new BB(mutants[i]);
                        dis.BBs.Add(bb);
                        Q.Enqueue(bb);
                    }
                }
            }

            ret = 0;
            goto cleanup;

            fail:
            ret = -1;

            cleanup:
            //if (mutants) {
            //    delete[] mutants;
            //}
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

