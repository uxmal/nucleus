using System;
using System.Collections.Generic;
using System.Linq;

namespace Nucleus
{


    public delegate double bb_score_function_t(DisasmSection sec, BB bb);
    public delegate uint bb_mutate_function_t(DisasmSection sec, BB bb, out BB[] mutants);
    public delegate int bb_select_function_t(DisasmSection sec, BB[] bb, uint n);

    public abstract class Strategy
    {
        public abstract double score_function(DisasmSection sec, BB bb);
        public abstract uint mutate_function(DisasmSection sec, BB bb, out BB[] mutants);
        public abstract int select_function(DisasmSection sec, BB[] bb, uint n);
    }

    partial class Nucleus
    {
        /*******************************************************************************
         **                        strategy function: linear                          **
         ******************************************************************************/
        double
        bb_score_linear(DisasmSection dis, BB bb)
        {
            bb.score = 1.0;
            return bb.score;
        }


        uint
        bb_mutate_linear(DisasmSection dis, BB parent, ref BB[] mutants)
        {
            if (parent == null)
            {
                try
                {
                    mutants = new BB[1];
                    mutants[0] = new BB();
                }
                catch (OutOfMemoryException)
                {
                    print_err("out of memory");
                    return 0;
                }
                /* start disassembling at the start of the section */
                mutants[0].set(dis.section.vma, 0);
            }
            else if (dis.section.contains(parent.end))
            {
                /* next BB is directly after the current BB */
                mutants[0].set(parent.end, 0);
            }
            else
            {
                mutants[0].set(0, 0);
                return 0;
            }

            return 1;
        }


        int
        bb_select_linear(DisasmSection dis, BB[] mutants, uint len)
        {
            uint i;

            for (i = 0; i < len; i++)
            {
                mutants[i].alive = true;
            }

            return len;
        }
        /*******************************************************************************
         **                       strategy function: recursive                        **
         ******************************************************************************/
        double
        bb_score_recursive(DisasmSection dis, BB bb)
        {
            bb.score = 1.0;
            return bb.score;
        }


        uint
        bb_queue_recursive(DisasmSection dis, BB parent, BB[] mutants, uint n, uint max_mutants)
        {
            ulong target;

            foreach (var ins in parent.insns)
            {
                target = ins.target;
                if (target && dis.section.contains(target)
                   && (dis.addrmap.addr_type(target) & AddressMap.DisasmRegion.DISASM_REGION_BB_START) == 0)
                {
                    /* recursively queue the target BB for disassembly */
                    mutants[n++].set(target, 0);
                }
                if ((n + 1) == max_mutants) break;
            }
            var ins = parent.insns.Last();
            if ((ins.flags & Instruction.InstructionFlags.INS_FLAG_COND) != 0
               || (ins.flags & Instruction.InstructionFlags.INS_FLAG_CALL) != 0)
            {
                /* queue fall-through block of conditional jump or call */
                if (((n + 1) < max_mutants) && dis.section.contains(parent.end)
                   && !(dis.addrmap.addr_type(parent.end) & AddressMap.DisasmRegion.DISASM_REGION_BB_START))
                {
                    mutants[n++].set(parent.end, 0);
                }
            }
            return n;
        }


        uint
        bb_mutate_recursive(DisasmSection dis, BB parent, ref BB[] mutants)
        {
            uint i, n;
            const uint max_mutants = 4096;
            List<Symbol> symbols;

            /* XXX: This strategy may yield overlapping BBs. Also, the current
             * implementation is very basic and yields low coverage. For normal
             * use the linear strategy is recommended. */

            n = 0;
            if (parent == null)
            {
                try
                {
                    mutants = new BB[max_mutants];
                }
                catch (OutOfMemoryException)
                {
                    print_err("out of memory");
                    return 0;
                }

                /* first guess for BBs are the entry point and function symbols if available, 
                 * or the section start address otherwise */
                if (dis.section.contains(dis.section.binary.entry))
                {
                    mutants[n++].set(dis.section.binary.entry, 0);
                }
                symbols = dis.section.binary.symbols;
                for (i = 0; i < symbols.Count; i++)
                {
                    if ((symbols[i].type & Symbol.SymbolType.SYM_TYPE_FUNC) && ((n + 1) < max_mutants)
                        && dis.section.contains(symbols.at(i).addr))
                    {
                        mutants[n++].set(symbols[i].addr, 0);
                    }
                }
                if (n == 0)
                {
                    mutants[n++].set(dis.section.vma, 0);
                }

                return n;
            }
            else
            {
                n = bb_queue_recursive(dis, parent, mutants, n, max_mutants);
                if (n == 0)
                {
                    /* no recursive targets found, resort to heuristics */
                    if (dis.section.contains(parent.end) && !(dis.addrmap.addr_type(parent.end) & AddressMap.DisasmRegion.DISASM_REGION_BB_START))
                    {
                        /* guess next BB directly after parent */
                        mutants[n++].set(parent.end, 0);
                    }
                }
            }

            return n;
        }


        int
        bb_select_recursive(DisasmSection dis, BB[] mutants, int len)
        {
            uint i;

            for (i = 0; i < len; i++)
            {
                mutants[i].alive = true;
            }

            return len;
        }
        /*******************************************************************************
         **                            dispatch functions                             **
         ******************************************************************************/
        string[] strategy_functions = {
  "linear",
  "recursive",
  null
};

        string[] strategy_functions_doc = {
  /* linear     */ "Linear disassembly",
  /* recursive  */ "Recursive disassembly (incomplete implementation, not recommended)",
  null
};

        Strategy[] bb_strategy_functions = {
  //{ (void*)bb_score_linear    , (void*)bb_mutate_linear    , (void*)bb_select_linear     },
  //{ (void*)bb_score_recursive , (void*)bb_mutate_recursive , (void*)bb_select_recursive  },
  //{ NULL, NULL, NULL }
};


        static int
        get_strategy_function_idx()
        {
            int i;

            i = 0;
            while (strategy_functions[i])
            {
                if (options.strategy_function.name.compare(strategy_functions[i]) == 0)
                {
                    return i;
                }
                i++;
            }

            return -1;
        }


        int
        load_bb_strategy_functions()
        {
            int i;
            string func;

            //func = options.strategy_function.name;
            i = get_strategy_function_idx();
            if (i >= 0)
            {
                //options.strategy_function.score_function  = (bb_score_function_t)bb_strategy_functions[i][0];
                //options.strategy_function.mutate_function = (bb_mutate_function_t)bb_strategy_functions[i][1];
                //options.strategy_function.select_function = (bb_select_function_t)bb_strategy_functions[i][2];
            }
            else
            {
                goto fail;
            }

            return 0;

            fail:
            print_err("unknown strategy function '%s'", func);
            return -1;
        }

        double
        bb_score(DisasmSection dis, BB bb)
        {
            if (!options.strategy_function.score_function)
            {
                if (load_bb_strategy_functions() < 0) return -1.0;
            }

            return options.strategy_function.score_function(dis, bb);
        }


        unsigned
        bb_mutate(DisasmSection dis, BB parent, BB[] mutants)
        {
            if (!options.strategy_function.mutate_function)
            {
                if (load_bb_strategy_functions() < 0) return 0;
            }

            return options.strategy_function.mutate_function(dis, parent, mutants);
        }

        int
        bb_select(DisasmSection dis, BB[] mutants, int len)
        {
            if (!options.strategy_function.select_function)
            {
                if (load_bb_strategy_functions() < 0) return 0;
            }
            return options.strategy_function.select_function(dis, mutants, len);
        }
    }
}
