using System;
using System.Collections.Generic;
using System.Linq;

namespace Nucleus
{


    public delegate double bb_score_function_t(DisasmSection sec, BB bb);
    public delegate uint bb_mutate_function_t(DisasmSection sec, BB bb, BB[] mutants);
    public delegate int bb_select_function_t(DisasmSection sec, BB[] bb, uint n);

    public abstract class Strategy
    {
        public abstract double score_function(DisasmSection sec, BB bb);
        public abstract uint mutate_function(DisasmSection sec, BB bb, BB[] mutants);
        public abstract int select_function(DisasmSection sec, BB[] bb, int n);
    }

    partial class Nucleus
    {
        /*******************************************************************************
         **                        strategy function: linear                          **
         ******************************************************************************/
        public class linear_strategy : Strategy
        {
            public override double score_function(DisasmSection sec, BB bb)
            {
                bb.score = 1.0;
                return bb.score;
            }


            public override uint mutate_function(DisasmSection dis, BB parent, BB[] mutants)
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
                        Log.print_err("out of memory");
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


            public override int select_function(DisasmSection sec, BB[] mutants, int len)
            {
                int i;

                for (i = 0; i < len; i++)
                {
                    mutants[i].alive = true;
                }

                return len;
            }
        }
        /*******************************************************************************
         **                       strategy function: recursive                        **
         ******************************************************************************/
        public class recursive_strategy : Strategy
        {
            public override double score_function(DisasmSection sec, BB bb)
            {
                bb.score = 1.0;
                return bb.score;
            }



            uint bb_queue_recursive(DisasmSection dis, BB parent, BB[] mutants, uint n, uint max_mutants)
            {
                foreach (var instr in parent.insns)
                {
                    var target = instr.target();
                    if (target is not null && dis.section.contains(target.ToLinear())
                       && (dis.addrmap.addr_type(target.ToLinear()) & AddressMap.DisasmRegion.DISASM_REGION_BB_START) == 0)
                    {
                        /* recursively queue the target BB for disassembly */
                        mutants[n++].set(target.ToLinear(), 0);
                    }
                    if ((n + 1) == max_mutants) break;
                }
                var ins = parent.insns[^1];
                if ((ins.flags() & Instruction.InstructionFlags.INS_FLAG_COND) != 0
                   || (ins.flags() & Instruction.InstructionFlags.INS_FLAG_CALL) != 0)
                {
                    /* queue fall-through block of conditional jump or call */
                    if (((n + 1) < max_mutants) && dis.section.contains(parent.end)
                       && (dis.addrmap.addr_type(parent.end) & AddressMap.DisasmRegion.DISASM_REGION_BB_START) == 0)
                    {
                        mutants[n++].set(parent.end, 0);
                    }
                }
                return n;
            }

            public override uint mutate_function(DisasmSection dis, BB parent, BB[] mutants)
            {
                int i;
                const uint max_mutants = 4096;
                List<Symbol> symbols;

                /* XXX: This strategy may yield overlapping BBs. Also, the current
                 * implementation is very basic and yields low coverage. For normal
                 * use the linear strategy is recommended. */

                uint n = 0;
                if (parent == null)
                {
                    try
                    {
                        mutants = new BB[max_mutants];
                    }
                    catch (OutOfMemoryException)
                    {
                        Log.print_err("out of memory");
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
                        if ((symbols[i].type & Symbol.SymbolType.SYM_TYPE_FUNC) != 0 && ((n + 1) < max_mutants)
                            && dis.section.contains(symbols[i].addr))
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
                        if (dis.section.contains(parent.end) && (dis.addrmap.addr_type(parent.end) & AddressMap.DisasmRegion.DISASM_REGION_BB_START) == 0)
                        {
                            /* guess next BB directly after parent */
                            mutants[n++].set(parent.end, 0);
                        }
                    }
                }

                return n;
            }


            public override int select_function(DisasmSection dis, BB[] mutants, int len)
            {
                uint i;

                for (i = 0; i < len; i++)
                {
                    mutants[i].alive = true;
                }

                return len;
            }
        }

        /*******************************************************************************
         **                            dispatch functions                             **
         ******************************************************************************/
        static Tuple<string, Type>[] strategy_functions = {
            Tuple.Create("linear", typeof(linear_strategy)),
            Tuple.Create("recursive", typeof(recursive_strategy))
        };

        string[] strategy_functions_doc = {
  /* linear     */ "Linear disassembly",
  /* recursive  */ "Recursive disassembly (incomplete implementation, not recommended)",
};

        static Strategy[] bb_strategy_functions = {
  //{ (void*)bb_score_linear    , (void*)bb_mutate_linear    , (void*)bb_select_linear     },
  //{ (void*)bb_score_recursive , (void*)bb_mutate_recursive , (void*)bb_select_recursive  },
  //{ NULL, NULL, NULL }
};


        static Type
        get_strategy_function_type()
        {
            foreach (var sf in strategy_functions)
            {
                if (options.strategy.name == sf.Item1)
                {
                    return sf.Item2;
                }
            }
            return null;
        }

        static int
        load_bb_strategy_functions()
        {
            var type = get_strategy_function_type();
            if (type != null)
            {
                options.strategy.function = (Strategy)Activator.CreateInstance(type);
                return 0;
            }
            else
            {
            Log.print_err("unknown strategy function '{0}'", options.strategy.name);
                return -1;
            }
        }

        static double bb_score(DisasmSection dis, BB bb)
        {
            if (options.strategy.function == null)
            {
                if (load_bb_strategy_functions() < 0) return -1.0;
            }

            return options.strategy.function.score_function(dis, bb);
        }


        static uint bb_mutate(DisasmSection dis, BB parent, BB[] mutants)
        {
            if (options.strategy.function == null)
            {
                if (load_bb_strategy_functions() < 0) return 0;
            }

            return options.strategy.function.mutate_function(dis, parent, mutants);
        }

        static int bb_select(DisasmSection dis, BB[] mutants, int len)
        {
            if (options.strategy.function == null)
            {
                if (load_bb_strategy_functions() < 0) return 0;
            }
            return options.strategy.function.select_function(dis, mutants, len);
        }
    }
}
