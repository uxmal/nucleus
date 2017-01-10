using System;

namespace Nucleus
{
    partial class Log
    {

        public static void verbose(int level, string fmt, params object[] args)
        {
            if (Nucleus.options.verbosity >= level)
            {
                Console.Out.WriteLine(fmt, args);
            }
        }

        public static void print_warn(string fmt, params object[] args)
        {
            if (Nucleus.options.warnings)
            {
                Console.Error.Write("WARNING: ");
                Console.Error.WriteLine(fmt, args);
            }
        }

        public static void print_err(string fmt, params object[] args)
        {
            Console.Error.Write("ERROR: ");
            Console.Error.WriteLine(fmt, args);
        }
    }
}
