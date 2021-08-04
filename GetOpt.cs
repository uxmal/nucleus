using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public class GetOpt
{
    private string[] argv;
    private int i;
    private Dictionary<char, bool> argnames;
    public GetOpt(string[] argv, string optstr)
    {
        this.argv = argv;
        this.i = 0;
        this.argnames = parseOptstr(optstr);
    }

    private Dictionary<char, bool> parseOptstr(string optstr)
    {
        var dict = new Dictionary<char, bool>();
        for (int i = 0; i < optstr.Length; ++i)
        {
            var opt = optstr[i];
            if (opt != ':')
                dict[opt] = (i < optstr.Length - 1 && optstr[i + 1] == ':');
        }
        return dict;
    }

    public int getopt(out string optarg)
    {
        if (i >= argv.Length)
        {
            optarg = null;
            return -1;
        }
        var arg = argv[i++];
        throw new NotImplementedException();
    }
}
