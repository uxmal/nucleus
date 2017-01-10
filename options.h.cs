namespace Nucleus
{ 
public class options {
  public int verbosity;
  public int warnings;
  public bool only_code_sections;
  public int allow_privileged;
  public int summarize_functions;

  struct {
    string real;
    string dir;
    string base;
  } nucleuspath;

  struct {
    string ida;
    string dot;
  } exports;

  struct {
    string        filename;
    Binary::BinaryType type;
    Binary::BinaryArch arch;
    unsigned           bits;
    uint64_t           base_vma;
  } binary;

  struct {
    string name;
    double   (*score_function)  (DisasmSection*, BB*);
    unsigned (*mutate_function) (DisasmSection*, BB*, BB**);
    int      (*select_function) (DisasmSection*, BB*, unsigned);
  } strategy_function;
};
extern struct options options;

int parse_options (int argc, char *argv[]);

#endif /* NUCLEUS_OPTIONS_H */

