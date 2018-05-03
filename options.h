#ifndef NUCLEUS_OPTIONS_H
#define NUCLEUS_OPTIONS_H

#include <stdint.h>

#include <string>

#include "bb.h"
#include "loader.h"
#include "disasm.h"

struct options {
  int verbosity;
  int warnings;
  int only_code_sections;
  int allow_privileged;
  int summarize_functions;

  struct {
    std::string real;
    std::string dir;
    std::string base;
  } nucleuspath;

  struct {
    std::string ida;
    std::string binja;
    std::string dot;
  } exports;

  struct {
    std::string        filename;
    Binary::BinaryType type;
    Binary::BinaryArch arch;
    unsigned           bits;
    uint64_t           base_vma;
  } binary;

  struct {
    std::string name;
    double   (*score_function)  (DisasmSection*, BB*);
    unsigned (*mutate_function) (DisasmSection*, BB*, BB**);
    int      (*select_function) (DisasmSection*, BB*, unsigned);
  } strategy_function;
};
extern struct options options;

int parse_options (int argc, char *argv[]);

#endif /* NUCLEUS_OPTIONS_H */

