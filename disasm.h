#ifndef NUCLEUS_DISASM_H
#define NUCLEUS_DISASM_H

#include <stdint.h>

#include <map>
#include <list>
#include <string>

#include <capstone/capstone.h>

#include "bb.h"
#include "dataregion.h"
#include "loader.h"

class AddressMap {
public:
  enum DisasmRegion {
    DISASM_REGION_UNMAPPED   = 0x0000,
    DISASM_REGION_CODE       = 0x0001,
    DISASM_REGION_DATA       = 0x0002,
    DISASM_REGION_INS_START  = 0x0100,
    DISASM_REGION_BB_START   = 0x0200,
    DISASM_REGION_FUNC_START = 0x0400
  };

  AddressMap() {}

  void     insert        (uint64_t addr);
  bool     contains      (uint64_t addr);
  unsigned get_addr_type (uint64_t addr);
  void     set_addr_type (uint64_t addr, unsigned type);
  void     add_addr_flag (uint64_t addr, unsigned flag);
  unsigned addr_type     (uint64_t addr);

  size_t   unmapped_count ();
  uint64_t get_unmapped   (size_t i);
  void     erase          (uint64_t addr);
  void     erase_unmapped (uint64_t addr);

private:
  std::map<uint64_t, unsigned> addrmap;
  std::vector<uint64_t>        unmapped;
  std::map<uint64_t, size_t>   unmapped_lookup;
};

class DisasmSection {
public:
  DisasmSection() : section(NULL) {}

  void print_BBs(FILE *out);

  Section              *section;
  AddressMap            addrmap;
  std::list<BB>         BBs;
  std::list<DataRegion> data;

private:
  void sort_BBs();
};

int nucleus_disasm (Binary *bin, std::list<DisasmSection> *disasm);

#endif /* NUCLEUS_DISASM_H */

