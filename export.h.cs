#ifndef NUCLEUS_EXPORT_H
#define NUCLEUS_EXPORT_H

#include <string>
#include <list>

#include "loader.h"
#include "disasm.h"
#include "cfg.h"

int export_bin2ida (string &fname, Binary *bin, std::list<DisasmSection> *disasm, CFG *cfg);
int export_cfg2dot (string &fname, CFG *cfg);

#endif /* NUCLEUS_EXPORT_H */

