#ifndef NUCLEUS_DATAREGION_H
#define NUCLEUS_DATAREGION_H

#include <stdint.h>

class DataRegion {
public:
  DataRegion() : start(0), end(0) {}
  DataRegion(const DataRegion &d) : start(d.start), end(d.end) {}

  uint64_t start;
  uint64_t end;
};

#endif /* NUCLEUS_DATAREGION_H */

