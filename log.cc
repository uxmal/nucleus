#include <stdio.h>
#include <stdarg.h>

#include "options.h"
#include "log.h"

#define ERROUT stderr


void
verbose(int level, char const *fmt, ...)
{
  va_list args;

  if(options.verbosity >= level) {
    va_start(args, fmt);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
  }
}


void
print_warn(char const *fmt, ...)
{
  va_list args;

  if(options.warnings) {
    va_start(args, fmt);
    fprintf(ERROUT, "WARNING: ");
    vfprintf(ERROUT, fmt, args);
    fprintf(ERROUT, "\n");
    va_end(args);
  }
}


void
print_err(char const *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  fprintf(ERROUT, "ERROR: ");
  vfprintf(ERROUT, fmt, args);
  fprintf(ERROUT, "\n");
  va_end(args);
}

