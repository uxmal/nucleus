#include <stdlib.h>

#include <exception>

#include "log.h"
#include "exception.h"


void
nucleus_terminate()
{
  print_err("unhandled exception, terminating...");
  exit(EXIT_FAILURE);
}


void
set_exception_handlers()
{
  std::set_terminate(nucleus_terminate);
}

