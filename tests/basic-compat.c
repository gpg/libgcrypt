#include "../src/compat/gcrypt.h"
#include "common.h"

unsigned int test_startup_flags = 0;

#include <stdio.h>

int
test_main (int argc, char **argv)
{
  const char *version;

  version = gcry_check_version (NULL);
  printf ("Version: %s\n", version);

  return 0;
}
