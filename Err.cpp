#include "Err.h"

void errorQuit(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);

  printf("Errno: %d\n", errno);
  exit(1);
}
