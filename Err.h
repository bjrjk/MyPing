#ifndef MYPING_ERR_H
#define MYPING_ERR_H

#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cerrno>

void errorQuit(const char *fmt, ...) __attribute__((noreturn));

#endif
