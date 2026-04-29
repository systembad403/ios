#ifndef INJECTION_H
#define INJECTION_H
#include <mach/mach.h>
#include <stddef.h>
#include <unistd.h>
pid_t find_pid_by_name(const char *name);
kern_return_t inject_into_pid(pid_t target, const void *payload, size_t size);
void inject_powerd(const void *payload, size_t size);
#endif
