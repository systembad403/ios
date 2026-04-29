#ifndef MEMORY_H
#define MEMORY_H
#include <stdint.h>
typedef uint64_t (*kread64_t)(uint64_t addr);
typedef void (*kwrite64_t)(uint64_t addr, uint64_t val);
typedef uint64_t (*kbase_t)(void);
void coruna_init_primitives(kread64_t read_func, kwrite64_t write_func, kbase_t base_func);
uint64_t kread64(uint64_t addr);
void kwrite64(uint64_t addr, uint64_t val);
uint64_t kernel_base(void);
/* Exported so Stage3 can call it via dlsym after dlopen returns */
void coruna_constructor(void);
#endif
