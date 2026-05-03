/*
 * Stage3_VariantB.js（Go 仓库内 PATCH）同步拉取 code.dylib 后，会解析 LC_SYMTAB，
 * 查找名为 "_process" 的导出符号；找不到则抛错 → C2 侧看到 coruna chain error。
 *
 * 主逻辑仍在 coruna_constructor / coruna_init_primitives；此处仅提供链所要求的
 * Mach-O 导出项。使用 default 可见性，避免被 -fvisibility=hidden 剔除出导出表。
 */
__attribute__((visibility("default")))
void process(void) {
    /* no-op：dlopen 时 constructor 已触发；若链向此 VA 转跳，驻留安全 */
}
