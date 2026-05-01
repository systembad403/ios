#include "offsets.h"
#include <string.h>
#include <sys/sysctl.h>

/*
 * 与 iOS 17.x 对应的 Darwin 版本（约）：
 *   17.0.x → 23.0.x，17.1.x → 23.1.x，17.2.x → 23.2.x（首要目标）
 *
 * sysctlbyname("kern.version") 返回串需命中下列子串之一，否则 get_kernel_offsets() 为 NULL，
 * 提权跳过但采集仍可能跑。若某小版本内核布局不同，请在真机上核对 kern.version 后：
 *   1）新增一行更合适子串；2）按越狱/安全笔记改正 allproc 与各结构位移。
 *
 * 下列 23.0 / 23.1 行暂与 23.2 共用同一组数值，仅保证「能匹配版本串」；
 * 若在 17.0/17.1 上 kread 异常，请单独填该版本的公开偏移。
 */
static const KernelOffsets offsets_table[] = {
    { "Darwin Kernel Version 23.2.0", 0xFFFFFFF009A2C000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x20, 0x28, 0x30F },
    { "Darwin Kernel Version 23.1.0", 0xFFFFFFF009A2C000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x20, 0x28, 0x30F },
    { "Darwin Kernel Version 23.0.0", 0xFFFFFFF009A2C000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x20, 0x28, 0x30F },
    { "Darwin Kernel Version 22.5.0", 0xFFFFFFF0078B4000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x20, 0x28, 0x30F },
    { "Darwin Kernel Version 21.6.0", 0xFFFFFFF0078B4000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x20, 0x28, 0x30F },
    { "Darwin Kernel Version 20.6.0", 0xFFFFFFF006E04000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x20, 0x28, 0x30F },
    { "Darwin Kernel Version 19.6.0", 0xFFFFFFF006E04000, 0x60, 0x08, 0xF0, 0xE0, 0x18, 0x20, 0x28, 0x30F },
    { NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
const KernelOffsets* get_kernel_offsets(void) {
    char kern_version[256];
    size_t size = sizeof(kern_version);
    sysctlbyname("kern.version", kern_version, &size, NULL, 0);
    for (int i = 0; offsets_table[i].version_substring != NULL; i++) {
        if (strstr(kern_version, offsets_table[i].version_substring)) return &offsets_table[i];
    }
    return NULL;
}
