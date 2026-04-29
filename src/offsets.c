#include "offsets.h"
#include <string.h>
#include <sys/sysctl.h>
static const KernelOffsets offsets_table[] = {
    { "Darwin Kernel Version 23.2.0", 0xFFFFFFF009A2C000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x20, 0x28, 0x30F },
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
