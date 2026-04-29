#ifndef OFFSETS_H
#define OFFSETS_H
#include <stdint.h>
typedef struct {
    const char *version_substring;
    uint64_t allproc_offset;
    uint64_t proc_p_pid;
    uint64_t proc_p_list_next;
    uint64_t proc_p_ucred;
    uint64_t proc_p_fd;
    uint64_t ucred_cr_uid;
    uint64_t ucred_cr_ruid;
    uint64_t ucred_cr_svuid;
    uint64_t host_special_port;
} KernelOffsets;
const KernelOffsets* get_kernel_offsets(void);
#endif
