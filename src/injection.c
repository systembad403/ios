#include "injection.h"
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach_vm.h>
pid_t find_pid_by_name(const char *name) {
    struct kinfo_proc *procs = NULL;
    size_t count = 0;
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t bufSize = 0;
    sysctl(mib, 4, NULL, &bufSize, NULL, 0);
    procs = (struct kinfo_proc *)malloc(bufSize);
    if (sysctl(mib, 4, procs, &bufSize, NULL, 0) != 0) { free(procs); return -1; }
    count = bufSize / sizeof(struct kinfo_proc);
    for (size_t i = 0; i < count; i++) {
        if (strcmp(procs[i].kp_proc.p_comm, name) == 0) {
            pid_t pid = procs[i].kp_proc.p_pid;
            free(procs);
            return pid;
        }
    }
    free(procs);
    return -1;
}
kern_return_t inject_into_pid(pid_t target, const void *payload, size_t size) {
    task_t remote_task;
    kern_return_t kr = task_for_pid(mach_task_self(), target, &remote_task);
    if (kr != KERN_SUCCESS) return kr;
    mach_vm_address_t remote_addr = 0;
    kr = mach_vm_allocate(remote_task, &remote_addr, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return kr;
    kr = mach_vm_write(remote_task, remote_addr, (vm_offset_t)payload, size);
    if (kr != KERN_SUCCESS) return kr;
    arm_thread_state64_t state = {0};
    state.__pc = (uint64_t)remote_addr;
    state.__sp = (uint64_t)remote_addr + size - 0x1000;
    thread_act_t remote_thread;
    kr = thread_create_running(remote_task, ARM_THREAD_STATE64,
                               (thread_state_t)&state, ARM_THREAD_STATE64_COUNT,
                               &remote_thread);
    return kr;
}
void inject_powerd(const void *payload, size_t size) {
    pid_t pid = find_pid_by_name("powerd");
    if (pid > 0) inject_into_pid(pid, payload, size);
}
