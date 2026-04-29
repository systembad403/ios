#include "stealth.h"
#include <dlfcn.h>
#include <sys/sysctl.h>
#include <unistd.h>
int is_debugged(void) {
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    sysctl(name, 4, &info, &size, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}
int is_jailbroken(void) {
    const char *paths[] = {"/Applications/Cydia.app", "/bin/bash", "/etc/apt", NULL};
    for (int i = 0; paths[i]; i++) if (access(paths[i], F_OK) == 0) return 1;
    return 0;
}
int is_lockdown_mode(void) { return 0; }
void apply_anti_debug(void) {
    void *handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    int (*ptrace)(int, pid_t, caddr_t, int) = dlsym(handle, "ptrace");
    if (ptrace) ptrace(31, 0, 0, 0);
}
