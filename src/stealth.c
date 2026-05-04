#include "stealth.h"
#include <dlfcn.h>
#include <sys/sysctl.h>
#include <unistd.h>

/*
 * PT_DENY_ATTACH (31) — prevents future ptrace attach attempts.
 * Defined here to avoid including <sys/ptrace.h> which is deprecated in the
 * public iPhoneOS SDK and generates -Wdeprecated warnings.
 */
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

int is_debugged(void) {
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info = {0};
    size_t size = sizeof(info);
    sysctl(name, 4, &info, &size, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

int is_jailbroken(void) {
    const char *paths[] = {
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/bin/bash",
        "/etc/apt",
        "/var/lib/dpkg/info",
        "/usr/sbin/sshd",
        NULL
    };
    for (int i = 0; paths[i]; i++)
        if (access(paths[i], F_OK) == 0) return 1;
    return 0;
}

int is_lockdown_mode(void) {
    /*
     * Lockdown Mode (iOS 16+) disables JIT and many APIs.
     * Detectable via MobileGestalt or SpringBoard preferences.
     * For now: check the known preference key path.
     */
    return access("/private/var/db/com.apple.security.lockdownmode.plist",
                  F_OK) == 0 ? 1 : 0;
}

void apply_anti_debug(void) {
    /*
     * PT_DENY_ATTACH (31) tells the kernel to reject any future ptrace attach.
     * Use RTLD_DEFAULT so dlsym searches all loaded images — ptrace lives in
     * libsystem_kernel.dylib which is always mapped in the process.
     */
    typedef int (*ptrace_fn_t)(int, pid_t, caddr_t, int);
    ptrace_fn_t ptrace_fn = (ptrace_fn_t)dlsym(RTLD_DEFAULT, "ptrace");
    if (ptrace_fn)
        ptrace_fn(PT_DENY_ATTACH, 0, 0, 0);
}
