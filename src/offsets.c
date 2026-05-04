#include "offsets.h"
#include <string.h>
#include <sys/sysctl.h>

/*
 * allproc_offset 语义说明（重要）
 * ─────────────────────────────
 * 这里存储的是「相对偏移」= allproc 静态 VA − 内核静态链接基址。
 * arm64 / arm64e 静态链接基址统一为 0xFFFFFFF007004000。
 * 运行时: allproc_runtime = kernel_base_runtime + allproc_offset
 *
 * 换算公式（从越狱/IDA 拿到静态 VA 后执行一次）：
 *   allproc_offset = allproc_static_va - 0xFFFFFFF007004000
 *
 * 例：Darwin 23.2.0 allproc 静态 VA = 0xFFFFFFF009A2C000
 *   0xFFFFFFF009A2C000 - 0xFFFFFFF007004000 = 0x2A28000
 *
 * struct 字段偏移（proc_p_pid 等）是结构体内相对偏移，不受 KASLR 影响，
 * 不需要任何换算，直接使用。
 *
 * 各版本 allproc 静态 VA 来源：
 *   Darwin 23.x : ipsw.me / ida / jelbrektime 公开符号
 *   Darwin 22.x : Dopamine/Fugu15 公开符号
 *   Darwin 21.x : unc0ver 公开符号
 *   Darwin 20.x / 19.x : checkra1n 公开符号（iOS 13/14 静态基址可能不同，
 *                          若 ke_run 失败可跳过提权直接采集）
 *
 * 若某版本在真机上偏移不对，用 Kfund / MemoryDump / lldb 查看
 *   (lldb) image lookup -s _allproc   →  得到运行时 VA
 *   allproc_offset = 运行时 VA - kernel_base_runtime（ke_run 打印的值）
 */

/*
 * 与 iOS 17.x 对应的 Darwin 版本（约）：
 *   17.0.x → 23.0.x，17.1.x → 23.1.x，17.2.x → 23.2.x（首要目标）
 *
 * sysctlbyname("kern.version") 返回串需命中下列子串之一，否则 get_kernel_offsets() 为 NULL，
 * 提权跳过但采集仍可能跑。若某小版本内核布局不同，请在真机上核对 kern.version 后：
 *   1）新增一行更合适子串；2）按越狱/安全笔记改正 allproc 与各结构位移。
 */
/*
 * ucred field offsets (arm64, XNU 10002, iOS 15–17):
 *
 *   struct ucred {
 *       TAILQ_ENTRY(ucred) cr_link;   // +0x00, 16 B
 *       u_long             cr_ref;    // +0x10,  8 B
 *       struct posix_cred  cr_posix;  // starts at +0x18
 *   };
 *   struct posix_cred {
 *       uid_t  cr_uid;      // +0x18, 4 B  ← ucred_cr_uid
 *       uid_t  cr_ruid;     // +0x1C, 4 B  (zeroed by 8-byte write at 0x18)
 *       uid_t  cr_svuid;    // +0x20, 4 B  ← ucred_cr_svuid (read-modify-write)
 *       short  cr_ngroups;  // +0x24, 2 B  (preserved by read-modify-write)
 *       ...
 *   };
 *
 * ucred_cr_ruid is NOT used directly — it is zeroed automatically when
 * elevate_to_root() does a single 8-byte kwrite64 at ucred_cr_uid (0x18),
 * which covers both cr_uid (0x18–0x1B) and cr_ruid (0x1C–0x1F).
 *
 * ucred_cr_svuid uses a read-modify-write to zero only the low 32 bits at
 * offset 0x20, leaving cr_ngroups (0x24) and cr_groups[] (0x28+) intact.
 *
 * host_special_port is unused by elevate_to_root; kept in struct for future use.
 *
 * Layout: { version_substr, allproc_off,
 *           proc_p_pid, proc_p_list_next, proc_p_ucred, proc_p_fd,
 *           ucred_cr_uid, ucred_cr_ruid (unused), ucred_cr_svuid,
 *           host_special_port }
 */
static const KernelOffsets offsets_table[] = {
    /*
     * Darwin 23.x — iOS 17.0 / 17.1 / 17.2
     * allproc 静态 VA: 0xFFFFFFF009A2C000 → 相对偏移: 0x2A28000
     * proc 字段偏移来自 XNU-10002.x 公开代码 + Dopamine 注释
     * ucred 字段偏移已按 XNU posix_cred struct 布局校正
     */
    { "Darwin Kernel Version 23.2.0", 0x2A28000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x1C, 0x20, 0x30F },
    { "Darwin Kernel Version 23.1.0", 0x2A28000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x1C, 0x20, 0x30F },
    { "Darwin Kernel Version 23.0.0", 0x2A28000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x1C, 0x20, 0x30F },

    /*
     * Darwin 22.x — iOS 16.x
     * allproc 静态 VA: 0xFFFFFFF0078B4000 → 相对偏移: 0x8B0000
     * (Dopamine/Fugu15 公开符号)
     */
    { "Darwin Kernel Version 22.5.0", 0x8B0000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x1C, 0x20, 0x30F },
    { "Darwin Kernel Version 22.4.0", 0x8B0000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x1C, 0x20, 0x30F },
    { "Darwin Kernel Version 22.3.0", 0x8B0000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x1C, 0x20, 0x30F },
    { "Darwin Kernel Version 22.2.0", 0x8B0000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x1C, 0x20, 0x30F },
    { "Darwin Kernel Version 22.1.0", 0x8B0000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x1C, 0x20, 0x30F },
    { "Darwin Kernel Version 22.0.0", 0x8B0000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x1C, 0x20, 0x30F },

    /*
     * Darwin 21.x — iOS 15.x
     * allproc 静态 VA: 0xFFFFFFF0078C4000 → 相对偏移: 0x8C0000
     * (unc0ver 5.x / Fugu14 公开符号; 若 15.0 有出入可单独新增一行)
     * proc_p_ucred 和 proc_p_fd 在 iOS 15 与 16/17 略有不同
     */
    { "Darwin Kernel Version 21.6.0", 0x8C0000, 0x68, 0x08, 0xF8, 0xE8, 0x18, 0x1C, 0x20, 0x30F },
    { "Darwin Kernel Version 21.5.0", 0x8C0000, 0x68, 0x08, 0xF8, 0xE8, 0x18, 0x1C, 0x20, 0x30F },
    { "Darwin Kernel Version 21.4.0", 0x8C0000, 0x68, 0x08, 0xF8, 0xE8, 0x18, 0x1C, 0x20, 0x30F },

    /*
     * Darwin 20.x — iOS 14.x / Darwin 19.x — iOS 13.x
     * ke_run() 可能对这些版本不准确（ipi_zone->zv_name 路径不同）。
     * 若 ke_run 返回 false，提权被跳过，采集仍继续。
     * allproc 偏移仅供参考，请在真机上用 checkra1n lldb 确认后替换。
     */
    { "Darwin Kernel Version 20.6.0", 0x5B0000, 0x68, 0x08, 0x100, 0xF0, 0x18, 0x1C, 0x20, 0x30F },
    { "Darwin Kernel Version 19.6.0", 0x380000, 0x60, 0x08, 0xF0,  0xE0, 0x18, 0x1C, 0x20, 0x30F },

    { NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

const KernelOffsets* get_kernel_offsets(void) {
    char kern_version[256];
    size_t size = sizeof(kern_version);
    sysctlbyname("kern.version", kern_version, &size, NULL, 0);
    for (int i = 0; offsets_table[i].version_substring != NULL; i++) {
        if (strstr(kern_version, offsets_table[i].version_substring))
            return &offsets_table[i];
    }
    return NULL;
}
