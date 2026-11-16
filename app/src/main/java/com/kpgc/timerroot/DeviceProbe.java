package com.kpgc.timerroot;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Debug logger: captures every device detail the shell user service can read
 * and appends it to the latest timer debug log on /data/local/tmp.
 *
 * The point is evidence for a failed port. An app process (untrusted_app) is
 * denied most of /proc and /sys, so the capture runs inside the Shizuku user
 * service (uid 2000, u:r:shell:s0), which reads the same files a manual
 * "adb shell" would. Everything is read-only probing: no exploit stage is
 * started here, and the capture is done before the exploit runs so a parked
 * process or a kernel panic afterwards still leaves the spec behind.
 *
 * Two logs, on purpose:
 *  - the latest timer debug log ({@link #DEBUG_LOG}) holds the current
 *    boot's device spec; it is truncated when a new capture starts, so the
 *    file always describes the run that is about to happen (or just
 *    happened). The exploit's own /data/local/tmp/timer.log and
 *    /data/local/tmp/timer_last.log stay untouched.
 *  - the auto-root log (AutoRoot.log(), device-protected storage) keeps the
 *    per-boot iteration history across reboots, because /data/local/tmp is
 *    only readable over adb while the phone is unlocked.
 */
final class DeviceProbe {

    /** World-readable, so adb can read it while the device is still locked. */
    static final String DEBUG_LOG = "/data/local/tmp/timer-debug.log";
    private static final int LOG_LIMIT = 256 * 1024;
    private static final SimpleDateFormat STAMP =
            new SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US);

    private DeviceProbe() {
    }

    /** One probed field: label, the command that produced it, its output. */
    static final class Entry {
        final String label;
        final String command;
        final String output;

        Entry(String label, String command, String output) {
            this.label = label;
            this.command = command;
            this.output = output == null ? "" : output.trim();
        }
    }

    /**
     * Builds the full capture. Every entry is independent: a denied or
     * missing file becomes "(unavailable)" rather than aborting the rest,
     * because a partial spec is still worth having after a failed plant.
     *
     * {@code service} is the Shizuku shell-user service: it executes the
     * reads in u:r:shell:s0, which sees /proc and /sys files an app process
     * is denied. Nothing here starts an exploit stage.
     */
    static String capture(IUserService service, String confSummary) {
        StringBuilder sb = new StringBuilder();
        sb.append("== TimerRoot device probe ==\n");
        sb.append("time=").append(STAMP.format(new Date())).append('\n');
        sb.append("boot_id=").append(AutoRoot.bootId()).append('\n');
        sb.append("uid=").append(uid(service)).append('\n');
        sb.append("mode=").append(mode(service)).append('\n');
        if (confSummary != null && !confSummary.isEmpty()) {
            sb.append("conf=").append(confSummary).append('\n');
        }
        sb.append("-- identity --\n");
        sb.append(entry(service, "build",
                "getprop ro.build.fingerprint; "
                        + "getprop ro.product.model; "
                        + "getprop ro.product.device; "
                        + "getprop ro.build.version.release; "
                        + "getprop ro.build.version.sdk"));
        sb.append(entry(service, "kernel_release", "uname -a"));
        sb.append(entry(service, "kernel_boot_params", "cat /proc/cmdline"));
        sb.append(entry(service, "kernel_version", "cat /proc/version"));
        sb.append("-- cpu / memory --\n");
        sb.append(entry(service, "cpu", "cat /proc/cpuinfo"));
        sb.append(entry(service, "memory",
                "head -n 8 /proc/meminfo; grep -i huge /proc/meminfo"));
        sb.append("-- security --\n");
        sb.append(entry(service, "selinux",
                "getenforce; cat /sys/kernel/security/lsm 2>/dev/null"));
        sb.append(entry(service, "seccomp",
                "grep -m1 Seccomp /proc/self/status; "
                        + "grep -m1 NoNewPrivs /proc/self/status"));
        sb.append(entry(service, "kernel_su",
                "/system/bin/su -c id 2>&1 | head -n1; "
                        + "grep -m1 '^kernelsu' /proc/modules 2>/dev/null"));
        sb.append("-- exploit state --\n");
        sb.append(entry(service, "binary",
                "ls -l /data/local/tmp/timer 2>&1; "
                        + "sha256sum /data/local/tmp/timer 2>/dev/null"));
        sb.append(entry(service, "profiles",
                "ls -R /data/local/tmp/timer-conf 2>&1 | head -n 60"));
        sb.append(entry(service, "ksud", "ls -l /data/local/tmp/w/ksud 2>&1"));
        sb.append("-- environment --\n");
        sb.append(entry(service, "tracing",
                "ls /sys/kernel/tracing 2>&1 | head -n 12; "
                        + "cat /sys/kernel/tracing/events/timer/"
                        + "timer_expire_entry/enable 2>&1"));
        sb.append(entry(service, "slab",
                "grep -E 'pid|cred|task|timer|kmalloc-192|kmalloc-256|"
                        + "kmalloc-512' /proc/slabinfo 2>&1 | head -n 20"));
        sb.append(entry(service, "mounts",
                "cat /proc/mounts | grep -E ' /(system|vendor|data|apex|"
                        + "system_ext|product) ' | head -n 20"));
        sb.append(entry(service, "modules", "head -n 20 /proc/modules 2>&1"));
        sb.append(entry(service, "props",
                "getprop | grep -Ei 'kernel|boot|slot|verified|vbmeta|"
                        + "kpatch|gki' | head -n 40"));
        sb.append("== end probe ==\n");
        return sb.toString();
    }

    private static String uid(IUserService service) {
        try {
            return service.probe("id -u; id");
        } catch (Throwable t) {
            return "unknown (" + t + ")";
        }
    }

    private static String mode(IUserService service) {
        try {
            return service.isSamsungMode() ? "samsung" : "generic";
        } catch (Throwable t) {
            return "unknown (" + t + ")";
        }
    }

    private static Entry entry(IUserService service, String label, String command) {
        String out;
        try {
            out = service.probe(command);
        } catch (Throwable t) {
            out = "(probe failed: " + t + ")";
        }
        if (out == null || out.trim().isEmpty()) {
            out = "(empty)";
        }
        return new Entry(label, command, out);
    }

    /** Truncates the latest debug log before a fresh capture is written. */
    static void reset() {
        try {
            File file = new File(DEBUG_LOG);
            File parent = file.getParentFile();
            if (parent != null) {
                //noinspection ResultOfMethodCallIgnored
                parent.mkdirs();
            }
            new FileOutputStream(file, false).close();
            android.system.Os.chmod(DEBUG_LOG, 0644);
        } catch (Throwable ignored) {
        }
    }

    /** Renders one capture as timestamped, world-readable text. */
    static synchronized String render(String capture) {
        StringBuilder sb = new StringBuilder();
        for (String line : capture.split("\n")) {
            sb.append(STAMP.format(new Date())).append("  ").append(line).append('\n');
        }
        return sb.toString();
    }

    /** Renders one boot-iteration line as timestamped text. */
    static synchronized String renderLine(String line) {
        return STAMP.format(new Date()) + "  " + line + "\n";
    }

    /** Appends text; keeps the file bounded like AutoRoot's own log. */
    static synchronized void append(String text) {
        File file = new File(DEBUG_LOG);
        try {
            if (file.length() > LOG_LIMIT) {
                String old = read();
                int keep = old.length() / 2;
                try (FileOutputStream out = new FileOutputStream(file, false)) {
                    out.write(old.substring(keep).getBytes("UTF-8"));
                }
            }
            try (FileOutputStream out = new FileOutputStream(file, true)) {
                out.write(text.getBytes("UTF-8"));
            }
            android.system.Os.chmod(DEBUG_LOG, 0644);
        } catch (Throwable ignored) {
        }
    }

    /** Full contents of the latest debug log, or a short note if absent. */
    static String read() {
        File file = new File(DEBUG_LOG);
        if (!file.exists()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                new FileInputStream(file), "UTF-8"))) {
            char[] buf = new char[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                sb.append(buf, 0, n);
                if (sb.length() > 256 * 1024) {
                    break;
                }
            }
        } catch (Throwable t) {
            return "cannot read " + DEBUG_LOG + ": " + t;
        }
        return sb.toString();
    }
}
