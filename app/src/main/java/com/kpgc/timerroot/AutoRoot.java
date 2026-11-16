package com.kpgc.timerroot;

import android.content.ComponentName;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.SystemClock;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import rikka.shizuku.Shizuku;

/**
 * Shared state for the boot path. Everything lives in device protected storage
 * so the receiver can read it before the user unlocks.
 */
final class AutoRoot {

    static final String PREFS = "auto_root";
    static final String KEY_ENABLED = "enabled";
    static final String KEY_ADB_PORT = "adb_port";
    static final String KEY_SETUP_DONE = "channel_installed";
    static final String KEY_LAST_BOOT = "last_attempt_boot";
    static final String KEY_RESTART_BOOT = "restart_boot";
    static final String KEY_RESTART_COUNT = "restart_count";
    static final String KEY_RESTART_PENDING = "restart_pending";
    static final int MAX_RESTARTS = 2;
    static final String KEY_LAST_RESULT = "last_result";
    static final String KEY_LAST_RESULT_TIME = "last_result_time";
    /** Boot id that produced last_result, so a reboot cannot inherit it. */
    static final String KEY_LAST_RESULT_BOOT = "last_result_boot";
    /**
     * Wall-clock heartbeat of the supervisor process. A run is live only while
     * this keeps moving; a silent heartbeat plus a claimed boot is what an
     * LMKD kill leaves behind.
     */
    static final String KEY_HEARTBEAT = "run_heartbeat";
    /** Stage that was in flight ("shell" or "fake") when the app last ran. */
    static final String KEY_RUN_PHASE = "run_phase";
    /** Wall-clock start of the KernelSU stage, so a resumed run keeps its budget. */
    static final String KEY_KSU_STARTED_AT = "ksu_started_at";
    static final String KEY_PRIVATE = "private_key";
    /** Live stage text for the boot status screen (device protected). */
    static final String KEY_STAGE = "stage";
    static final String KEY_STAGE_TIME = "stage_time";
    /** Boot id that wrote the stage, so a reboot cannot inherit it either. */
    static final String KEY_STAGE_BOOT = "stage_boot";
    /** 0 = running, 1 = success, -1 = failure. */
    static final String KEY_STAGE_STATE = "stage_state";
    /** Show the full-screen status activity over the lock screen. */
    static final String KEY_BOOT_UI = "boot_ui";
    /** Boot id for which the user tapped Hide; suppresses re-showing it. */
    static final String KEY_BOOT_UI_HIDDEN_BOOT = "boot_ui_hidden_boot";
    /**
     * Boot id for which the status screen was already acknowledged by a
     * restart: the completed result was on screen before the userspace
     * restart, so the resumed system must not show it again. The boot id
     * survives a soft restart, which is why this covers the resumed process.
     */
    static final String KEY_BOOT_UI_SEEN_BOOT = "boot_ui_seen_boot";
    /**
     * Samsung endgame selection. -1 = auto (default), 0 = forced generic,
     * 1 = forced Samsung.  Stored as an int so a user override can be
     * distinguished from the automatic vendor detection.
     */
    static final String KEY_SAMSUNG_MODE = "samsung_mode";
    static final int SAMSUNG_AUTO = -1;
    /** Restart the Android userspace once KernelSU is loaded (modules apply). */
    static final String KEY_SOFT_RESTART = "soft_restart";
    /** Boot id for which the automatic soft restart was already triggered. */
    static final String KEY_SOFT_RESTART_BOOT = "soft_restart_boot";
    /** Boot id for which the post-restart resume already ran. */
    static final String KEY_RESUME_BOOT = "resume_after_restart_boot";

    static final int STAGE_RUNNING = 0;
    static final int STAGE_OK = 1;
    static final int STAGE_FAILED = -1;

    /*
     * Result kinds. A uid-0 shell and a loaded KernelSU are not the same
     * outcome: the shell is the exploit's own root and dies with the boot,
     * while only KernelSU survives. Keeping them apart is what stops a
     * "... KernelSU failed: ..." result from being reported as a success.
     */
    static final int RESULT_FAILED = 0;
    static final int RESULT_SHELL = 1;
    static final int RESULT_KSU = 2;

    /**
     * One `timer fake` run plants three times and took 316 s to reach its
     * "selinux write failed" line on the Pixel 7a, so the old 90 s window
     * always expired while the plant was still racing. The exploit's own
     * `shell` stage is bounded at 300 s in UserService.openRoot().
     */
    static final long KSU_STAGE_BUDGET_MS = 8 * 60 * 1000L;
    /** All KernelSU replants together; a boot must not hang forever on it. */
    static final long KSU_TOTAL_BUDGET_MS = 15 * 60 * 1000L;
    /**
     * No heartbeat for this long means the supervisor is gone: the app was
     * killed while the detached exploit kept running. The heartbeat itself
     * ticks every 10 s, and a live run always beats within a few seconds of
     * that, so anything past four missed ticks is dead.
     *
     * This must stay well under the next broadcast: after a userspace
     * restart, `LOCKED_BOOT_COMPLETED` is redelivered once, about a minute
     * after the kill (observed 23:32:35 kill → 23:33:49 delivery on the
     * Pixel 7a). The old 90 s threshold was older than that gap, so the
     * recovery was thrown away and the boot sat unsupervised until the user
     * unlocked, 2.5 minutes later.
     */
    static final long HEARTBEAT_STALE_MS = 40 * 1000L;
    /** A stage that stopped printing for this long is dead, not busy. */
    static final long KSU_STALL_MS = 60 * 1000L;

    static final int DEFAULT_ADB_PORT = AdbLocal.DEFAULT_PORT;

    private static final String LOG_FILE = "auto_root.log";
    private static final int LOG_LIMIT = 64 * 1024;
    private static final SimpleDateFormat STAMP =
            new SimpleDateFormat("MM-dd HH:mm:ss", Locale.US);

    private AutoRoot() {
    }

    static SharedPreferences prefs(Context context) {
        return context.createDeviceProtectedStorageContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    static boolean isEnabled(Context context) {
        return prefs(context).getBoolean(KEY_ENABLED, false);
    }

    static void setEnabled(Context context, boolean enabled) {
        prefs(context).edit().putBoolean(KEY_ENABLED, enabled).commit();
    }

    // ------------------------------------------------------ Samsung mode

    /** True when this is a Samsung-built device (One UI / Exynos or SD). */
    static boolean isSamsungDevice() {
        return "samsung".equalsIgnoreCase(Build.MANUFACTURER)
                || "samsung".equalsIgnoreCase(Build.BRAND);
    }

    /** Stored override: {@link #SAMSUNG_AUTO}, 0 (generic) or 1 (Samsung). */
    static int samsungModeOverride(Context context) {
        return prefs(context).getInt(KEY_SAMSUNG_MODE, SAMSUNG_AUTO);
    }

    /**
     * True when the Samsung chain should be used.  A device with no override
     * follows the vendor automatically; once the user taps the toggle, the
     * explicit choice wins (so a Samsung phone can still run the generic
     * profile, and a non-Samsung phone can try the Samsung chain).
     */
    static boolean isSamsungMode(Context context) {
        int override = samsungModeOverride(context);
        return override != SAMSUNG_AUTO ? override == 1 : isSamsungDevice();
    }

    /** Stores an explicit on/off choice, replacing auto-detection. */
    static void setSamsungMode(Context context, boolean enabled) {
        prefs(context).edit()
                .putInt(KEY_SAMSUNG_MODE, enabled ? 1 : 0)
                .apply();
    }

    /** Drops the explicit choice and returns to vendor auto-detection. */
    static void useAutoSamsungMode(Context context) {
        prefs(context).edit().remove(KEY_SAMSUNG_MODE).apply();
    }

    /** Samsung mode's required manager (diabl0w/KernelSU Samsung build). */
    static final String SAMSUNG_MANAGER_PACKAGE = "me.weishu.kernelsu";
    /**
     * diabl0w/KernelSU keeps the upstream package name, so its Samsung build
     * is identified by the manager versionName prefix (samsung-v2.x).
     */
    static final String SAMSUNG_MANAGER_VERSION_PREFIX = "samsung-";
    /** Other KernelSU forks that must not be used for the Samsung chain. */
    private static final String[] OTHER_KSU_MANAGERS = {
            "me.weishu.kernelsu.pr", "com.rifsxd.ksunext", "com.sukisu.ultra"
    };

    /**
     * Returns null when the pinned diabl0w/KernelSU Samsung manager is
     * installed, or a user-facing reason why Samsung mode cannot run.
     *
     * The bundled ksud and its embedded module come from that release, so a
     * different KernelSU variant (or the upstream manager, which shares the
     * package name but not the samsung-v version) is rejected rather than
     * late-loaded into a mismatched module.
     */
    static String samsungManagerProblem(Context context) {
        PackageManager pm = context.getPackageManager();
        PackageInfo required = null;
        try {
            required = pm.getPackageInfo(SAMSUNG_MANAGER_PACKAGE, 0);
        } catch (PackageManager.NameNotFoundException ignored) {
        }
        if (required == null) {
            String other = installedOtherManager(pm);
            if (other != null) {
                return "Samsung mode is pinned to diabl0w/KernelSU ("
                        + SAMSUNG_MANAGER_PACKAGE + ", manager version"
                        + " samsung-v*), but " + other + " is installed"
                        + " instead. Uninstall it and install"
                        + " github.com/diabl0w/KernelSU";
            }
            return "Samsung mode is pinned to the diabl0w/KernelSU Samsung"
                    + " build (" + SAMSUNG_MANAGER_PACKAGE + ", manager"
                    + " version samsung-v*). Install github.com/diabl0w/KernelSU"
                    + " first";
        }
        String version = required.versionName;
        if (version == null
                || !version.startsWith(SAMSUNG_MANAGER_VERSION_PREFIX)) {
            return "Samsung mode is pinned to the diabl0w/KernelSU Samsung"
                    + " build, but the installed " + SAMSUNG_MANAGER_PACKAGE
                    + " reports version "
                    + (version == null ? "unknown" : version)
                    + ". Uninstall it and install github.com/diabl0w/KernelSU"
                    + " (manager version samsung-v*)";
        }
        String other = installedOtherManager(pm);
        if (other != null) {
            return "Samsung mode must use only diabl0w/KernelSU, but "
                    + other + " is also installed. Uninstall the other"
                    + " KernelSU manager and retry";
        }
        return null;
    }

    /** Package label of the first installed non-Samsung KernelSU manager. */
    private static String installedOtherManager(PackageManager pm) {
        for (String pkg : OTHER_KSU_MANAGERS) {
            try {
                PackageInfo pi = pm.getPackageInfo(pkg, 0);
                String version = pi.versionName;
                return pkg + (version == null ? "" : " " + version);
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }
        return null;
    }

    /** True when this boot already owns an attempt (running or finished). */
    static boolean isBootClaimed(Context context) {
        return prefs(context).getLong(KEY_LAST_BOOT, Long.MIN_VALUE) == bootId();
    }

    /** True when a binder-restart has been claimed but not consumed yet. */
    static boolean hasPendingRestart(Context context) {
        SharedPreferences prefs = prefs(context);
        return prefs.getLong(KEY_RESTART_BOOT, Long.MIN_VALUE) == bootId()
                && prefs.getBoolean(KEY_RESTART_PENDING, false);
    }

    static int adbPort(Context context) {
        return prefs(context).getInt(KEY_ADB_PORT, DEFAULT_ADB_PORT);
    }

    /** A boot identity that is stable for one boot and changes on the next. */
    static long bootId() {
        return (System.currentTimeMillis() - SystemClock.elapsedRealtime()) / 30000L;
    }

    /**
     * Claims a boot attempt. Returns false when another attempt already owns
     * this boot, which is what stops LOCKED_BOOT_COMPLETED + BOOT_COMPLETED,
     * a retry, or a second service start from running the exploit twice.
     */
    static boolean claimBoot(Context context) {
        SharedPreferences prefs = prefs(context);
        long boot = bootId();
        if (prefs.getLong(KEY_LAST_BOOT, Long.MIN_VALUE) == boot) {
            return false;
        }
        prefs.edit().putLong(KEY_LAST_BOOT, boot).apply();
        return true;
    }

    /**
     * Gives the boot back when the attempt could not even start the exploit
     * (no binder, no permission, bind or install failure). Without this a
     * device left at the lock screen would consume its one attempt and never
     * retry that boot. An actual exploit run always keeps the claim, because
     * the exploit is one-shot per boot.
     */
    static void releaseBoot(Context context) {
        prefs(context).edit().remove(KEY_LAST_BOOT).apply();
    }

    /**
     * Claims a process restart for this boot. Used only when shizuku_server
     * is running but its binder never arrived: a fresh process gives the uid
     * a gone -> active transition, which is when the server pushes it.
     */
    static boolean claimRestart(Context context) {
        SharedPreferences prefs = prefs(context);
        long boot = bootId();
        int count = prefs.getLong(KEY_RESTART_BOOT, Long.MIN_VALUE) == boot
                ? prefs.getInt(KEY_RESTART_COUNT, 0) : 0;
        if (count >= MAX_RESTARTS) {
            return false;
        }
        prefs.edit()
                .putLong(KEY_RESTART_BOOT, boot)
                .putInt(KEY_RESTART_COUNT, count + 1)
                .putBoolean(KEY_RESTART_PENDING, true)
                .apply();
        return true;
    }

    /**
     * Takes the pending restart for this boot, if any. Consuming it up front
     * makes sure the scheduled job and the post-unlock BOOT_COMPLETED cannot
     * both run the exploit: whichever arrives first proceeds, the other sees
     * no pending restart and no free boot claim.
     */
    static boolean consumeRestart(Context context) {
        SharedPreferences prefs = prefs(context);
        if (prefs.getLong(KEY_RESTART_BOOT, Long.MIN_VALUE) != bootId()
                || !prefs.getBoolean(KEY_RESTART_PENDING, false)) {
            return false;
        }
        prefs.edit().putBoolean(KEY_RESTART_PENDING, false).apply();
        return true;
    }

    static void clearRestart(Context context) {
        prefs(context).edit().putBoolean(KEY_RESTART_PENDING, false).apply();
    }

    static void record(Context context, String result) {
        /*
         * commit(), not apply(): an LMKD kill right after the recording must
         * not lose the outcome, otherwise the boot looks interrupted again.
         */
        prefs(context).edit()
                .putString(KEY_LAST_RESULT, result)
                .putLong(KEY_LAST_RESULT_TIME, System.currentTimeMillis())
                .putLong(KEY_LAST_RESULT_BOOT, bootId())
                .commit();
    }

    static String lastResult(Context context) {
        return prefs(context).getString(KEY_LAST_RESULT, "");
    }

    /**
     * The recorded result only counts for the boot that produced it. Without
     * this a reboot leaves the previous boot's "KernelSU active" on disk, and
     * the status screen reports a success this boot never had.
     */
    static String lastResultThisBoot(Context context) {
        SharedPreferences prefs = prefs(context);
        return prefs.getLong(KEY_LAST_RESULT_BOOT, Long.MIN_VALUE) == bootId()
                ? prefs.getString(KEY_LAST_RESULT, "") : "";
    }

    /** Drops the outcome: a run that starts now owes a fresh one. */
    static void clearResult(Context context) {
        prefs(context).edit()
                .remove(KEY_LAST_RESULT)
                .remove(KEY_LAST_RESULT_TIME)
                .remove(KEY_LAST_RESULT_BOOT)
                .commit();
    }

    /** Classifies a recorded result into {@link #RESULT_FAILED} and friends. */
    static int classify(String result) {
        if (result == null || !result.startsWith("root shell ready")) {
            return RESULT_FAILED;
        }
        return result.contains("KernelSU active") ? RESULT_KSU : RESULT_SHELL;
    }

    // -------------------------------------------------- supervisor liveness

    /**
     * Marks the supervisor alive. Refreshed every few seconds by the worker so
     * a run that lost its app process can be told apart from one that is
     * simply busy.
     */
    static void heartbeat(Context context) {
        prefs(context).edit()
                .putLong(KEY_HEARTBEAT, System.currentTimeMillis()).apply();
    }

    static long heartbeatAge(Context context) {
        return System.currentTimeMillis() - prefs(context).getLong(KEY_HEARTBEAT, 0);
    }

    /**
     * True when this boot's attempt has no outcome: the boot is claimed, no
     * result was recorded for it, and the supervisor stopped beating. That is
     * exactly what an LMKD kill leaves behind - the detached exploit may even
     * still be running, but nothing is watching it and the boot would
     * otherwise be written off as "already handled".
     */
    static boolean runInterrupted(Context context) {
        return isBootClaimed(context)
                && lastResultThisBoot(context).isEmpty()
                && heartbeatAge(context) > HEARTBEAT_STALE_MS;
    }

    /**
     * Remembers which stage is running, so a later process knows whether the
     * exploit was started (the one-shot claim must stay) and whether the
     * detached KernelSU plant is still worth re-attaching to.
     */
    static void setRunPhase(Context context, String phase) {
        prefs(context).edit().putString(KEY_RUN_PHASE, phase).commit();
    }

    static String runPhase(Context context) {
        return prefs(context).getString(KEY_RUN_PHASE, "");
    }

    /** Clears the in-flight stage bookkeeping (phase and its start time). */
    static void clearRunPhase(Context context) {
        prefs(context).edit()
                .remove(KEY_RUN_PHASE)
                .remove(KEY_KSU_STARTED_AT)
                .commit();
    }

    static long ksuStartedAt(Context context) {
        return prefs(context).getLong(KEY_KSU_STARTED_AT, 0);
    }

    static void setKsuStartedAt(Context context, long at) {
        prefs(context).edit().putLong(KEY_KSU_STARTED_AT, at).commit();
    }

    // ------------------------------------------------------- boot status UI

    /**
     * Publishes the current boot stage for the status activity. Uses
     * commit() rather than apply(): the value has to be on disk before the
     * activity reads it, and the stage changes only a handful of times per
     * boot.
     */
    static void stage(Context context, String text, int state) {
        if (text == null) {
            text = "";
        }
        prefs(context).edit()
                .putString(KEY_STAGE, text)
                .putLong(KEY_STAGE_TIME, System.currentTimeMillis())
                .putInt(KEY_STAGE_STATE, state)
                .putLong(KEY_STAGE_BOOT, bootId())
                .commit();
    }

    /**
     * True when the stored stage belongs to this boot. A reboot leaves the
     * previous boot's "loading KernelSU... 75s" behind, and the status screen
     * must show the new boot's state instead of a frozen one.
     */
    private static boolean stageIsCurrent(Context context) {
        return prefs(context).getLong(KEY_STAGE_BOOT, Long.MIN_VALUE) == bootId();
    }

    static String stageText(Context context) {
        return stageIsCurrent(context)
                ? prefs(context).getString(KEY_STAGE, "waiting for the boot…")
                : "waiting for the boot…";
    }

    static long stageTime(Context context) {
        return stageIsCurrent(context) ? prefs(context).getLong(KEY_STAGE_TIME, 0) : 0;
    }

    static int stageState(Context context) {
        return stageIsCurrent(context)
                ? prefs(context).getInt(KEY_STAGE_STATE, STAGE_RUNNING)
                : STAGE_RUNNING;
    }

    /**
     * True when the boot chain should soft-restart Android once KernelSU is
     * loaded. Defaults to on: a late-loaded module only runs its init scripts
     * and Zygisk after a userspace restart, so this is what turns a working
     * root shell into a usable rooted system.
     */
    static boolean softRestartEnabled(Context context) {
        return prefs(context).getBoolean(KEY_SOFT_RESTART, true);
    }

    static void setSoftRestartEnabled(Context context, boolean enabled) {
        prefs(context).edit().putBoolean(KEY_SOFT_RESTART, enabled).commit();
    }

    /**
     * Claims the one soft restart this boot gets. Linux's boot id survives a
     * userspace restart, and so does this preference, so the restarted system
     * cannot loop on it.
     */
    static boolean claimSoftRestart(Context context) {
        SharedPreferences prefs = prefs(context);
        long boot = bootId();
        if (prefs.getLong(KEY_SOFT_RESTART_BOOT, Long.MIN_VALUE) == boot) {
            return false;
        }
        prefs.edit().putLong(KEY_SOFT_RESTART_BOOT, boot).commit();
        return true;
    }

    static boolean softRestartDoneThisBoot(Context context) {
        return prefs(context).getLong(KEY_SOFT_RESTART_BOOT, Long.MIN_VALUE)
                == bootId();
    }

    /** Undoes the claim when the restart turned out to be unavailable. */
    static void releaseSoftRestart(Context context) {
        prefs(context).edit()
                .remove(KEY_SOFT_RESTART_BOOT)
                .commit();
    }

    /**
     * True once for the boot that follows a soft restart. The restarted system
     * sends both LOCKED_BOOT_COMPLETED and BOOT_COMPLETED, and which of them
     * arrives first depends on the lock state, so the resume path claims this
     * instead of relying on one specific broadcast.
     */
    static boolean claimResumeAfterRestart(Context context) {
        SharedPreferences prefs = prefs(context);
        long boot = bootId();
        if (prefs.getLong(KEY_RESUME_BOOT, Long.MIN_VALUE) == boot) {
            return false;
        }
        prefs.edit().putLong(KEY_RESUME_BOOT, boot).commit();
        return true;
    }

    static boolean bootUiEnabled(Context context) {
        return prefs(context).getBoolean(KEY_BOOT_UI, true);
    }

    static void setBootUiEnabled(Context context, boolean enabled) {
        SharedPreferences.Editor editor = prefs(context).edit()
                .putBoolean(KEY_BOOT_UI, enabled);
        if (enabled) {
            // Turning it back on also clears a Hide or a restart mark from
            // earlier this boot.
            editor.putLong(KEY_BOOT_UI_HIDDEN_BOOT, Long.MIN_VALUE)
                    .remove(KEY_BOOT_UI_SEEN_BOOT);
        }
        editor.commit();
    }

    /**
     * True when the status screen should be shown now: enabled, the user has
     * not hidden it on this boot, and this boot's completed result has not
     * already been acknowledged by a userspace restart. Hide and the restart
     * mark are per boot, so the next auto-root run may show it again.
     */
    static boolean bootUiWanted(Context context) {
        SharedPreferences prefs = prefs(context);
        long boot = bootId();
        return bootUiEnabled(context)
                && prefs.getLong(KEY_BOOT_UI_HIDDEN_BOOT, Long.MIN_VALUE) != boot
                && prefs.getLong(KEY_BOOT_UI_SEEN_BOOT, Long.MIN_VALUE) != boot;
    }

    static void hideBootUi(Context context) {
        prefs(context).edit()
                .putLong(KEY_BOOT_UI_HIDDEN_BOOT, bootId()).commit();
    }

    /**
     * Records that the completed result was on screen before a userspace
     * restart. The boot id survives the restart, so the resumed system sees
     * this and keeps the status screen away: the user already saw that the
     * phone is rooted and only gains a lock screen to unlock from here.
     */
    static void markBootUiSeen(Context context) {
        prefs(context).edit()
                .putLong(KEY_BOOT_UI_SEEN_BOOT, bootId()).commit();
    }

    /** Drops the mark when the restart did not actually happen. */
    static void clearBootUiSeen(Context context) {
        prefs(context).edit()
                .remove(KEY_BOOT_UI_SEEN_BOOT).commit();
    }

    /**
     * True when this boot's completed page was already seen and a userspace
     * restart suppressed it. The notification keeps its explicit **Status**
     * action in that case, so the user can still open the page on purpose.
     */
    static boolean bootUiSkippedAfterRestart(Context context) {
        return bootUiEnabled(context)
                && prefs(context).getLong(KEY_BOOT_UI_SEEN_BOOT, Long.MIN_VALUE)
                == bootId();
    }

    /** Directory for the optional boot screen background, readable at BFU. */
    static File bootUiDir(Context context) {
        File dir = new File(context.createDeviceProtectedStorageContext()
                .getFilesDir(), "bootui");
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        return dir;
    }

    // ------------------------------------------------------------- adb key

    static synchronized KeyPair keyPair(Context context) throws Exception {
        SharedPreferences prefs = prefs(context);
        String stored = prefs.getString(KEY_PRIVATE, "");
        if (!stored.isEmpty()) {
            try {
                PrivateKey key = AdbKey.decodePrivate(stored);
                RSAPublicKey publicKey = (RSAPublicKey) java.security.KeyFactory
                        .getInstance("RSA").generatePublic(
                                new java.security.spec.RSAPublicKeySpec(
                                        ((java.security.interfaces.RSAPrivateCrtKey) key)
                                                .getModulus(),
                                        ((java.security.interfaces.RSAPrivateCrtKey) key)
                                                .getPublicExponent()));
                return new KeyPair(publicKey, key);
            } catch (Exception ignored) {
                // Regenerate a key we cannot parse.
            }
        }
        KeyPair generated = AdbKey.generate();
        prefs.edit().putString(KEY_PRIVATE, AdbKey.encodePrivate(generated.getPrivate())).apply();
        return generated;
    }

    /** The line to append to adb_keys, or null when no key exists yet. */
    static String publicKeyLine(Context context) {
        try {
            KeyPair pair = keyPair(context);
            return AdbKey.publicKeyLine((RSAPublicKey) pair.getPublic());
        } catch (Exception e) {
            return null;
        }
    }

    // ------------------------------------------------------------- logging

    static File logFile(Context context) {
        return new File(context.createDeviceProtectedStorageContext().getFilesDir(),
                LOG_FILE);
    }

    static synchronized void log(Context context, String message) {
        String line = STAMP.format(new Date()) + "  " + message + "\n";
        File file = logFile(context);
        try {
            if (file.length() > LOG_LIMIT) {
                String old = readLog(context);
                int keep = old.length() / 2;
                try (FileOutputStream out = new FileOutputStream(file, false)) {
                    out.write(old.substring(keep).getBytes("UTF-8"));
                }
            }
            try (FileOutputStream out = new FileOutputStream(file, true)) {
                out.write(line.getBytes("UTF-8"));
            }
        } catch (Throwable ignored) {
        }
        android.util.Log.i("TimerRoot", "auto: " + message);
    }

    static String readLog(Context context) {
        File file = logFile(context);
        if (!file.exists()) {
            return "";
        }
        try (FileInputStream in = new FileInputStream(file)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (out.size() > 256 * 1024) {
                    break;
                }
            }
            return out.toString("UTF-8");
        } catch (Throwable t) {
            return "cannot read log: " + t;
        }
    }

    // ------------------------------------------------------------ shizuku

    static ComponentName component(Context context) {
        return new ComponentName(context.getPackageName(), UserService.class.getName());
    }

    static Shizuku.UserServiceArgs serviceArgs(Context context) {
        return new Shizuku.UserServiceArgs(component(context))
                .daemon(false)
                .processNameSuffix("timer")
                .debuggable(false)
                /*
                 * Bump on every AIDL change: Shizuku tears down a cached user
                 * service whose version differs, so a stale shell from an
                 * earlier APK can never answer the new transaction ids.
                 * 8 -> 9 added softRestart(); 9 -> 10 added setSamsungMode();
                 * 10 -> 11 added execSu(); 11 -> 12 added the device-probe
                 * methods (probe, captureDebugLog, readDebugLog) and
                 * isSamsungMode(); 12 -> 13 added appendDebugLog() so the
                 * auto-root iteration can write into the latest timer debug
                 * log.
                 */
                .version(13);
    }
}
