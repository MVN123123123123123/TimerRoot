package com.kpgc.timerroot;

import android.content.ComponentName;
import android.content.Context;
import android.content.SharedPreferences;
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
    static final String KEY_PRIVATE = "private_key";
    /** Live stage text for the boot status screen (device protected). */
    static final String KEY_STAGE = "stage";
    static final String KEY_STAGE_TIME = "stage_time";
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
    /** Restart the Android userspace once KernelSU is loaded (modules apply). */
    static final String KEY_SOFT_RESTART = "soft_restart";
    /** Boot id for which the automatic soft restart was already triggered. */
    static final String KEY_SOFT_RESTART_BOOT = "soft_restart_boot";
    /** Boot id for which the post-restart resume already ran. */
    static final String KEY_RESUME_BOOT = "resume_after_restart_boot";

    static final int STAGE_RUNNING = 0;
    static final int STAGE_OK = 1;
    static final int STAGE_FAILED = -1;

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
        prefs(context).edit()
                .putString(KEY_LAST_RESULT, result)
                .putLong(KEY_LAST_RESULT_TIME, System.currentTimeMillis())
                .apply();
    }

    static String lastResult(Context context) {
        return prefs(context).getString(KEY_LAST_RESULT, "");
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
                .commit();
    }

    static String stageText(Context context) {
        return prefs(context).getString(KEY_STAGE, "waiting for the boot…");
    }

    static long stageTime(Context context) {
        return prefs(context).getLong(KEY_STAGE_TIME, 0);
    }

    static int stageState(Context context) {
        return prefs(context).getInt(KEY_STAGE_STATE, STAGE_RUNNING);
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
                 * 8 -> 9 added softRestart().
                 */
                .version(9);
    }
}
