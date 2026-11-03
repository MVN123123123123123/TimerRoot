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
    static final int MAX_RESTARTS = 2;
    static final String KEY_LAST_RESULT = "last_result";
    static final String KEY_LAST_RESULT_TIME = "last_result_time";
    static final String KEY_PRIVATE = "private_key";

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
     * Gives the boot back when the attempt could not even start (the device
     * was still locked). Without this a device left at the lock screen would
     * consume its one attempt and never retry that boot.
     */
    static void releaseBoot(Context context) {
        prefs(context).edit().remove(KEY_LAST_BOOT).apply();
    }

    /**
     * Claims the one allowed process restart for this boot. The restart is
     * what makes shizuku_server push its binder: it only reacts to a uid
     * gone -> active transition, and at boot the app process already exists
     * when the server starts.
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
                .apply();
        return true;
    }

    static boolean isRestart(Context context) {
        return prefs(context).getLong(KEY_RESTART_BOOT, Long.MIN_VALUE) == bootId();
    }

    static void clearRestart(Context context) {
        prefs(context).edit()
                .remove(KEY_RESTART_BOOT)
                .remove(KEY_RESTART_COUNT)
                .apply();
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
                .version(7);
    }
}
