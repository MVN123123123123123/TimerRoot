package com.kpgc.timerroot;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import rikka.shizuku.Shizuku;

/**
 * Boot-time state machine:
 *
 *   wait for Shizuku -> start it over the local ADB channel if needed ->
 *   bind the shell user service -> install the bundled exploit -> run it once.
 *
 * The service stays in the foreground after success, because the root shell
 * lives in the Shizuku user service and that service is tied to this app
 * process. Stopping the service would throw the root shell away.
 */
public class AutoRootService extends Service {

    static final String ACTION_START = "com.kpgc.timerroot.AUTOROOT_START";
    static final String ACTION_STOP = "com.kpgc.timerroot.AUTOROOT_STOP";
    static final String ACTION_RUN_NOW = "com.kpgc.timerroot.AUTOROOT_RUN_NOW";
    static final String ACTION_PRESTART = "com.kpgc.timerroot.AUTOROOT_PRESTART";

    private static final String CHANNEL = "auto_root";
    private static final int NOTIFICATION_ID = 41;
    private static final String SHIZUKU_PACKAGE = "moe.shizuku.privileged.api";

    private Thread worker;
    private PowerManager.WakeLock wakeLock;
    private Shizuku.UserServiceArgs boundArgs;
    private ServiceConnection boundConnection;
    private IUserService userService;

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        startForeground(NOTIFICATION_ID, notification(
                "Auto-root", "preparing...", true));

        final boolean force = ACTION_RUN_NOW.equals(action);
        final boolean prestart = ACTION_PRESTART.equals(action);
        synchronized (this) {
            Thread previous = worker;
            Thread next = new Thread(() -> {
                if (previous != null) {
                    try {
                        // A prestart may still be running; run after it.
                        previous.join();
                    } catch (InterruptedException ignored) {
                    }
                }
                if (prestart) {
                    prestartShizuku();
                } else {
                    run(force);
                }
            }, "auto-root");
            next.start();
            worker = next;
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        releaseWakeLock();
        if (boundArgs != null && boundConnection != null) {
            try {
                // Keep the user service: an open root shell lives inside it.
                Shizuku.unbindUserService(boundArgs, boundConnection, false);
            } catch (Throwable ignored) {
            }
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    // ------------------------------------------------------------- worker

    /**
     * Starts Shizuku as early as possible (LOCKED_BOOT_COMPLETED) so it is
     * already up when the user unlocks and the binder can be delivered. It
     * does not touch the boot guard and does not bind: Shizuku's permission
     * check needs the credential-encrypted user, which is still locked.
     */
    private void prestartShizuku() {
        if (!AutoRoot.isEnabled(this)) {
            stopSelf();
            return;
        }
        AutoRoot.log(this, "prestart: looking for Shizuku");
        if (waitForShizuku(5000)) {
            AutoRoot.log(this, "prestart: Shizuku is already running");
            show("Auto-root", "Shizuku is up - waiting for unlock");
            return;
        }
        acquireWakeLock();
        try {
            /*
             * This runs seconds after the boot broadcast, when parts of the
             * system are still starting up. A starter call can therefore
             * return before the server is actually there, so retry a few
             * times instead of giving up on the first try.
             */
            for (int attempt = 1; attempt <= 4; attempt++) {
                show("Auto-root", "starting Shizuku early (try " + attempt + ")...");
                String started = startShizuku();
                AutoRoot.log(this, "prestart starter " + attempt + ": " + started);
                long deadline = System.currentTimeMillis() + 15000;
                boolean up = false;
                while (System.currentTimeMillis() < deadline) {
                    if (waitForShizuku(1500)) {
                        AutoRoot.log(this, "prestart: Shizuku is up");
                        up = true;
                        break;
                    }
                    if (shizukuServerRunning()) {
                        AutoRoot.log(this, "prestart: server is up, waiting for unlock");
                        up = true;
                        break;
                    }
                }
                if (up) {
                    break;
                }
                AutoRoot.log(this, "prestart: server still not up after try " + attempt);
            }
        } catch (Throwable t) {
            AutoRoot.log(this, "prestart failed: " + t);
        } finally {
            releaseWakeLock();
        }
        // Keep the service alive so the BOOT_COMPLETED attempt can reuse it.
        show("Auto-root", "Shizuku is up - waiting for unlock");
    }

    private void run(boolean force) {
        SharedPreferences prefs = AutoRoot.prefs(this);
        if (!prefs.getBoolean(AutoRoot.KEY_ENABLED, false)) {
            AutoRoot.log(this, "auto-root is disabled, stopping");
            finish("Auto-root is off", "Enable it in TimerRoot first.", false);
            return;
        }
        boolean restarted = AutoRoot.isRestart(this);
        boolean firstAttempt = AutoRoot.claimBoot(this);
        if (!force && !restarted && !firstAttempt) {
            AutoRoot.log(this, "already attempted this boot, skipping");
            finish("Auto-root", "Already ran this boot.", false);
            return;
        }
        if (restarted) {
            AutoRoot.log(this, "resuming this boot after the binder restart");
        }
        acquireWakeLock();

        String result;
        try {
            result = attempt();
        } catch (Throwable t) {
            result = "unexpected error: " + t;
        } finally {
            releaseWakeLock();
        }
        if (result == null) {
            // The process is about to die so the uid can go active again.
            return;
        }
        AutoRoot.clearRestart(this);
        AutoRoot.record(this, result);
        boolean success = result.startsWith("root shell ready");
        AutoRoot.log(this, (success ? "success: " : "failed: ") + result);
        if (success) {
            // Stay alive to keep the Shizuku user service (and the root shell).
            finish("Root shell ready", "The exploit reached uid=0.", true);
        } else {
            stopForeground(STOP_FOREGROUND_DETACH);
            finish("Auto-root failed", summary(result), false);
            stopSelf();
        }
    }

    private String attempt() throws Exception {
        String started = null;
        /*
         * Shizuku's binder cannot reach us before the first unlock: its
         * BinderSender checks the permission against the credential-
         * encrypted user. BOOT_COMPLETED normally arrives after the unlock
         * on Android 17, so this is only a safety net for the case where it
         * is delivered while the device is still at the lock screen. The
         * foreground service keeps the process alive while waiting.
         */
        releaseWakeLock(); // do not hold a 10 min lock through a long wait
        if (!waitForUnlock(30 * 60 * 1000L)) {
            // Do not burn this boot's one attempt on a device left locked.
            AutoRoot.releaseBoot(this);
            return "user is still locked after 30 min; unlock and press Run auto-root now";
        }
        acquireWakeLock();
        boolean binder = waitForShizuku(15000);
        boolean serverUp = false;
        if (binder) {
            AutoRoot.log(this, "Shizuku is already running");
            serverUp = true;
        } else {
            /*
             * The prestart stage (LOCKED_BOOT_COMPLETED) usually started the
             * server already. Do not restart a healthy server: the starter
             * kills the old process first, which would throw the early start
             * away.
             */
            serverUp = shizukuServerRunning();
            if (serverUp) {
                AutoRoot.log(this, "Shizuku server is already up from the prestart");
            } else {
                show("Auto-root", "starting Shizuku over the local ADB channel...");
                started = startShizuku();
                AutoRoot.log(this, "starter: " + started);
                long deadline = System.currentTimeMillis() + 45000;
                while (System.currentTimeMillis() < deadline) {
                    if (waitForShizuku(1500)) {
                        binder = true;
                        serverUp = true;
                        break;
                    }
                    if (shizukuServerRunning()) {
                        serverUp = true;
                        break;
                    }
                }
            }
        }

        if (!binder) {
            if (!serverUp) {
                return "Shizuku did not start ("
                        + (started == null ? "already running" : started) + ")";
            }
            /*
             * The server is up but has no idea this app exists: it only
             * pushes the binder on a uid gone -> active transition. Kill the
             * process once per boot and let a scheduled job start it again.
             */
            if (!AutoRoot.claimRestart(this)) {
                return "Shizuku is running but did not push its binder";
            }
            AutoRoot.log(this, "server is up, no binder yet; restarting the app process");
            show("Auto-root", "restarting to receive the Shizuku binder...");
            RestartJobService.schedule(this);
            killSelf();
            return null;
        }

        AutoRoot.clearRestart(this);
        int permission;
        try {
            permission = Shizuku.checkSelfPermission();
        } catch (Throwable t) {
            permission = -1;
        }
        if (permission != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            return "Shizuku permission is not granted - open TimerRoot and allow it once";
        }

        show("Auto-root", "binding the shell user service...");
        IUserService service = bindUserService();
        if (service == null) {
            return "could not bind the Shizuku user service";
        }

        String installed = service.install(getPackageCodePath());
        AutoRoot.log(this, installed);
        if (!installed.startsWith("installed")) {
            return "could not install the bundled exploit: " + installed;
        }
        String target = service.run("target");
        if (!target.contains("target=lynx")) {
            return "bundled exploit rejected for this kernel: " + target.trim();
        }

        show("Auto-root", "running the exploit...");
        AutoRoot.log(this, "timer shell");
        String output = service.openRoot();
        if (output.startsWith("root shell ready")) {
            return "root shell ready";
        }
        return "exploit did not reach uid=0: " + tail(output);
    }

    /**
     * True once the user has unlocked at least once since boot. The data
     * directory of the credential-encrypted user only becomes readable then.
     */
    private boolean userUnlocked() {
        android.os.UserManager um = getSystemService(android.os.UserManager.class);
        return um == null || um.isUserUnlocked();
    }

    private boolean waitForUnlock(long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (userUnlocked()) {
                return true;
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                return false;
            }
        }
        return userUnlocked();
    }

    private boolean waitForShizuku(long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            try {
                if (Shizuku.pingBinder()) {
                    return true;
                }
            } catch (Throwable ignored) {
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                return false;
            }
        }
        return false;
    }

    /**
     * Ends this process so the next start of the app is a uid gone -> active
     * transition. The scheduled job survives the kill and starts us again.
     */
    private void killSelf() {
        releaseWakeLock();
        try {
            Thread.sleep(250);
        } catch (InterruptedException ignored) {
        }
        android.os.Process.killProcess(android.os.Process.myPid());
    }

    /**
     * True when shizuku_server is alive, checked over the local ADB channel.
     * The server daemonizes, so its pid is not a child of the starter call.
     */
    private boolean shizukuServerRunning() {
        try {
            KeyPair pair = AutoRoot.keyPair(this);
            AdbLocal.Result result = AdbLocal.shell("127.0.0.1", AutoRoot.adbPort(this),
                    pair.getPrivate(), (RSAPublicKey) pair.getPublic(),
                    "pidof shizuku_server", 15000);
            return result.finished && result.output.trim().matches("[0-9]+");
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Runs Shizuku's own starter as the shell user over adbd. This is exactly
     * what Shizuku's wireless-debugging boot path does, except the port is
     * fixed (persist.adb.tcp.port) and comes from adb_keys, not mDNS.
     */
    private String startShizuku() {
        try {
            KeyPair pair = AutoRoot.keyPair(this);
            String command = "P=$(pm path " + SHIZUKU_PACKAGE + " | head -n1 | cut -d: -f2); "
                    + "D=$(dirname \"$P\"); "
                    + "L=$(ls \"$D\"/lib/*/libshizuku.so 2>/dev/null | head -n1); "
                    + "echo \"apk=$P\"; echo \"lib=$L\"; "
                    + "[ -x \"$L\" ] || { echo NO_STARTER; exit 1; }; "
                    + "\"$L\" --apk=\"$P\"; echo STARTER_DONE";
            AdbLocal.Result result = AdbLocal.shell("127.0.0.1", AutoRoot.adbPort(this),
                    pair.getPrivate(), (RSAPublicKey) pair.getPublic(),
                    command, 45000);
            String output = result.output == null ? "" : result.output.trim();
            AutoRoot.log(this, "adb starter raw: " + (output.isEmpty() ? "(no output)" : tail(output)));
            if (result.needsAuthorization) {
                return "TimerRoot's ADB key is not authorized yet - connect it once"
                        + " from a computer or tap Allow on the device";
            }
            if (result.finished) {
                return "launched";
            }
            String error = result.error == null ? "no response" : result.error;
            return "adb: " + error + (output.isEmpty() ? "" : " / " + output);
        } catch (Throwable t) {
            return "adb failed: " + t;
        }
    }

    private IUserService bindUserService() {
        final CountDownLatch latch = new CountDownLatch(1);
        final IUserService[] holder = new IUserService[1];
        final Shizuku.UserServiceArgs args = AutoRoot.serviceArgs(this);
        ServiceConnection connection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder binder) {
                holder[0] = IUserService.Stub.asInterface(binder);
                latch.countDown();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                AutoRoot.log(AutoRootService.this, "user service disconnected");
            }
        };
        try {
            Shizuku.bindUserService(args, connection);
            if (!latch.await(20, TimeUnit.SECONDS)) {
                return null;
            }
            boundArgs = args;
            boundConnection = connection;
            userService = holder[0];
            return holder[0];
        } catch (Throwable t) {
            AutoRoot.log(this, "bind failed: " + t);
            return null;
        }
    }

    // -------------------------------------------------------- notification

    private void createChannel() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(CHANNEL, "Auto-root",
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Boot-time root attempt state");
        channel.enableVibration(false);
        channel.setShowBadge(false);
        manager.createNotificationChannel(channel);
    }

    private Notification notification(String title, String text, boolean ongoing) {
        PendingIntent open = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                                | Intent.FLAG_ACTIVITY_CLEAR_TOP),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder builder = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setContentIntent(open)
                .setOnlyAlertOnce(true)
                .setOngoing(ongoing);
        if (ongoing) {
            PendingIntent stop = PendingIntent.getService(this, 1,
                    new Intent(this, AutoRootService.class)
                            .setAction(ACTION_STOP),
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            builder.addAction(new Notification.Action.Builder(null, "Stop", stop).build());
        }
        return builder.build();
    }

    private void show(String title, String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, notification(title, text, true));
        }
    }

    private void finish(String title, String text, boolean keepRunning) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, notification(title, text, keepRunning));
        }
        if (!keepRunning) {
            stopForeground(STOP_FOREGROUND_DETACH);
        }
    }

    private static String summary(String result) {
        return result.length() > 120 ? result.substring(0, 117) + "..." : result;
    }

    private static String tail(String output) {
        String trimmed = output.trim();
        if (trimmed.length() <= 400) {
            return trimmed;
        }
        return "..." + trimmed.substring(trimmed.length() - 400);
    }

    // ------------------------------------------------------------- wake lock

    private void acquireWakeLock() {
        try {
            PowerManager power = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (power == null || wakeLock != null) {
                return;
            }
            wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,
                    "TimerRoot:auto-root");
            wakeLock.setReferenceCounted(false);
            wakeLock.acquire(10 * 60 * 1000L);
        } catch (Throwable ignored) {
        }
    }

    private void releaseWakeLock() {
        try {
            if (wakeLock != null && wakeLock.isHeld()) {
                wakeLock.release();
            }
        } catch (Throwable ignored) {
        }
        wakeLock = null;
    }
}
