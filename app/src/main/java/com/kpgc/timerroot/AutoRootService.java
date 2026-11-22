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
import android.os.DeadObjectException;
import android.os.IBinder;
import android.os.PowerManager;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import rikka.shizuku.Shizuku;

/**
 * Boot-time state machine:
 *
 *   wait for Shizuku -> start it over the local ADB channel if needed ->
 *   bind the shell user service -> install the bundled exploit -> run it once
 *   -> late-load KernelSU and re-apply permissive.
 *
 * This runs from LOCKED_BOOT_COMPLETED, so it normally completes before the
 * first unlock (BFU). The Shizuku provider is directBootAware, which is what
 * lets the server deliver its binder while the user is still locked.
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
    /**
     * Sent after a userspace restart: root is already in the kernel, so this
     * only brings Shizuku back and republishes the result. It must never run
     * the exploit again.
     */
    static final String ACTION_AFTER_RESTART = "com.kpgc.timerroot.AUTOROOT_AFTER_RESTART";

    private static final String CHANNEL = "auto_root";
    /** High-importance channel so the status notification may use a full-screen intent. */
    private static final String CHANNEL_BOOT = "auto_root_boot";
    private static final int NOTIFICATION_ID = 41;
    private static final String SHIZUKU_PACKAGE = "moe.shizuku.privileged.api";

    private Thread worker;
    private PowerManager.WakeLock wakeLock;
    private Thread heartbeatThread;
    private volatile boolean beating;
    private Shizuku.UserServiceArgs boundArgs;
    private ServiceConnection boundConnection;
    private IUserService userService;
    /** True once this service instance has called startForeground(). */
    private boolean foregroundStarted;
    /** True once the exploit has actually been started this boot. */
    private boolean exploitStarted;
    /**
     * Stage left behind by an interrupted run ("shell"/"fake"), captured when
     * the service starts so the recovery path knows what to do.
     */
    private String recoverPhase;
    /** Start of that interrupted KernelSU stage, so its budget still counts. */
    private long recoverStartedAt;

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
        /*
         * A duplicate boot broadcast, or a second start after a successful
         * run, must not replace the live notification or touch the root
         * shell. Stop a freshly created service (which also cancels the
         * startForegroundService deadline); leave an already running one
         * exactly as it is.
         *
         * An interrupted run is the exception: its claim is held but nothing
         * recorded an outcome, so the boot still needs a supervisor.
         */
        if (!ACTION_RUN_NOW.equals(action)
                && !ACTION_AFTER_RESTART.equals(action)
                && AutoRoot.isBootClaimed(this)
                && !AutoRoot.hasPendingRestart(this)
                && !AutoRoot.runInterrupted(this)) {
            log("already attempted this boot, ignoring " + action);
            if (!foregroundStarted) {
                stopSelf(startId);
            }
            return START_NOT_STICKY;
        }
        final boolean force = ACTION_RUN_NOW.equals(action);
        final boolean prestart = ACTION_PRESTART.equals(action);
        final boolean afterRestart = ACTION_AFTER_RESTART.equals(action);
        /*
         * The resume path republishes the recorded result immediately, so it
         * must not reset the stage to "waiting" or replace the outcome text
         * with "preparing...".
         */
        boolean bootUi = AutoRoot.bootUiWanted(this) && !afterRestart;
        if (bootUi) {
            AutoRoot.stage(this, "waiting for the boot…", AutoRoot.STAGE_RUNNING);
        }
        startForeground(NOTIFICATION_ID, notification(
                "Auto-root", afterRestart ? "restored" : "preparing...", true, bootUi));
        foregroundStarted = true;
        /*
         * Attach the status screen through the overlay exemption when it is
         * available. On Android 15+ this background start may be refused, in
         * which case the full-screen intent on the notification is the path
         * that actually shows it. Both are opportunistic and harmless.
         */
        if (AutoRoot.bootUiWanted(this) && !ACTION_RUN_NOW.equals(action)) {
            BootStatusActivity.maybeShow(this);
        }

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
                    startShizukuEarly();
                }
                if (afterRestart) {
                    resumeAfterRestart();
                } else {
                    run(force);
                }
            }, "auto-root");
            next.start();
            worker = next;
        }
        return START_NOT_STICKY;
    }

    /**
     * Post-soft-restart re-entry: the module is already in the kernel and the
     * exploit must not run again (its parked processes are gone from the
     * process table, but the boot claim still holds). All that is missing
     * after a userspace restart is Shizuku, so start it and republish the
     * previous success.
     */
    private void resumeAfterRestart() {
        String last = AutoRoot.lastResultThisBoot(this);
        log("after restart: last result=" + summary(last));
        if (AutoRoot.classify(last) == AutoRoot.RESULT_FAILED) {
            /*
             * No outcome was recorded for this boot. Reporting the previous
             * boot's success here is exactly how a failed run used to look
             * like a win, so say what is actually known.
             */
            AutoRoot.stage(this, "the restart left no recorded result",
                    AutoRoot.STAGE_RUNNING);
            if (!AutoRoot.isEnabled(this)) {
                finish("Auto-root is off", "Enable it in TimerRoot first.", false);
                return;
            }
            startShizukuEarly();
            finish("Auto-root", "Shizuku is back; no result was recorded for "
                    + "this boot.", false);
            stopSelf();
            return;
        }
        AutoRoot.stage(this, last, AutoRoot.STAGE_OK);
        if (!AutoRoot.isEnabled(this)) {
            finish("Auto-root is off", "Enable it in TimerRoot first.", false);
            return;
        }
        startShizukuEarly();
        finish(AutoRoot.classify(last) == AutoRoot.RESULT_KSU
                        ? "Jailbreak mode ready" : "Root shell ready",
                last, true);
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
     * Starts Shizuku as early as possible (LOCKED_BOOT_COMPLETED), before the
     * normal boot attempt. The service then continues straight into
     * {@link #run(boolean)}: with a direct-boot-aware provider the server can
     * hand over its binder while the credential-encrypted user is still
     * locked, so there is no reason to wait for the unlock.
     */
    private void startShizukuEarly() {
        if (!AutoRoot.isEnabled(this)) {
            return;
        }
        log("prestart: looking for Shizuku");
        if (waitForShizuku(5000)) {
            log("prestart: Shizuku is already running");
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
                log("prestart starter " + attempt + ": " + started);
                long deadline = System.currentTimeMillis() + 15000;
                boolean up = false;
                while (System.currentTimeMillis() < deadline) {
                    if (waitForShizuku(1500)) {
                        log("prestart: Shizuku is up");
                        up = true;
                        break;
                    }
                    if (shizukuServerRunning()) {
                        log("prestart: server is up, waiting for its binder");
                        up = true;
                        break;
                    }
                }
                if (up) {
                    break;
                }
                log("prestart: server still not up after try " + attempt);
            }
        } catch (Throwable t) {
            log("prestart failed: " + t);
        } finally {
            releaseWakeLock();
        }
    }

    private void run(boolean force) {
        SharedPreferences prefs = AutoRoot.prefs(this);
        if (!prefs.getBoolean(AutoRoot.KEY_ENABLED, false)) {
            log("auto-root is disabled, stopping");
            finish("Auto-root is off", "Enable it in TimerRoot first.", false);
            return;
        }
        boolean restarted = AutoRoot.consumeRestart(this);
        boolean firstAttempt = AutoRoot.claimBoot(this);
        /*
         * A claimed boot with no recorded outcome and no heartbeat is a run
         * whose supervisor was killed (LMKD under memory pressure). The
         * detached exploit may still be out there, so this must not be
         * mistaken for "already handled this boot". A pending binder restart
         * is its own recovery path and keeps its claim on purpose.
         */
        boolean recover = !restarted && !firstAttempt
                && AutoRoot.runInterrupted(this);
        if (!force && !restarted && !firstAttempt && !recover) {
            log("already attempted this boot, skipping");
            String last = AutoRoot.lastResultThisBoot(this);
            if (userService != null && AutoRoot.classify(last) != AutoRoot.RESULT_FAILED) {
                // Keep the successful run, its root shell and its FGS alive.
                finish(AutoRoot.classify(last) == AutoRoot.RESULT_KSU
                                ? "Jailbreak mode ready" : "Root shell ready",
                        last, true);
            } else {
                finish("Auto-root", "Already ran this boot.", false);
                stopSelf();
            }
            return;
        }
        if (restarted) {
            log("resuming this boot after the binder restart");
        }
        /*
         * Capture what the dead process left behind before this attempt
         * rewrites the stage bookkeeping. A recovery does not clear the phase
         * yet: if this process is killed too, the next one must still see that
         * the one-shot trigger was spent (and whether the detached plant is
         * worth re-attaching to). The phase is cleared with the result.
         */
        String phase = recover ? AutoRoot.runPhase(this) : "";
        recoverStartedAt = recover ? AutoRoot.ksuStartedAt(this) : 0;
        if (!recover) {
            AutoRoot.clearRunPhase(this);
        }
        recoverPhase = phase == null || phase.isEmpty() ? null : phase;
        if (recover && recoverPhase == null) {
            /*
             * The supervisor died before the exploit was started, so nothing
             * destructive ran: give the boot back and try normally.
             */
            log("the interrupted run never reached the exploit; retrying this boot");
            AutoRoot.releaseBoot(this);
            AutoRoot.claimBoot(this);
        } else if (recover) {
            log("recovering the interrupted run (" + recoverPhase + ")");
        }
        /*
         * From here on this boot has no decided outcome. Dropping the old
         * result is what keeps a previous success from being displayed while
         * the exploit is in flight - or after the supervisor is killed.
         */
        AutoRoot.clearResult(this);
        acquireWakeLock();
        startHeartbeat();

        String result;
        exploitStarted = false;
        try {
            result = attempt();
        } catch (Throwable t) {
            result = "unexpected error: " + t;
        } finally {
            stopHeartbeat();
            releaseWakeLock();
        }
        if (result == null) {
            // The process is about to die so the uid can go active again.
            return;
        }
        if (!exploitStarted) {
            /*
             * Nothing destructive ran, so this boot may still try again after
             * the unlock (or when the user presses Run auto-root now). The
             * one-exploit-per-boot guard is only spent by the exploit itself.
             */
            AutoRoot.releaseBoot(this);
        }
        AutoRoot.clearRestart(this);
        AutoRoot.clearRunPhase(this);
        AutoRoot.record(this, result);
        int kind = AutoRoot.classify(result);
        log((kind == AutoRoot.RESULT_KSU ? "success: "
                : kind == AutoRoot.RESULT_SHELL ? "partial (no KernelSU): "
                : "failed: ") + result);
        if (kind != AutoRoot.RESULT_FAILED) {
            // Stay alive to keep the Shizuku user service (and the root shell).
            finish(kind == AutoRoot.RESULT_KSU
                            ? "Jailbreak mode ready" : "Root shell ready",
                    kind == AutoRoot.RESULT_KSU
                            ? "KernelSU late-loaded; su works in u:r:ksu:s0."
                            : summary(result), true);
            if (kind == AutoRoot.RESULT_KSU && userService != null) {
                /*
                 * Last step, and deliberately after record() + finish(): the
                 * restart kills this process, so the outcome must already be
                 * on disk for the status screen and the restarted system.
                 */
                maybeSoftRestart(userService);
            }
        } else {
            stopForeground(STOP_FOREGROUND_DETACH);
            finish("Auto-root failed", summary(result), false);
            stopSelf();
        }
    }

    private String attempt() throws Exception {
        String started = null;
        if (recoverPhase != null) {
            /*
             * The dead process already spent this boot's trigger, whether or
             * not this process manages to take the supervision back: the
             * one-shot claim must stay even if the rebind fails below.
             */
            exploitStarted = true;
        }
        if (recoverPhase != null && !PHASE_FAKE.equals(recoverPhase)) {
            /*
             * The root shell lives in the Shizuku user service process, which
             * died with the app. There is nothing left to supervise, and a
             * second `timer shell` would spend the one trigger this boot gets.
             */
            return "auto-root was interrupted while the shell stage was running"
                    + " (the app was killed); reboot to retry";
        }
        /*
         * No unlock wait here. The provider is directBootAware, so
         * shizuku_server can deliver its binder to this app while the
         * credential-encrypted user is still locked, and the shell user
         * service lives in device-encrypted storage as well. Running the
         * exploit at BFU is the whole point of the boot path.
         */
        boolean binder = waitForShizuku(15000);
        boolean serverUp = false;
        if (binder) {
            log("Shizuku is already running");
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
                log("Shizuku server is already up from the prestart");
            } else {
                show("Auto-root", "starting Shizuku over the local ADB channel...");
                started = startShizuku();
                log("starter: " + started);
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
            if (!userUnlocked()) {
                /*
                 * The server hands its binder to every permission-holding
                 * app when it starts, through the direct-boot-aware
                 * provider. If it is still missing, do not rely on a
                 * JobScheduler restart that Android may defer until the
                 * unlock; leave the boot claim free so the post-unlock
                 * BOOT_COMPLETED can try again in a fresh process.
                 */
                return "Shizuku is up but its binder has not arrived; retrying after unlock";
            }
            /*
             * The server is up but has no idea this app exists: it only
             * pushes the binder on a uid gone -> active transition. Kill the
             * process once per boot and let a scheduled job start it again.
             */
            if (!AutoRoot.claimRestart(this)) {
                return "Shizuku is running but did not push its binder";
            }
            log("server is up, no binder yet; restarting the app process");
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

        if (PHASE_FAKE.equals(recoverPhase)) {
            /*
             * The detached `timer fake` and its log outlive this app process:
             * the app supervises the run, it does not own it. Rebind, pick
             * the log up where it is, and drive that same plant to its
             * terminal line instead of spending a second trigger on this
             * boot. The shell-domain root is gone with the old process, so
             * anything that needs it is done through KernelSU's su.
             */
            log("re-attaching to the KernelSU stage that outlived the app");
            show("Auto-root", "re-attaching to the KernelSU stage...");
            long startedAt = recoverStartedAt > 0 && recoverStartedAt <= System.currentTimeMillis()
                    ? recoverStartedAt : System.currentTimeMillis();
            /*
             * Keep the bookkeeping live: if this process is killed too, the
             * next one must still see the stage and its original start time.
             */
            AutoRoot.setRunPhase(this, PHASE_FAKE);
            if (AutoRoot.ksuStartedAt(this) <= 0) {
                AutoRoot.setKsuStartedAt(this, startedAt);
            }
            String ksu = loadKernelSu(service, startedAt);
            if (!ksu.startsWith("KernelSU active")) {
                /*
                 * The shell-domain root died with the old process, so a
                 * KernelSU failure here leaves no root at all. This is a plain
                 * failure, not the usual "shell works, no module" case.
                 */
                return "auto-root was interrupted and KernelSU did not load: " + ksu;
            }
            IUserService live = userService != null ? userService : service;
            log("boot UI grants: " + tail(applyBootUiGrants(live)));
            return "root shell ready; " + ksu;
        }

        /*
         * Beta builds only: force-refresh the binary before install()/probe so
         * the probe records the hash that actually runs. Best effort - a bad
         * network at locked boot must not stop auto-root from using the copy
         * already on the device.
         */
        String refreshed = null;
        if (MainActivity.AUTO_REFRESH_BETA) {
            BetaBinaryRefresh.Result result =
                    BetaBinaryRefresh.refresh(this, service, MainActivity.TIMER_URL);
            refreshed = result.message;
            log(refreshed);
        }

        String installed = service.install(getPackageCodePath());
        log(installed);
        if (!installed.startsWith("installed")) {
            return "could not install the bundled exploit: " + installed;
        }
        /*
         * Probe the whole device and write it to the latest timer debug log
         * before anything destructive runs, so a failed or parked plant still
         * leaves the kernel boot parameters, CPU/memory layout, SELinux state
         * and the resolved profile behind as evidence.
         */
        try {
            log(service.captureDebugLog());
            /* The probe truncates the debug log; keep the refresh line next to
             * the spec so a pulled log shows which binary was about to run. */
            if (refreshed != null) {
                service.appendDebugLog(refreshed);
            }
        } catch (Throwable t) {
            log("device probe failed: " + t);
        }
        String target = service.run("target");
        if (!target.contains("target=lynx")) {
            return "installed exploit rejected for this kernel: " + target.trim();
        }

        boolean samsung = AutoRoot.isSamsungMode(this);
        if (samsung) {
            String problem = AutoRoot.samsungManagerProblem(this);
            if (problem != null) {
                log(problem);
                return problem;
            }
        }
        show("Auto-root", samsung ? "running the Samsung chain..."
                : "running the exploit...");
        log(samsung ? "timer fake (samsung)" : "timer shell");
        /*
         * Written before the call: if the app is killed mid-exploit, the next
         * process must know a trigger was already spent on this boot.
         */
        AutoRoot.setRunPhase(this, PHASE_SHELL);
        exploitStarted = true;
        String output;
        try {
            output = service.openRoot();
        } catch (DeadObjectException e) {
            /*
             * Unlike `timer fake`, the root shell stage is a child of the
             * shell user service, so it dies with it. There is nothing left
             * to supervise and the one-shot trigger is already spent.
             */
            log("the shell user service died during the root shell stage");
            return "the shell user service died during the root shell stage;"
                    + " reboot to retry";
        }
        if (!output.startsWith("root shell ready")) {
            log("full shell-stage output: " + UserService.SHELL_LOG);
            return "exploit did not reach uid=0: " + shellStageFailure(output);
        }
        if (samsung) {
            /*
             * The Samsung endgame loads KernelSU inside the same `fake`
             * plant (DEFEX clear + KDP-safe ksud).  There is no shell-domain
             * root and no second late-load stage, and its SELinux is left to
             * ksud, so openRoot() already returned the final state.
             */
            log("boot UI grants: "
                    + tail(applyBootUiGrants(service)));
            log("samsung chain ready: " + tail(output));
            return output;
        }

        /*
         * The shell-domain root cannot keep KernelSU loaded across a boot, so
         * the chain does not stop here: the fake-credential endgame late-loads
         * the installed manager's module, exactly like the manual "Get root
         * shell" button does. A KSU failure must not throw away the working
         * root shell, hence the separate result suffix.
         */
        log("root shell ready; loading KernelSU");
        show("Auto-root", "loading KernelSU...");
        String ksu = loadKernelSu(service);
        /*
         * The boot status screen needs either "display over other apps" or
         * the "full-screen notifications" special access. Both are app-ops
         * that root can grant without touching the UI, so take them after
         * the time-sensitive KernelSU stage; the user can still revoke them
         * in Settings. Install channel does the same, so the first boot after
         * setup already has them.
         */
        /*
         * loadKernelSu() may have rebound the user service after the old
         * process died, so use the live field rather than the binding made at
         * the start of this attempt.
         */
        IUserService live = userService != null ? userService : service;
        log("boot UI grants: " + tail(applyBootUiGrants(live)));
        return "root shell ready; " + ksu;
    }

    /**
     * Best-effort boot UI app-op grants. The shell-domain root shell is gone
     * when the user service was rebound, but KernelSU's su is exactly what
     * those app-ops need, so fall back to it. A dead binder here must never
     * turn an already-loaded KernelSU into a failed run.
     */
    private static String applyBootUiGrants(IUserService service) {
        try {
            String viaShell = service.execRoot(grantBootUiAccess());
            if (viaShell != null && !viaShell.startsWith("root shell not open")) {
                return viaShell;
            }
        } catch (Throwable ignored) {
        }
        try {
            return service.execSu(grantBootUiAccess());
        } catch (Throwable t) {
            return "grants skipped: " + t;
        }
    }

    /**
     * Restarts the Android userspace after a successful late-load, so the
     * just-loaded module runs its boot stages and Zygisk - what the manager's
     * "soft reboot" button does. The kernel keeps KernelSU loaded, so su
     * survives; only the app processes are replaced.
     *
     * A soft restart throws this process away, so it must run last, after the
     * result is already recorded and published. Skipped when the user turned
     * it off, when a previous attempt this boot already did it, or when
     * KernelSU did not load - restarting without a module would only cost the
     * user a wait.
     */
    private void maybeSoftRestart(IUserService service) {
        if (!AutoRoot.softRestartEnabled(this)) {
            log("soft restart disabled");
            return;
        }
        if (!AutoRoot.claimSoftRestart(this)) {
            log("soft restart already done this boot");
            return;
        }
        String last = AutoRoot.lastResult(this);
        try {
            show("Auto-root", "restarting Android to load modules...");
            AutoRoot.stage(this, "Android is restarting with root; "
                    + "it returns to the lock screen when done", AutoRoot.STAGE_RUNNING);
            /*
             * The completed result is on screen right now, so the user already
             * knows the phone is rooted. After the userspace restart the device
             * is back at the lock screen and the same boot id comes with it;
             * record that so the resumed process does not show the finished
             * page again and the user simply gets the lock screen.
             */
            AutoRoot.markBootUiSeen(this);
            log("soft restart: requesting userspace restart");
            String result = service.softRestart();
            log("soft restart: " + result);
            if (result.startsWith("soft restart unavailable")
                    || result.startsWith("soft restart failed")) {
                /*
                 * Nothing was restarted, so put the success back: the stage is
                 * what the status screen reads. Free the claim so a restart can
                 * still be requested by hand, and let the screen show again
                 * since the user never left it.
                 */
                AutoRoot.releaseSoftRestart(this);
                AutoRoot.clearBootUiSeen(this);
                AutoRoot.stage(this, last, AutoRoot.STAGE_OK);
            } else if (!result.endsWith("started")) {
                /*
                 * The command was sent but the system did not visibly go down
                 * within the probe window. Keep the claim and the seen mark
                 * (the restart may still be in flight, and the resume path must
                 * not re-run the exploit) but stop claiming progress on screen.
                 */
                AutoRoot.stage(this, last, AutoRoot.STAGE_OK);
            }
        } catch (Throwable t) {
            /*
             * Expected: "stop" kills this process, so the binder call dies
             * mid-flight. Anything else means the restart did not start, and
             * the root shell is still valid.
             */
            log("soft restart call ended: " + t);
        }
    }

    /** How many times the racy late-load stage may be replanted. */
    private static final int KSU_ATTEMPTS = 3;
    /** Run phases persisted in {@link AutoRoot#KEY_RUN_PHASE}. */
    private static final String PHASE_SHELL = "shell";
    private static final String PHASE_FAKE = "fake";

    private static final class KsuStage {
        boolean loaded;
        String failure;
        /** True when the plant lost its race and nothing was loaded yet. */
        boolean replant;
        /**
         * True when the binder to the shell user service died while this
         * stage was being watched. The detached plant keeps running; the
         * caller must rebind and resume watching it, not start another one.
         */
        boolean reconnect;
    }

    /**
     * Runs `timer fake`, which points the child's credentials at a fake
     * full-capability cred and execs ksud late-load. That same plant also
     * clears the kernel's SELinux enforcing flag, so no separate
     * `timer permissive` run is needed.
     *
     * The stage shell can be torn down by the loader (SukiSU Ultra) before it
     * prints KSU_LOADED, so `su -c id` in u:r:ksu:s0 is the authoritative
     * success signal. KernelSU re-enables SELinux about 0.4s after it loads,
     * which is why keepPermissive() runs afterwards.
     *
     * A plant can miss its burst and park a zombie; the exploit itself
     * replants up to three times in `shell`/`permissive` mode for exactly
     * that reason, so the whole stage is replanted here too. A parked
     * process keeps its fake cred page pinned, which is the pristine state
     * between attempts.
     */
    private String loadKernelSu(IUserService service) {
        return loadKernelSu(service, 0);
    }

    /**
     * KernelSU stage for a run that may have outlived its app process.
     * {@code resumedAt} is the wall-clock start of a plant that was already
     * running (0 starts a new one); the budget is measured from there, so a
     * recovered run does not get a fresh eight minutes on top of the time
     * the plant has already spent.
     */
    private String loadKernelSu(IUserService service, long resumedAt) {
        long runStart = resumedAt > 0 ? resumedAt : System.currentTimeMillis();
        String failure = resumedAt > 0
                ? "the app was killed before the stage finished"
                : "no attempt was made";
        IUserService active = service;
        try {
            for (int attempt = 1; attempt <= KSU_ATTEMPTS; attempt++) {
                boolean resume = attempt == 1 && resumedAt > 0;
                if (attempt > 1) {
                    if (System.currentTimeMillis() - runStart
                            >= AutoRoot.KSU_TOTAL_BUDGET_MS) {
                        failure = "out of time after "
                                + (AutoRoot.KSU_TOTAL_BUDGET_MS / 60000)
                                + " minutes of KernelSU attempts";
                        break;
                    }
                    log("KernelSU attempt " + attempt + ": "
                            + failure);
                    show("Auto-root", "retrying KernelSU (" + attempt + "/"
                            + KSU_ATTEMPTS + ")...");
                }
                KsuStage stage = runKsuStage(active, attempt, resume, runStart);
                /*
                 * The exploit is detached: if the shell user service dies
                 * while the plant is racing, the timer binary keeps going and
                 * can still load KernelSU. That used to surface as a
                 * DeadObjectException failure even though root was acquired.
                 * Rebind and re-attach to the same plant instead of spending a
                 * second one-shot trigger on this boot.
                 */
                String reconnectFailure = null;
                for (int reconnect = 0;
                        stage.reconnect && reconnect < KSU_RECONNECTS;
                        reconnect++) {
                    if (System.currentTimeMillis() - runStart
                            >= AutoRoot.KSU_TOTAL_BUDGET_MS) {
                        reconnectFailure = "out of time while reconnecting to"
                                + " the shell user service";
                        break;
                    }
                    log("the KernelSU stage outlived the shell user service;"
                            + " rebinding");
                    active = rebindUserService();
                    if (active == null) {
                        reconnectFailure = "the shell user service is gone and"
                                + " could not be rebound (the detached plant may"
                                + " still finish; reboot to re-check)";
                        break;
                    }
                    log("watching the KernelSU stage that is already running");
                    stage = runKsuStage(active, attempt, true, runStart);
                }
                if (stage.reconnect) {
                    failure = reconnectFailure != null ? reconnectFailure
                            : "the shell user service kept dying during the"
                                    + " KernelSU stage";
                    break;
                }
                if (stage.loaded) {
                    String selinux = keepPermissive(active);
                    log("KernelSU active: " + selinux);
                    log(tail(readLogQuietly(active)));
                    return "KernelSU active (" + selinux + ")";
                }
                log(tail(readLogQuietly(active)));
                failure = stage.failure;
                if (!stage.replant) {
                    break;
                }
            }
        } catch (Throwable t) {
            log("KernelSU step failed: " + t);
            return "KernelSU failed: " + t;
        }
        return "KernelSU failed: " + failure;
    }

    /** How many times a dead shell user service may be rebound per run. */
    private static final int KSU_RECONNECTS = 4;

    /**
     * Replaces a shell user service whose binder died. The Shizuku server is
     * normally still alive (only the app_process it spawned went away); if
     * that is gone too, start it again over the local ADB channel first.
     */
    private IUserService rebindUserService() {
        /*
         * Drop the dead binding first. `kill=false` keeps a still-alive user
         * service around (it may hold the root shell), and the call is
         * harmless when Shizuku already removed the record.
         */
        if (boundArgs != null && boundConnection != null) {
            try {
                Shizuku.unbindUserService(boundArgs, boundConnection, false);
            } catch (Throwable ignored) {
            }
        }
        boundArgs = null;
        boundConnection = null;
        userService = null;
        for (int i = 0; i < 3; i++) {
            if (!waitForShizuku(2000)) {
                log("Shizuku binder is gone; restarting the server");
                log("restart: " + startShizuku());
                if (!waitForShizuku(10000)) {
                    log("Shizuku did not come back");
                    continue;
                }
            }
            IUserService rebound = bindUserService();
            if (rebound != null) {
                log("shell user service rebound");
                return rebound;
            }
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                return null;
            }
        }
        log("could not rebind the shell user service");
        return null;
    }

    /** keepPermissive() must never turn a loaded KernelSU into a failure. */
    private String keepPermissive(IUserService active) {
        try {
            return active.keepPermissive();
        } catch (Throwable t) {
            log("keepPermissive failed: " + t);
            IUserService rebound = rebindUserService();
            if (rebound != null) {
                try {
                    return rebound.keepPermissive();
                } catch (Throwable t2) {
                    log("keepPermissive failed after rebind: " + t2);
                }
            }
            return "selinux state unavailable";
        }
    }

    private static String readLogQuietly(IUserService active) {
        try {
            return active.readLog();
        } catch (Throwable t) {
            return "";
        }
    }

    /**
     * Supervises one `timer fake` plant. A plant needs minutes, not seconds:
     * three internal attempts, each waiting for its child to exec and be
     * killed. The 90 s window this used to have expired while the plant was
     * still racing, so the outcome was always "timed out" and the failure
     * line was never seen.
     *
     * {@code resume} means the plant was started by an earlier, killed app
     * process: its output file is still there and must not be truncated by a
     * second runDetached().
     */
    private KsuStage runKsuStage(IUserService service, int attempt, boolean resume,
                                 long runStart) {
        KsuStage stage = new KsuStage();
        try {
            final long stageStart = System.currentTimeMillis();
            /*
             * The stage budget covers one plant; the total budget covers all
             * replants, and is never cut below a minute so a run recovered
             * long after the fact can still have its log evaluated.
             */
            final long deadline = Math.min(stageStart + AutoRoot.KSU_STAGE_BUDGET_MS,
                    Math.max(runStart + AutoRoot.KSU_TOTAL_BUDGET_MS,
                            stageStart + 60_000L));
            if (resume) {
                /*
                 * The plant may have won its race - or been loaded by the
                 * loader - after the app died and before it printed anything
                 * terminal. Root that already works ends the stage here.
                 */
                if (service.ksuActive()) {
                    stage.loaded = true;
                    return stage;
                }
                log("watching the KernelSU stage that is already running");
            } else {
                AutoRoot.setRunPhase(this, PHASE_FAKE);
                if (AutoRoot.ksuStartedAt(this) <= 0) {
                    AutoRoot.setKsuStartedAt(this, stageStart);
                }
                /*
                 * runDetached() truncates /data/local/tmp/timer.log, so
                 * anything read from here on belongs to this run.
                 */
                String started = service.runDetached("fake");
                log("timer fake");
                if (started.startsWith("start failed")) {
                    stage.failure = tail(started);
                    return stage;
                }
            }
            long lastChange = System.currentTimeMillis();
            long lastProgress = 0;
            int lastLength = service.readLog().length();
            boolean sawLateLoad = false;
            while (System.currentTimeMillis() < deadline) {
                Thread.sleep(1000);
                String log = service.readLog();
                if (log.length() != lastLength) {
                    lastLength = log.length();
                    lastChange = System.currentTimeMillis();
                }
                if (log.contains("KSU_LOADED")) {
                    /*
                     * The marker is the stage's own claim, and a loader can
                     * print it without actually handing out root. Ask the
                     * kernel, exactly like the late-load paths below do.
                     */
                    if (service.ksuActive()) {
                        stage.loaded = true;
                    } else {
                        stage.failure = "the stage printed KSU_LOADED but su does"
                                + " not hand out u:r:ksu:s0";
                    }
                    return stage;
                }
                if (log.contains("selinux write failed")) {
                    stage.failure = "the selinux stage missed its race";
                    stage.replant = true;
                    return stage;
                }
                if (log.contains("KSU_STALE")) {
                    stage.failure = "an old KernelSU module is still loaded";
                    return stage;
                }
                if (log.contains("[ksu] ksud missing")) {
                    stage.failure = "no supported manager (KernelSU,"
                            + " KernelSU-Next, SukiSU)";
                    return stage;
                }
                if (log.contains("KSU_MISSING")) {
                    stage.failure = "ksud late-load failed - see the [ksu]"
                            + " log lines";
                    return stage;
                }
                if (log.contains("[ksu] late-load rc=0")) {
                    sawLateLoad = true;
                }
                /*
                 * The exploit parent always parks, even on success, so the
                 * parking line alone means nothing. Once the late-load has
                 * run, ask the kernel whether root actually works.
                 */
                if (log.contains("parking without reap")) {
                    if (sawLateLoad && service.ksuActive()) {
                        stage.loaded = true;
                    } else if (sawLateLoad) {
                        stage.failure = "ksud finished but su is not available";
                    } else {
                        stage.failure = "the exploit parked before loading"
                                + " ksud";
                        stage.replant = true;
                    }
                    return stage;
                }
                if (sawLateLoad
                        && System.currentTimeMillis() - lastChange > 5000) {
                    if (service.ksuActive()) {
                        stage.loaded = true;
                    } else {
                        stage.failure = "ksud late-load finished but su is"
                                + " not available";
                    }
                    return stage;
                }
                long secs = (System.currentTimeMillis() - stageStart) / 1000;
                if (secs - lastProgress >= 5) {
                    lastProgress = secs;
                    String label = attempt > 1 ? " (" + attempt + "/"
                            + KSU_ATTEMPTS + ")" : "";
                    show("Auto-root", "loading KernelSU... " + secs + "s" + label);
                }
            }
            if (service.ksuActive()) {
                // Last chance: the stage may have lost its output.
                stage.loaded = true;
                return stage;
            }
            stage.failure = "the KernelSU stage did not finish in time";
            /*
             * Only a stage that went silent is worth replacing: a live plant
             * keeps printing, and a second plant started while the first is
             * still racing would make both of them lose.
             */
            long quiet = System.currentTimeMillis() - lastChange;
            stage.replant = quiet >= AutoRoot.KSU_STALL_MS;
            if (stage.replant) {
                stage.failure += " (no output for " + (quiet / 1000) + "s)";
            }
            return stage;
        } catch (DeadObjectException e) {
            /*
             * The shell user service was killed (LMKD, or Shizuku tearing the
             * record down). The `timer fake` process is detached and keeps
             * running, so this is not a failed plant: the caller rebinds and
             * resumes watching the same log.
             */
            log("the shell user service died during the KernelSU stage");
            stage.failure = "the shell user service died mid-stage";
            stage.reconnect = true;
            return stage;
        } catch (Throwable t) {
            log("KernelSU step failed: " + t);
            stage.failure = String.valueOf(t);
            return stage;
        }
    }

    /**
     * True once the user has unlocked at least once since boot. Used only to
     * decide whether the binder restart fallback can run; the normal BFU path
     * does not depend on it.
     */
    private boolean userUnlocked() {
        android.os.UserManager um = getSystemService(android.os.UserManager.class);
        return um == null || um.isUserUnlocked();
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
            log("adb starter raw: " + (output.isEmpty() ? "(no output)" : tail(output)));
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
                log("user service disconnected");
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
            try {
                // The user service runs as shell and cannot read the app's
                // device-protected mode preference, so pass it explicitly.
                userService.setSamsungMode(AutoRoot.isSamsungMode(this));
            } catch (Throwable t) {
                log("setSamsungMode failed: " + t);
            }
            return holder[0];
        } catch (Throwable t) {
            log("bind failed: " + t);
            return null;
        }
    }

    // ------------------------------------------------------------- logging

    /**
     * Writes one auto-root boot-iteration line to both logs: AutoRoot's own
     * device-protected history (survives a reboot, readable at BFU) and the
     * latest timer debug log on /data/local/tmp, appended after the device
     * probe so the decisions sit next to the spec they explain. The debug
     * copy is best-effort: without a bound shell user service there is
     * nothing to append through, and the history line still lands.
     */
    private void log(String message) {
        AutoRoot.log(this, message);
        IUserService service = this.userService;
        if (service != null) {
            try {
                service.appendDebugLog(message);
            } catch (Throwable ignored) {
            }
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

        /*
         * A full-screen intent is only honoured from a high-importance
         * channel. Keep it silent: the screen is the point, not the alert.
         */
        NotificationChannel boot = new NotificationChannel(CHANNEL_BOOT,
                "Boot status screen", NotificationManager.IMPORTANCE_HIGH);
        boot.setDescription("Shows the auto-root progress over the lock screen");
        boot.setSound(null, null);
        boot.enableVibration(false);
        boot.setShowBadge(false);
        boot.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
        manager.createNotificationChannel(boot);
    }

    private Notification notification(String title, String text, boolean ongoing,
                                      boolean fullScreen) {
        PendingIntent open = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                                | Intent.FLAG_ACTIVITY_CLEAR_TOP),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder builder = new Notification.Builder(this,
                fullScreen ? CHANNEL_BOOT : CHANNEL)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setContentIntent(open)
                .setOnlyAlertOnce(true)
                .setOngoing(ongoing);
        if (fullScreen) {
            builder.setFullScreenIntent(BootStatusActivity.pendingIntent(this), true)
                    .setCategory(Notification.CATEGORY_SERVICE)
                    .setVisibility(Notification.VISIBILITY_PUBLIC);
        }
        if (AutoRoot.bootUiWanted(this) || AutoRoot.bootUiSkippedAfterRestart(this)) {
            builder.addAction(new Notification.Action.Builder(null, "Status",
                    BootStatusActivity.pendingIntent(this)).build());
        }
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
        AutoRoot.stage(this, text, AutoRoot.STAGE_RUNNING);
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, notification(title, text, true,
                    AutoRoot.bootUiWanted(this)));
        }
    }

    private void finish(String title, String text, boolean keepRunning) {
        int state;
        String lower = title == null ? "" : title.toLowerCase(Locale.US);
        if (lower.contains("ready")) {
            state = AutoRoot.STAGE_OK;
        } else if (lower.contains("failed") || lower.contains("off")) {
            state = AutoRoot.STAGE_FAILED;
        } else {
            state = AutoRoot.STAGE_RUNNING;
        }
        AutoRoot.stage(this, text, state);
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            /*
             * The full-screen intent is only needed while the run is live and
             * for the final outcome. "Already ran this boot." should not pop
             * a screen, so only attach it for a terminal state.
             */
            boolean fullScreen = AutoRoot.bootUiWanted(this)
                    && state != AutoRoot.STAGE_RUNNING;
            manager.notify(NOTIFICATION_ID, notification(title, text, keepRunning,
                    fullScreen));
        }
        if (!keepRunning) {
            stopForeground(STOP_FOREGROUND_DETACH);
        }
    }

    private static String summary(String result) {
        return result.length() > 120 ? result.substring(0, 117) + "..." : result;
    }

    /**
     * Grants the two app-ops the boot status screen can use, from a
     * shell-domain uid-0 shell. "Display over other apps" is the background
     * activity launch exemption; USE_FULL_SCREEN_INTENT lets the notification
     * open the screen over the keyguard on Android 14+. Failures are harmless
     * (older releases may not have the full-screen op).
     */
    static String grantBootUiAccess() {
        return "appops set com.kpgc.timerroot android:use_full_screen_intent allow; "
                + "appops set com.kpgc.timerroot android:system_alert_window allow; "
                + "echo BOOT_UI_GRANTS_DONE";
    }

    private static String tail(String output) {
        String trimmed = output.trim();
        if (trimmed.length() <= 400) {
            return trimmed;
        }
        return "..." + trimmed.substring(trimmed.length() - 400);
    }

    /**
     * Turns the shell stage's output into the one sentence a user can act on.
     * The exploit's raw lines are kernel addresses and race counters, so they
     * go to {@link UserService#SHELL_LOG} (readable over adb while the phone
     * is still locked) instead of the notification.
     */
    private static String shellStageFailure(String output) {
        if (output.contains("no successful plant")
                || output.contains("exhausted retries")) {
            return "the exploit could not plant in any of its attempts;"
                    + " reboot to retry (details: " + UserService.SHELL_LOG + ")";
        }
        if (output.contains("bad base") || output.contains("victim not captured")) {
            return "the exploit could not locate the timer slab;"
                    + " reboot to retry (details: " + UserService.SHELL_LOG + ")";
        }
        return tail(output) + " (details: " + UserService.SHELL_LOG + ")";
    }

    // ------------------------------------------------------------- heartbeat

    /**
     * Keeps the supervisor heartbeat fresh while the worker is alive. A boot
     * whose app was killed mid-run leaves a stale heartbeat behind, which is
     * how {@link AutoRoot#runInterrupted} tells a dead run from a busy one.
     *
     * The same thread re-arms the watchdog job. Scheduling with one job id
     * replaces the pending job, so a live run keeps it in the future and it
     * only fires after the heartbeats stop. At BFU jobs may be deferred until
     * the unlock (where BOOT_COMPLETED already re-enters), so this covers the
     * window after the boot broadcast: a kill there has nothing else left to
     * bring the supervisor back.
     */
    private void startHeartbeat() {
        beating = true;
        Thread thread = new Thread(() -> {
            long armed = 0;
            while (beating) {
                AutoRoot.heartbeat(this);
                long now = System.currentTimeMillis();
                if (now - armed > 60_000) {
                    RestartJobService.scheduleWatchdog(this);
                    armed = now;
                }
                try {
                    Thread.sleep(10_000);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }, "auto-root-heartbeat");
        thread.setDaemon(true);
        thread.start();
        heartbeatThread = thread;
    }

    private void stopHeartbeat() {
        beating = false;
        Thread thread = heartbeatThread;
        heartbeatThread = null;
        if (thread != null) {
            thread.interrupt();
        }
        RestartJobService.cancelWatchdog(this);
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
            /*
             * Covers the whole chain: the shell stage is bounded at 300 s and
             * the KernelSU stage at 15 min across replants.
             */
            wakeLock.acquire(30 * 60 * 1000L);
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
