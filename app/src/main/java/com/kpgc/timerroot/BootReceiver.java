package com.kpgc.timerroot;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

/**
 * Starts auto-root on a real boot only.
 *
 * Two stages, both attempt the exploit:
 *
 *   LOCKED_BOOT_COMPLETED -> start Shizuku early, then run at BFU
 *   BOOT_COMPLETED        -> retry only if the BFU attempt failed before the
 *                            exploit ran (the per-boot guard prevents a
 *                            second exploit run)
 *
 * A third case is a userspace ("soft") restart, which re-sends these same
 * broadcasts without rebooting the kernel: the exploit must not run again, so
 * that path only resumes Shizuku and republishes the recorded result.
 *
 * The Shizuku provider is directBootAware, so the server can hand over its
 * binder while the credential-encrypted user is still locked.
 */
public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent == null ? null : intent.getAction();
        boolean boot = Intent.ACTION_BOOT_COMPLETED.equals(action);
        boolean locked = Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(action);
        if (!boot && !locked) {
            return;
        }
        if (!AutoRoot.isEnabled(context)) {
            return;
        }
        AutoRoot.log(context, "received " + action);
        /*
         * A userspace restart re-sends these broadcasts while the kernel (and
         * KernelSU) never went away. The exploit must not run again - it is
         * one-shot per boot - so hand off to the resume path instead, which
         * starts Shizuku and republishes the recorded result.
         *
         * Either broadcast may arrive first depending on whether the restart
         * left the device locked, so claim the resume instead of picking one.
         */
        if (AutoRoot.softRestartDoneThisBoot(context)) {
            if (!AutoRoot.claimResumeAfterRestart(context)) {
                AutoRoot.log(context, action + ": resume already ran this boot");
                return;
            }
            AutoRoot.log(context, action + ": resuming after a userspace restart");
            start(context, AutoRootService.ACTION_AFTER_RESTART);
            return;
        }
        /*
         * The exploit is one-shot per boot. If the locked-boot stage already
         * claimed this boot (or is still running it), do not start the
         * service again just to have it skip: that would replace the live
         * "Root shell ready" notification with "preparing..." for a moment.
         * A pending binder restart is the one case that must be allowed
         * through.
         */
        if (AutoRoot.isBootClaimed(context) && !AutoRoot.hasPendingRestart(context)) {
            AutoRoot.log(context, action + ": already handled this boot, ignoring");
            return;
        }
        start(context, locked ? AutoRootService.ACTION_PRESTART
                : AutoRootService.ACTION_START);
    }

    private static void start(Context context, String action) {
        Intent service = new Intent(context, AutoRootService.class)
                .setAction(action);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(service);
            } else {
                context.startService(service);
            }
        } catch (Throwable t) {
            AutoRoot.log(context, "cannot start auto-root service: " + t);
        }
    }
}
