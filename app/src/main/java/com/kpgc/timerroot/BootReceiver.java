package com.kpgc.timerroot;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

/**
 * Starts auto-root on a real boot only. Activity starts and force-stops never
 * send these broadcasts, so a soft restart cannot trip it.
 *
 * Two stages, because Shizuku's binder cannot be delivered while the user is
 * locked (its permission check reads the credential-encrypted user):
 *
 *   LOCKED_BOOT_COMPLETED -> start Shizuku now, so it is already up later
 *   BOOT_COMPLETED        -> bind it and run the exploit (delivered after
 *                            the first unlock on Android 17)
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
        Intent service = new Intent(context, AutoRootService.class)
                .setAction(locked
                        ? AutoRootService.ACTION_PRESTART
                        : AutoRootService.ACTION_START);
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
