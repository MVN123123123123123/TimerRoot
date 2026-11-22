package com.kpgc.timerroot;

import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Beta-channel binary refresh.
 *
 * The shell user service deliberately keeps any installed timer that speaks
 * the current protocol, because the installed copy may be a newer download.
 * That also means a beta APK can keep running a stale protocol-3 binary that
 * predates an exploit fix: the protocol marker alone cannot tell the two
 * apart. On the beta channel we therefore re-download the rolling beta asset
 * on every run and force-install it, so the binary always matches the source
 * the beta app was built from.
 *
 * Best effort by design: a failed download or install leaves the already
 * installed binary alone and is logged, never fatal to the app or auto-root.
 * Callers must run this off the UI thread.
 */
final class BetaBinaryRefresh {

    private static final String TAG = "TimerRoot";
    private static final String PROTOCOL_MARKER = "TIMER_PROTOCOL=3";
    private static final String TARGET_MARKER = "target=lynx";
    private static final long MIN_BYTES = 100_000L;

    static final class Result {
        final boolean ok;
        final String message;

        Result(boolean ok, String message) {
            this.ok = ok;
            this.message = message;
        }
    }

    private BetaBinaryRefresh() {
    }

    /** Downloads, validates and force-installs the beta timer. */
    static Result refresh(Context context, IUserService service, String url) {
        File file = new File(context.getCacheDir(), "timer-beta-refresh");
        try {
            TimerFetcher.Result got = TimerFetcher.download(url, file);
            if (got.bytes < MIN_BYTES) {
                throw new IOException("download is too small: " + got.bytes + " bytes");
            }
            /* Check before replacing anything: a bad build must not clobber a
             * working binary. installFd() does not validate its payload. */
            String image = new String(Files.readAllBytes(file.toPath()),
                    StandardCharsets.ISO_8859_1);
            if (!image.contains(PROTOCOL_MARKER)) {
                throw new IOException("download lacks " + PROTOCOL_MARKER);
            }
            if (!image.contains(TARGET_MARKER)) {
                throw new IOException("download lacks " + TARGET_MARKER);
            }

            /* Publish this APK's profiles first; install() keeps the binary
             * that is already staged, so the force-install below still wins. */
            String confs = service.install(context.getPackageCodePath());
            String installed;
            try (ParcelFileDescriptor fd = ParcelFileDescriptor.open(
                    file, ParcelFileDescriptor.MODE_READ_ONLY)) {
                installed = service.installFd(fd);
            }
            if (installed == null || !installed.startsWith("installed")) {
                throw new IOException("install failed: " + installed);
            }
            String target = service.run("target");
            if (target == null || !target.contains(TARGET_MARKER)) {
                throw new IOException("installed binary rejected for this kernel: " + target);
            }

            String message = "beta binary refresh: installed " + got.bytes
                    + " bytes sha256 " + got.sha256 + " (" + confs.trim() + ")";
            Log.i(TAG, message);
            record(service, message);
            return new Result(true, message);
        } catch (Throwable t) {
            String message = "beta binary refresh failed (kept the installed"
                    + " timer): " + t;
            Log.w(TAG, message);
            record(service, message);
            return new Result(false, message);
        } finally {
            //noinspection ResultOfMethodCallIgnored
            file.delete();
        }
    }

    /** Debug-log evidence is best effort too; the app log always has it. */
    static void record(IUserService service, String message) {
        try {
            service.appendDebugLog(message);
        } catch (Throwable ignored) {
        }
    }
}
