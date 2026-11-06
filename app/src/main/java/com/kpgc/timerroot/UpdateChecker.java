package com.kpgc.timerroot;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Checks GitHub for a newer TimerRoot build.
 *
 * The release metadata carries no version: the tag is a codename and the body
 * is free text. The APK asset is the only source of truth, so a check reads it
 * with {@link PackageManager#getPackageArchiveInfo}. The download is skipped
 * when that exact asset (matched by its {@code updated_at}) was already
 * inspected, which keeps repeat checks to one small API request.
 */
final class UpdateChecker {

    static final String REPO = "MVN123123123123123/TimerRoot";
    static final String RELEASES_PAGE =
            "https://github.com/" + REPO + "/releases/latest";

    private static final String API_LATEST =
            "https://api.github.com/repos/" + REPO + "/releases/latest";
    private static final String APK_ASSET = "TimerRoot.apk";
    /** The APK is about 1 MB today; refuse anything wildly larger. */
    private static final long MAX_APK_BYTES = 32L * 1024 * 1024;

    private static final String PREFS = "updates";
    private static final String KEY_AUTO = "auto";
    private static final String KEY_LAST_CHECK = "last_check";
    private static final String KEY_ASSET_STAMP = "asset_stamp";
    private static final String KEY_ASSET_VERSION = "asset_version";
    private static final String KEY_DISMISSED = "dismissed_version";
    /** Cached outcome so Home can show the banner before a check runs. */
    private static final String KEY_LATEST_CODE = "latest_code";
    private static final String KEY_LATEST_NAME = "latest_name";
    /** Last check's one-line outcome, shown in Settings. */
    private static final String KEY_LAST_MESSAGE = "last_message";

    /** Do not hit the network more than once a day on automatic checks. */
    static final long AUTO_INTERVAL_MS = 24L * 60 * 60 * 1000;

    static final class Result {
        final boolean available;
        /** Version of the published build; null when unknown. */
        final String remoteVersion;
        final int remoteCode;
        final String releaseUrl;
        /** One line describing the outcome, for the log and Settings. */
        final String message;

        Result(boolean available, String remoteVersion, int remoteCode,
               String releaseUrl, String message) {
            this.available = available;
            this.remoteVersion = remoteVersion;
            this.remoteCode = remoteCode;
            this.releaseUrl = releaseUrl;
            this.message = message;
        }
    }

    private UpdateChecker() {
    }

    static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    static boolean isAutoEnabled(Context context) {
        return prefs(context).getBoolean(KEY_AUTO, true);
    }

    static void setAutoEnabled(Context context, boolean enabled) {
        prefs(context).edit().putBoolean(KEY_AUTO, enabled).apply();
    }

    static long lastCheck(Context context) {
        return prefs(context).getLong(KEY_LAST_CHECK, 0);
    }

    /** True when an automatic check is due. */
    static boolean isCheckDue(Context context) {
        return System.currentTimeMillis() - lastCheck(context) >= AUTO_INTERVAL_MS;
    }

    /** Hides the Home banner for one specific version. */
    static boolean isDismissed(Context context, int versionCode) {
        return prefs(context).getInt(KEY_DISMISSED, -1) == versionCode;
    }

    static void dismiss(Context context, int versionCode) {
        prefs(context).edit().putInt(KEY_DISMISSED, versionCode).apply();
    }

    /** Version code from the last successful check, or 0 when unknown. */
    static int cachedLatestCode(Context context) {
        return prefs(context).getInt(KEY_LATEST_CODE, 0);
    }

    static String cachedLatestName(Context context) {
        return prefs(context).getString(KEY_LATEST_NAME, null);
    }

    static String lastMessage(Context context) {
        return prefs(context).getString(KEY_LAST_MESSAGE, null);
    }

    /**
     * True when the cached check found a build newer than this one and the
     * user has not dismissed that exact version.
     */
    static boolean hasCachedUpdate(Context context) {
        int latest = cachedLatestCode(context);
        return latest > installedVersionCode(context)
                && !isDismissed(context, latest);
    }

    static int installedVersionCode(Context context) {
        try {
            return (int) context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0)
                    .getLongVersionCode();
        } catch (Throwable t) {
            return 0;
        }
    }

    /**
     * Runs the check. Blocking, so call it off the main thread.
     *
     * The APK asset is only fetched when the cached version does not match the
     * asset's {@code updated_at}, so repeated checks against an unchanged
     * release cost one small API request.
     */
    static Result check(Context context) {
        int installed = installedVersionCode(context);
        // Record the attempt up front: a failed check must not make every
        // launch retry, and the auto-check gate reads this value.
        prefs(context).edit()
                .putLong(KEY_LAST_CHECK, System.currentTimeMillis()).apply();
        HttpURLConnection connection = null;
        try {
            connection = open(API_LATEST);
            connection.setRequestProperty("Accept", "application/vnd.github+json");
            int code = connection.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                if (code == HttpURLConnection.HTTP_NOT_FOUND) {
                    return result(context, false, null, 0, RELEASES_PAGE,
                            "no releases published yet", installed);
                }
                return result(context, false, null, 0, RELEASES_PAGE,
                        "GitHub returned HTTP " + code, installed);
            }
            String body = readText(connection.getInputStream(), 256 * 1024);
            JSONObject release = new JSONObject(body);
            String releaseUrl = release.optString("html_url", RELEASES_PAGE);

            JSONObject asset = null;
            org.json.JSONArray assets = release.optJSONArray("assets");
            if (assets != null) {
                for (int i = 0; i < assets.length(); i++) {
                    JSONObject candidate = assets.optJSONObject(i);
                    if (candidate != null
                            && APK_ASSET.equals(candidate.optString("name"))) {
                        asset = candidate;
                        break;
                    }
                }
            }
            if (asset == null) {
                return result(context, false, null, 0, releaseUrl,
                        "the latest release has no " + APK_ASSET, installed);
            }

            String stamp = asset.optString("updated_at", "");
            String downloadUrl = asset.optString("browser_download_url", "");
            long size = asset.optLong("size", 0);
            if (size > MAX_APK_BYTES) {
                return result(context, false, null, 0, releaseUrl,
                        "release APK is unexpectedly large", installed);
            }

            // Reuse the version from a previous check of the same asset.
            SharedPreferences prefs = prefs(context);
            int remote = -1;
            String remoteName = null;
            if (!stamp.isEmpty() && stamp.equals(prefs.getString(KEY_ASSET_STAMP, ""))) {
                remote = prefs.getInt(KEY_ASSET_VERSION, -1);
            }
            if (remote < 0) {
                if (downloadUrl.isEmpty()) {
                    return result(context, false, null, 0, releaseUrl,
                            "release APK has no download URL", installed);
                }
                File apk = new File(context.getCacheDir(), "update-check.apk");
                try {
                    download(downloadUrl, apk);
                    PackageInfo info = context.getPackageManager()
                            .getPackageArchiveInfo(apk.getAbsolutePath(), 0);
                    if (info == null) {
                        return result(context, false, null, 0, releaseUrl,
                                "published APK could not be read", installed);
                    }
                    if (!context.getPackageName().equals(info.packageName)) {
                        return result(context, false, null, 0, releaseUrl,
                                "published APK belongs to " + info.packageName,
                                installed);
                    }
                    remote = (int) info.getLongVersionCode();
                    remoteName = info.versionName;
                    prefs.edit()
                            .putString(KEY_ASSET_STAMP, stamp)
                            .putInt(KEY_ASSET_VERSION, remote)
                            .apply();
                } finally {
                    //noinspection ResultOfMethodCallIgnored
                    apk.delete();
                }
            }

            prefs.edit()
                    .putInt(KEY_LATEST_CODE, remote)
                    .putString(KEY_LATEST_NAME, remoteName)
                    .apply();
            if (remote > installed) {
                return result(context, true, remoteName, remote, releaseUrl,
                        "update available", installed);
            }
            return result(context, false, remoteName, remote, releaseUrl,
                    "up to date", installed);
        } catch (Throwable t) {
            return result(context, false, null, 0, RELEASES_PAGE,
                    "check failed: " + t, installed);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /** Builds the result, its one-line description and records the message. */
    private static Result result(Context context, boolean available,
                                 String remoteVersion, int remoteCode,
                                 String releaseUrl, String message, int installed) {
        String text = message;
        if (remoteCode > 0) {
            text = message + " (" + versionLabel(remoteVersion, remoteCode)
                    + " vs " + installed + ")";
        }
        prefs(context).edit().putString(KEY_LAST_MESSAGE, text).apply();
        return new Result(available, remoteVersion, remoteCode, releaseUrl, text);
    }

    static String versionLabel(String versionName, int versionCode) {
        return versionName != null && !versionName.isEmpty()
                ? versionName : String.valueOf(versionCode);
    }

    // ---------------------------------------------------------------- network

    private static HttpURLConnection open(String url) throws IOException {
        HttpURLConnection connection =
                (HttpURLConnection) new URL(url).openConnection();
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(20000);
        connection.setInstanceFollowRedirects(true);
        connection.setRequestProperty("User-Agent", "TimerRoot-UpdateChecker");
        return connection;
    }

    private static String readText(InputStream in, int limit) throws IOException {
        try (InputStream source = in) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = source.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (out.size() > limit) {
                    throw new IOException("response too large");
                }
            }
            return out.toString("UTF-8");
        }
    }

    private static void download(String url, File dest) throws IOException {
        HttpURLConnection connection = null;
        File tmp = new File(dest.getPath() + ".part");
        try {
            connection = open(url);
            connection.setRequestProperty("Accept", "application/octet-stream");
            int code = connection.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTP " + code);
            }
            long declared = connection.getContentLengthLong();
            if (declared > MAX_APK_BYTES) {
                throw new IOException("APK is too large");
            }
            long total = 0;
            try (InputStream in = connection.getInputStream();
                 FileOutputStream out = new FileOutputStream(tmp)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) {
                    total += n;
                    if (total > MAX_APK_BYTES) {
                        throw new IOException("APK is too large");
                    }
                    out.write(buf, 0, n);
                }
            }
            if (!tmp.renameTo(dest)) {
                throw new IOException("cannot write " + dest);
            }
        } catch (IOException e) {
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
            throw e;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}
