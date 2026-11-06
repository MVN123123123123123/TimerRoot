package com.kpgc.timerroot;

import android.os.Build;
import android.system.Os;
import android.system.OsConstants;
import android.text.TextUtils;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Runs inside the process that Shizuku starts as the shell user (uid 2000,
 * u:r:shell:s0), which is what the exploit needs for tracefs.
 */
public class UserService extends IUserService.Stub {

    private static final String TAG = "TimerRootService";

    private static final String BIN = "/data/local/tmp/timer";
    private static final String LOG = "/data/local/tmp/timer.log";
    private static final String SOFT_RESTART_LOG = "/data/local/tmp/soft_restart.log";
    private static final String CONF_DIR = "/data/local/tmp/timer-conf";
    /** Profiles for "dirty" kernel builds need an extra identity check. */
    private static final String DIRTY_CONF_SUBDIR = "dirty";
    /**
     * App &lt;-&gt; timer interface version. Must match APP_PROTOCOL in
     * p7a/timer_p7a.c. The binary refuses to run when this is missing, which
     * is how an old APK that downloads the new timer finds out it has to
     * update.
     */
    private static final int APP_PROTOCOL = 2;
    private static final int MAX_OUTPUT = 20000;

    private Process rootProcess;
    private BufferedWriter rootInput;
    private final BlockingQueue<String> rootLines = new LinkedBlockingQueue<>();
    /** Cached protocol probe result: -1 unknown, 0 legacy binary, 2 current. */
    private volatile int binaryProtocol = -1;

    public UserService() {
    }

    public UserService(android.content.Context context) {
    }

    @Override
    public void destroy() {
        closeRootInternal();
        System.exit(0);
    }

    @Override
    public void exit() {
        destroy();
    }

    @Override
    public String install(String apk) {
        try {
            int confCount;
            try (ZipFile zf = new ZipFile(apk)) {
                ZipEntry entry = zf.getEntry("assets/timer");
                if (entry == null) {
                    // Still publish the confs: the download path installs
                    // the binary separately through installFd().
                    confCount = extractConfs(zf);
                    return "assets/timer not found in " + apk
                            + " (installed " + confCount + " confs)";
                }
                String tmp = BIN + ".new";
                try (InputStream in = zf.getInputStream(entry);
                     FileOutputStream out = new FileOutputStream(tmp)) {
                    byte[] buf = new byte[65536];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        out.write(buf, 0, n);
                    }
                }
                // The old binary may still be mapped by a parked process; rename
                // over it instead of writing in place (ETXTBSY).
                Process move = Runtime.getRuntime().exec(new String[]{"/system/bin/sh",
                        "-c", "chmod 755 " + tmp + " && mv -f " + tmp + " " + BIN
                            + " && sync"});
                int rc = move.waitFor();
                if (rc != 0) {
                    return "install failed: mv rc=" + rc;
                }
                // A replaced binary must be re-identified before the next run.
                binaryProtocol = -1;

                // Per-kernel profiles. Wipe the directory first: a stale
                // flat conf would otherwise keep matching by release alone
                // and bypass the dirty/ identity checks.
                confCount = extractConfs(zf);
            }
            return "installed " + new File(BIN).length() + " bytes, " + confCount
                    + " confs (uid=" + Os.getuid() + ")";
        } catch (Throwable t) {
            return "install failed: " + t;
        }
    }

    /** Extracts APK assets/conf/**.conf into CONF_DIR. */
    private static int extractConfs(ZipFile zf) throws IOException {
        File confDir = new File(CONF_DIR);
        deleteRecursively(confDir);
        //noinspection ResultOfMethodCallIgnored
        confDir.mkdirs();

        int count = 0;
        java.util.Enumeration<? extends ZipEntry> entries = zf.entries();
        while (entries.hasMoreElements()) {
            ZipEntry e = entries.nextElement();
            if (e.isDirectory() || !e.getName().startsWith("assets/conf/")) {
                continue;
            }
            String name = e.getName().substring("assets/conf/".length());
            if (!name.endsWith(".conf") || name.contains("..")) {
                continue;
            }
            File dst = new File(confDir, name);
            File parent = dst.getParentFile();
            if (parent != null) {
                //noinspection ResultOfMethodCallIgnored
                parent.mkdirs();
            }
            try (InputStream in = zf.getInputStream(e);
                 FileOutputStream out = new FileOutputStream(dst)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
            }
            count++;
        }
        return count;
    }

    private static void deleteRecursively(File f) {
        File[] kids = f.listFiles();
        if (kids != null) {
            for (File k : kids) {
                deleteRecursively(k);
            }
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }

    /**
     * Installs a binary downloaded by the app. The fd stays readable even
     * though the app's cache directory is private to the untrusted_app uid.
     */
    @Override
    public String installFd(android.os.ParcelFileDescriptor fd) {
        if (fd == null) {
            return "install failed: no data";
        }
        String tmp = BIN + ".new";
        try {
            try (InputStream in = new android.os.ParcelFileDescriptor.AutoCloseInputStream(fd);
                 FileOutputStream out = new FileOutputStream(tmp)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
            }
            Process move = Runtime.getRuntime().exec(new String[]{"/system/bin/sh",
                    "-c", "chmod 755 " + tmp + " && mv -f " + tmp + " " + BIN
                            + " && sync"});
            int rc = move.waitFor();
            if (rc != 0) {
                return "install failed: mv rc=" + rc;
            }
            // A freshly installed binary must be re-probed before use.
            binaryProtocol = -1;
            return "installed " + new File(BIN).length() + " bytes (uid="
                    + android.system.Os.getuid() + ")";
        } catch (Throwable t) {
            return "install failed: " + t;
        }
    }

    private static String kernelRelease() {
        try {
            return Os.uname().release;
        } catch (Throwable t) {
            return "unknown";
        }
    }

    /**
     * True when the installed timer speaks this app's protocol.
     *
     * The app and the binary are installed independently, so the reverse of
     * the old-app case is possible too: an updated APK can meet a timer that
     * is still the pre-conf binary (its /data/local/tmp/timer survives an app
     * update). That binary has no argument parser, so handing it
     * "--conf &lt;path&gt;" would be read as an unknown mode and run a legacy
     * plant with the wrong kernel constants.
     *
     * The check reads the file instead of running it: the conf-driven binary
     * embeds the literal marker "TIMER_PROTOCOL=&lt;n&gt;" in its read-only data,
     * so a byte scan is side-effect free. Refusing on a missing marker is the
     * safe direction: the user is told to reinstall.
     */
    private boolean binarySpeaksProtocol() {
        if (binaryProtocol >= 0) {
            return binaryProtocol == APP_PROTOCOL;
        }
        binaryProtocol = 0;
        byte[] want = ("TIMER_PROTOCOL=" + APP_PROTOCOL).getBytes(StandardCharsets.US_ASCII);
        try (InputStream in = new FileInputStream(BIN)) {
            byte[] buf = new byte[1 << 16];
            int keep = want.length - 1;
            int carry = 0;
            int n;
            while ((n = in.read(buf, carry, buf.length - carry)) > 0) {
                int len = carry + n;
                if (indexOf(buf, len, want) >= 0) {
                    binaryProtocol = APP_PROTOCOL;
                    break;
                }
                carry = Math.min(keep, len);
                System.arraycopy(buf, len - carry, buf, 0, carry);
            }
        } catch (Throwable t) {
            Log.w(TAG, "protocol probe failed: " + t);
        }
        return binaryProtocol == APP_PROTOCOL;
    }

    /** Plain substring search over the first {@code len} bytes of a buffer. */
    private static int indexOf(byte[] hay, int len, byte[] needle) {
        int last = len - needle.length;
        outer:
        for (int i = 0; i <= last; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** The message shown when the installed binary predates the conf rewrite. */
    private static String oldBinaryMessage() {
        return "BREAKING CHANGE: the installed timer is too old for this app.\n"
                + "It does not understand --conf, so it cannot be given a kernel\n"
                + "profile. Press \"Download exploit\" (or Prepare) to reinstall\n"
                + "the current timer, then try again.";
    }

    /**
     * Returns "--conf &lt;path&gt;" for the profile that applies to this
     * device, or null when none matches.
     *
     * Two tiers:
     *  - confs directly under CONF_DIR match on {@code release == uname -r}
     *    (and, when present, {@code page_size}) alone. Stock GKI release
     *    strings are unique enough.
     *  - confs under CONF_DIR/dirty/ additionally check the device identity
     *    ({@code device_model}, {@code android_release}, optional
     *    {@code sdk_int}). A dirty build's release string is not unique to
     *    one vendor build, so the extra check keeps another device's
     *    constants from being applied.
     *
     * This selection logic is ported from rikumi/TimerRoot.
     */
    private String confArg() {
        String release;
        long pageSize;
        try {
            release = Os.uname().release;
            pageSize = Os.sysconf(OsConstants._SC_PAGESIZE);
        } catch (Throwable t) {
            Log.w(TAG, "cannot read kernel identity: " + t);
            return null;
        }

        File dir = new File(CONF_DIR);
        for (File f : listConfFiles(dir)) {
            if (!confMatches(f, release, pageSize)) {
                continue;
            }
            Log.i(TAG, "using conf " + f);
            return "--conf " + f.getAbsolutePath()
                    + " --protocol " + APP_PROTOCOL;
        }

        File dirtyDir = new File(dir, DIRTY_CONF_SUBDIR);
        for (File f : listConfFiles(dirtyDir)) {
            if (!confMatches(f, release, pageSize)) {
                continue;
            }
            if (!deviceIdentityMatches(f)) {
                Log.w(TAG, "skipping dirty conf " + f + ": device identity mismatch");
                continue;
            }
            Log.i(TAG, "using dirty conf " + f);
            return "--conf " + f.getAbsolutePath()
                    + " --protocol " + APP_PROTOCOL;
        }
        Log.w(TAG, "no conf matched uname -r = " + release
                + ", page size = " + pageSize);
        return null;
    }

    /** Regular .conf files directly inside {@code dir} (no recursion). */
    private static File[] listConfFiles(File dir) {
        File[] files = dir.listFiles((d, name) -> name.endsWith(".conf"));
        if (files == null) {
            return new File[0];
        }
        ArrayList<File> out = new ArrayList<>();
        for (File f : files) {
            if (f.isFile()) {
                out.add(f);
            }
        }
        return out.toArray(new File[0]);
    }

    private static boolean confMatches(File conf, String release, long pageSize) {
        Map<String, String> fields = readConfFields(conf);
        if (!releaseMatches(fields.get("release"), release)) {
            return false;
        }
        String wantPage = fields.get("page_size");
        if (TextUtils.isEmpty(wantPage)) {
            return true;
        }
        try {
            return Long.decode(wantPage) == pageSize;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /** A kernel release may or may not carry the "-4k" userspace suffix. */
    private static boolean releaseMatches(String configured, String running) {
        if (TextUtils.isEmpty(configured) || TextUtils.isEmpty(running)) {
            return false;
        }
        if (configured.equals(running)) {
            return true;
        }
        String a = configured.endsWith("-4k")
                ? configured.substring(0, configured.length() - 3) : configured;
        String b = running.endsWith("-4k")
                ? running.substring(0, running.length() - 3) : running;
        return a.equals(b);
    }

    /**
     * Identity gate for dirty confs. {@code device_model} and
     * {@code android_release} are required; {@code sdk_int} is compared when
     * present. A conf that omits a required field is rejected rather than
     * trusted, so an incomplete profile can never be selected.
     */
    private static boolean deviceIdentityMatches(File conf) {
        Map<String, String> fields = readConfFields(conf);
        String wantModel = fields.get("device_model");
        String wantRelease = fields.get("android_release");
        String wantSdk = fields.get("sdk_int");
        if (TextUtils.isEmpty(wantModel) || TextUtils.isEmpty(wantRelease)) {
            return false;
        }
        if (!wantModel.equals(Build.MODEL)) {
            return false;
        }
        if (!wantRelease.equals(Build.VERSION.RELEASE)) {
            return false;
        }
        return TextUtils.isEmpty(wantSdk)
                || wantSdk.equals(String.valueOf(Build.VERSION.SDK_INT));
    }

    /**
     * Minimal conf reader: {@code key = value} lines with {@code #} and
     * {@code //} comments stripped and surrounding quotes removed.
     */
    private static Map<String, String> readConfFields(File f) {
        Map<String, String> out = new HashMap<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(f)))) {
            String line;
            while ((line = r.readLine()) != null) {
                int hash = line.indexOf('#');
                if (hash >= 0) {
                    line = line.substring(0, hash);
                }
                int dsl = line.indexOf("//");
                if (dsl >= 0) {
                    line = line.substring(0, dsl);
                }
                int eq = line.indexOf('=');
                if (eq < 0) {
                    continue;
                }
                String key = line.substring(0, eq).trim();
                String val = line.substring(eq + 1).trim();
                if (val.length() >= 2 && val.startsWith("\"") && val.endsWith("\"")) {
                    val = val.substring(1, val.length() - 1);
                }
                if (!key.isEmpty() && !val.isEmpty()) {
                    out.put(key, val);
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Result of resolving the run arguments: exactly one field is set.
     */
    private static final class ConfCheck {
        final String args;
        final String error;

        ConfCheck(String args, String error) {
            this.args = args;
            this.error = error;
        }
    }

    /**
     * Returns the {@code --conf ... --protocol ...} argument for this device,
     * or the reason it is unavailable. The binary is verified first: an
     * installed binary from before the conf rewrite must never be handed
     * {@code --conf}.
     */
    private ConfCheck resolveConfArg() {
        if (!new File(BIN).isFile()) {
            return new ConfCheck(null,
                    "timer is not installed - press \"Download exploit\""
                            + " (or Prepare) first");
        }
        if (!binarySpeaksProtocol()) {
            return new ConfCheck(null, oldBinaryMessage());
        }
        String conf = confArg();
        if (conf == null) {
            return new ConfCheck(null, "no kernel conf matched uname -r = "
                    + kernelRelease() + " (install the app or press Prepare again)");
        }
        return new ConfCheck(conf, null);
    }

    @Override
    public String run(String args) {
        ConfCheck check = resolveConfArg();
        if (check.error != null) {
            return check.error;
        }
        String conf = check.args;
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "/system/bin/sh", "-c", BIN + " " + conf + " " + args + " 2>&1");
            pb.directory(new File("/data/local/tmp"));
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String text = readAll(p.getInputStream());
            if (!p.waitFor(420, TimeUnit.SECONDS)) {
                return text + "\n[timeout] still running after 420s - do not kill it,"
                        + " reboot to clean up";
            }
            return text;
        } catch (Throwable t) {
            return "run failed: " + t;
        }
    }

    @Override
    public String runDetached(String args) {
        ConfCheck check = resolveConfArg();
        if (check.error != null) {
            return "start failed: " + check.error;
        }
        String conf = check.args;
        try {
            String cmd = "cd /data/local/tmp && setsid " + BIN + " " + conf
                    + " " + args + " >" + LOG + " 2>&1 </dev/null &";
            Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", cmd});
            Thread.sleep(2000);
            return readLog();
        } catch (Throwable t) {
            return "start failed: " + t;
        }
    }

    @Override
    public String readLog() {
        try (FileInputStream in = new FileInputStream(LOG)) {
            return readAll(in);
        } catch (Throwable t) {
            return "";
        }
    }

    @Override
    public String openRoot() {
        if (rootProcess != null && rootProcess.isAlive()) {
            return "root shell already open";
        }
        ConfCheck check = resolveConfArg();
        if (check.error != null) {
            return "root shell failed: " + check.error;
        }
        String conf = check.args;
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "/system/bin/sh", "-c", BIN + " " + conf + " shell");
            pb.directory(new File("/data/local/tmp"));
            pb.redirectErrorStream(true);
            rootProcess = pb.start();
            rootInput = new BufferedWriter(
                    new OutputStreamWriter(rootProcess.getOutputStream()));
            final BufferedReader reader = new BufferedReader(
                    new InputStreamReader(rootProcess.getInputStream()));
            rootLines.clear();
            Thread pump = new Thread(() -> {
                try {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        rootLines.offer(line);
                    }
                } catch (IOException ignored) {
                }
            });
            pump.setDaemon(true);
            pump.start();
            /*
             * The trigger runs three plant attempts and each one has to wait
             * for its child to exec and be killed, so a success can take
             * minutes.  Do not declare failure early: keep reading until the
             * exploit prints its success marker or exits.
             */
            StringBuilder out = new StringBuilder();
            long deadline = System.currentTimeMillis() + 300000;
            boolean ok = false;
            while (System.currentTimeMillis() < deadline) {
                String line = rootLines.poll(200, TimeUnit.MILLISECONDS);
                if (line == null) {
                    if (!rootProcess.isAlive()) {
                        // Drain whatever is left, then stop.
                        String rest;
                        while ((rest = rootLines.poll()) != null) {
                            out.append(rest).append('\n');
                        }
                        break;
                    }
                    continue;
                }
                out.append(line).append('\n');
                if (line.contains("ROOT_SHELL_OK")
                        || (line.contains("uid=0(root)") && line.contains("context="))) {
                    ok = true;
                    break;
                }
                if (line.contains("parking without reap")
                        || line.contains("no successful plant")
                        || line.contains("cred writes landed, waking child")) {
                    // Give the child a moment to print its id line.
                    continue;
                }
            }
            return (ok ? "root shell ready\n" : "root shell failed\n") + out.toString().trim();
        } catch (Throwable t) {
            return "openRoot failed: " + t;
        }
    }

    @Override
    public String execRoot(String cmd) {
        if (rootProcess == null || !rootProcess.isAlive()) {
            return "root shell not open";
        }
        try {
            rootInput.write(cmd + " 2>&1\necho __END__\n");
            rootInput.flush();
            StringBuilder sb = new StringBuilder();
            long deadline = System.currentTimeMillis() + 30000;
            while (System.currentTimeMillis() < deadline) {
                String line = rootLines.poll(200, TimeUnit.MILLISECONDS);
                if (line == null) {
                    continue;
                }
                if (line.equals("__END__")) {
                    break;
                }
                sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (Throwable t) {
            return "execRoot failed: " + t;
        }
    }

    @Override
    public String closeRoot() {
        closeRootInternal();
        return "root shell closed";
    }

    /** SELinux / Seccomp / ksud, as shown on the home card. */
    @Override
    public String info() {
        String selinux = execOut("getenforce");
        String seccomp = execOut("grep -m1 Seccomp /proc/self/status | awk '{print $2}'");
        String ksud = "not loaded";
        Matcher m = Pattern.compile("version=(ksud[^\\n]*)").matcher(readLog());
        if (m.find()) {
            ksud = m.group(1).trim();
        } else if (selinux.contains("Permissive")) {
            ksud = "missing";
        }
        String ksu = execOut("/system/bin/su -c id").contains("u:r:ksu:s0")
                ? "active" : "not loaded";
        return "selinux=" + selinux + "\nseccomp=" + seccomp + "\nksud=" + ksud
                + "\nksu=" + ksu + "\n";
    }

    /**
     * KernelSU's module init forces SELinux back to Enforcing about 0.4s
     * after late-load, which overwrites the exploit's write. Re-apply from
     * here (uid 2000 shell) through KSU's own su, then confirm. su is the
     * reliable path: the enforcing flag stays 0 once set from u:r:ksu:s0.
     * The first su() calls can block while KSU finishes its allowlist and
     * manager setup, so every attempt is bounded and retried.
     */
    @Override
    public String keepPermissive() {
        String state = "unknown";
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(
                "/data/local/tmp/ksu_enforce.log", false)) {
            out.write(("start " + System.currentTimeMillis() + "\n").getBytes("UTF-8"));
        } catch (Throwable ignored) {
        }
        for (int i = 0; i < 12; i++) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ignored) {
                break;
            }
            execCodeTimeout("/system/bin/su -c 'setenforce 0'", 8000);
            state = execOutTimeout("getenforce", 5000).trim();
            diag("attempt=" + (i + 1) + " enforce=" + state);
            if (state.equals("Permissive")) {
                return "selinux=" + state + " (after " + (i + 1) + "s)";
            }
        }
        return "selinux=" + state;
    }

    /**
     * True when the loaded module hands out a shell in u:r:ksu:s0. Some
     * loaders (SukiSU Ultra) tear down the stage shell right after taking
     * over, so their stage never prints KSU_LOADED. Asking the kernel is
     * then the only reliable success signal.
     */
    @Override
    public boolean ksuActive() {
        for (int i = 0; i < 10; i++) {
            if (execOutTimeout("/system/bin/su -c id", 3000).contains("u:r:ksu:s0")) {
                return true;
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                break;
            }
        }
        return false;
    }

    private void diag(String line) {
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(
                "/data/local/tmp/ksu_enforce.log", true)) {
            out.write((line + "\n").getBytes("UTF-8"));
        } catch (Throwable ignored) {
        }
    }

    private void execCodeTimeout(String cmd, long ms) {
        try {
            Process p = new ProcessBuilder("/system/bin/sh", "-c", cmd)
                    .redirectErrorStream(true).start();
            if (!p.waitFor(ms, TimeUnit.MILLISECONDS)) {
                p.destroy();
            }
        } catch (Throwable ignored) {
        }
    }

    private String execOutTimeout(String cmd, long ms) {
        try {
            Process p = new ProcessBuilder("/system/bin/sh", "-c", cmd)
                    .redirectErrorStream(true).start();
            if (!p.waitFor(ms, TimeUnit.MILLISECONDS)) {
                p.destroy();
                return "timeout";
            }
            InputStream in = p.getInputStream();
            return readAll(in);
        } catch (Throwable t) {
            return "error";
        }
    }

    @Override
    public String rebootDevice() {
        int rc = execCode("/system/bin/svc power reboot");
        if (rc != 0) {
            rc = execCode("/system/bin/su -c reboot");
        }
        if (rc != 0) {
            rc = execCode("/system/bin/reboot");
        }
        return rc == 0 ? "rebooting" : "reboot failed (rc=" + rc + ")";
    }

    /**
     * Restarts Android's userspace without rebooting the kernel, the same way
     * the KernelSU manager's "soft reboot" does: reset sys.boot_completed,
     * stop init services, run post-fs-data / services / boot-completed, start
     * again. The point is that a late-loaded module only executes its scripts
     * and starts Zygisk during those stages, so this is what makes the root
     * that {@link #ksuActive()} reports actually usable (modules mounted,
     * Zygisk injected) with no real reboot.
     *
     * This process (and the whole app) is killed by the "stop" phase, so the
     * caller must expect the binder call to fail and must not depend on the
     * return value. Everything needed afterwards lives in device-protected
     * storage and in the kernel.
     *
     * Only KernelSU 3.x+ ships the subcommand, and it daemonizes before doing
     * anything, so support is probed with "--help" first: a failure after the
     * daemonize point could not be reported anyway.
     */
    @Override
    public String softRestart() {
        String ksud = findKsud();
        if (ksud == null) {
            return "soft restart unavailable: no ksud found (is KernelSU loaded?)";
        }
        if (execStatus("/system/bin/su -c '" + ksud
                + " soft-reboot --help' >/dev/null 2>&1", 15000) != 0) {
            return "soft restart unavailable: " + ksud
                    + " has no soft-reboot subcommand";
        }
        /*
         * Confirm the restart actually began before the caller is torn down.
         * Both a boot-completed flip and a change of system_server's pid mean
         * init ran the "stop" phase; at BFU sys.boot_completed is already 0, so
         * the pid is what makes this reliable there. A silent skip (mismatched
         * KernelSU uapi, for example) changes neither.
         */
        String before = probeBootState();
        try {
            /*
             * setsid + & so the restart survives this process being killed by
             * its own "stop" phase. su supplies the root the subcommand needs;
             * the shell-domain root shell is not enough here because ksud
             * switches mount namespaces.
             */
            String cmd = "cd / && setsid /system/bin/su -c '" + ksud
                    + " soft-reboot' >" + SOFT_RESTART_LOG
                    + " 2>&1 </dev/null &";
            Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", cmd});
        } catch (Throwable t) {
            return "soft restart failed: " + t;
        }
        for (int i = 0; i < 40; i++) {
            String now = probeBootState();
            if (!now.equals(before) && !now.startsWith("error")) {
                return "soft restart started";
            }
            try {
                Thread.sleep(250);
            } catch (InterruptedException ignored) {
                break;
            }
        }
        return "soft restart command sent (see " + SOFT_RESTART_LOG + ")";
    }

    /** One line that changes as soon as init's stop/start phase runs. */
    private String probeBootState() {
        return execOutTimeout("getprop sys.boot_completed; pidof system_server", 3000)
                .trim().replace('\n', '/');
    }

    /**
     * Locates a ksud binary through KSU's own su, which is the only shell that
     * can read /data/adb from the shell uid.
     */
    private String findKsud() {
        String out = execOutTimeout("/system/bin/su -c 'command -v ksud || "
                + "ls /data/adb/ksud /data/adb/ksu/bin/ksud 2>/dev/null | head -n1'",
                15000);
        for (String line : out.split("\n")) {
            String path = line.trim();
            if (path.startsWith("/") && !path.contains(" ")) {
                return path;
            }
        }
        return null;
    }

    /** Runs a command and returns its exit status, or -1 on any failure. */
    private int execStatus(String cmd, long ms) {
        try {
            Process p = new ProcessBuilder("/system/bin/sh", "-c", cmd)
                    .redirectErrorStream(true).start();
            if (!p.waitFor(ms, TimeUnit.MILLISECONDS)) {
                p.destroy();
                return -1;
            }
            return p.exitValue();
        } catch (Throwable t) {
            return -1;
        }
    }

    private int execCode(String cmd) {
        try {
            Process p = new ProcessBuilder("/system/bin/sh", "-c", cmd)
                    .redirectErrorStream(true).start();
            return p.waitFor();
        } catch (Throwable t) {
            return -1;
        }
    }

    private String execOut(String cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c", cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String text = readAll(p.getInputStream()).trim();
            p.waitFor();
            return text.isEmpty() ? "unknown" : text;
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private void closeRootInternal() {
        try {
            if (rootInput != null) {
                rootInput.write("exit\n");
                rootInput.flush();
            }
        } catch (IOException ignored) {
        }
        if (rootProcess != null) {
            rootProcess.destroy();
            rootProcess = null;
        }
        rootInput = null;
    }

    private static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        int total = 0;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
            total += n;
            if (total > MAX_OUTPUT) {
                break;
            }
        }
        return bos.toString("UTF-8");
    }
}
