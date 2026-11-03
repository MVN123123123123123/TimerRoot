package com.kpgc.timerroot;

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

    private static final String BIN = "/data/local/tmp/timer";
    private static final String LOG = "/data/local/tmp/timer.log";
    private static final int MAX_OUTPUT = 20000;

    private Process rootProcess;
    private BufferedWriter rootInput;
    private final BlockingQueue<String> rootLines = new LinkedBlockingQueue<>();

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
            try (ZipFile zf = new ZipFile(apk)) {
                ZipEntry entry = zf.getEntry("assets/timer");
                if (entry == null) {
                    return "assets/timer not found in " + apk;
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
                move.waitFor();
            }
            return "installed " + new File(BIN).length() + " bytes (uid="
                    + android.system.Os.getuid() + ")";
        } catch (Throwable t) {
            return "install failed: " + t;
        }
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
            return "installed " + new File(BIN).length() + " bytes (uid="
                    + android.system.Os.getuid() + ")";
        } catch (Throwable t) {
            return "install failed: " + t;
        }
    }

    @Override
    public String run(String args) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "/system/bin/sh", "-c", BIN + " " + args + " 2>&1");
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
        try {
            String cmd = "cd /data/local/tmp && setsid " + BIN + " " + args
                    + " >" + LOG + " 2>&1 </dev/null &";
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
        try {
            ProcessBuilder pb = new ProcessBuilder(BIN, "shell");
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
