package com.kpgc.timerroot;

import android.os.ParcelFileDescriptor;

interface IUserService {
    void destroy() = 16777114;
    void exit() = 1;
    String install(String apkPath) = 2;
    String run(String args) = 3;
    String runDetached(String args) = 4;
    String readLog() = 5;
    String openRoot() = 6;
    String execRoot(String cmd) = 7;
    String closeRoot() = 8;
    String info() = 9;
    String rebootDevice() = 10;
    String installFd(in ParcelFileDescriptor fd) = 11;
    String keepPermissive() = 12;
    boolean ksuActive() = 13;
    String softRestart() = 14;
    /**
     * Selects the Samsung endgame (DEFEX creds_hash clear + KDP-safe ksud)
     * for subsequent calls.  The app passes this explicitly because the
     * shell user service cannot read the app's device-protected preferences.
     */
    void setSamsungMode(boolean enabled) = 15;
    /**
     * Runs a command as full-capability uid 0 through KernelSU's su
     * (u:r:ksu:s0). Install channel uses this instead of the shell-domain
     * exploit shell because adb_keys needs CAP_DAC_OVERRIDE.
     */
    String execSu(String cmd) = 16;
    /**
     * Runs a read-only diagnostic command in the shell-user domain and
     * returns its output. Used by the device probe to read /proc and /sys
     * files an app process is denied (kernel boot parameters, cpuinfo,
     * tracing, slabinfo), so the latest timer debug log can carry a full
     * spec of the device the exploit is about to run on.
     */
    String probe(String cmd) = 17;
    /**
     * Probes the device and appends the capture to the latest timer debug
     * log. Called before the exploit runs (boot iteration or manual run);
     * does not start any exploit stage.
     */
    String captureDebugLog() = 18;
    /** Contents of the latest timer debug log on /data/local/tmp. */
    String readDebugLog() = 19;
    /**
     * The effective Samsung mode the service will run with, so the device
     * probe can record it alongside the rest of the spec.
     */
    boolean isSamsungMode() = 20;
    /**
     * Appends one line to the latest timer debug log without truncating it,
     * so the auto-root boot iteration can record its decisions next to the
     * device probe captured by {@link #captureDebugLog()}.
     */
    String appendDebugLog(String line) = 21;
}
