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
}
