# Auto-root research

Goal: after a real reboot (not a soft restart), get from "device booted" to
"TimerRoot has a root shell" with no user interaction.

Target stack as requested:

1. Shizuku starts automatically on boot.
2. Shizuku works without Wi-Fi if possible.
3. TimerRoot pairs with / binds to Shizuku automatically.
4. TimerRoot starts the exploit.

This document records what Android and Shizuku actually allow, and the three
architectures that work. It ends with the implementation plan I recommend for
this repository.

---

## 1. Verdict

| Situation | Zero-touch boot? |
| --- | --- |
| Device already rooted (KernelSU / APatch / Magisk) | **Yes.** Shizuku root mode already does this; TimerRoot only needs a boot receiver + retry. |
| Unrooted, Wi-Fi on + trusted network, Shizuku already paired and granted `WRITE_SECURE_SETTINGS` | **Yes, today, no code** (Shizuku's own boot receiver). |
| Unrooted, Wi-Fi off / never connected | **Not with stock Shizuku.** Its ADB boot path finds the port via mDNS, which needs a real network. Port is random per boot and is not readable by an app. |
| Unrooted, never bootstrapped at all | **Impossible.** No app can obtain `shell` without either root or an ADB key already in `/data/misc/adb/adb_keys`. This is the Android security boundary, not a missing feature. |

The useful conclusion: **the first root cannot be automatic, but every boot
after the first can be.** The one-time setup can be done by the exploit itself,
so it costs the user exactly one manual run.

Recommended path: during that first manual root session, install a *persistent
localhost ADB channel* (`persist.adb.tcp.port=5555` + the app's own public key in
`adb_keys`). From then on TimerRoot connects to `127.0.0.1:5555`, starts Shizuku
with its own starter, binds, and runs the exploit — no Wi-Fi, no PC, no patched
Shizuku. See §6.

---

## 2. What "on boot" can hook

- `android.intent.action.BOOT_COMPLETED` is sent once per real boot, after the
  user is unlocked. `LOCKED_BOOT_COMPLETED` is sent earlier, before credential
  encrypted storage is available, but only to `directBootAware` components.
- Soft restarts (app relaunch, force-stop, activity recreation, `am start`)
  never send these. So "boot, not soft restart" is automatic if the work is
  triggered only from these broadcasts.
- Do **not** also trigger from `onCreate()` of the activity, or a normal app
  launch would count as a boot.
- Android 15 (targetSdk 35+) forbids `BOOT_COMPLETED` receivers from starting
  `dataSync`, `camera`, `mediaPlayback`, `phoneCall`, `mediaProjection` and
  `microphone` foreground services. `specialUse` is still allowed and is the
  right type here. Android 16 (targetSdk 36) keeps that list.
- A boot-time job can run for minutes only in a foreground service; a
  `goAsync()` receiver is limited to ~10 s and the exploit can take longer
  (`openRoot()` in `UserService` already waits up to 300 s).
- Use a per-boot guard (see §7) so `LOCKED_BOOT_COMPLETED` + `BOOT_COMPLETED`
  and any retry loop never run the exploit twice in one boot.

---

## 3. The bootstrap problem

`timer shell` / `timer fake` need uid 2000 in `u:r:shell:s0` (tracefs writes).
Android grants that only through:

1. **root** (`su`), or
2. **adbd**, after the client's RSA key is authorized in
   `/data/misc/adb/adb_keys`.

There is no app permission, intent, or Shizuku API that hands out a shell
without one of those. Therefore:

- `Shizuku` in **root mode** is fully automatic on a rooted device.
- `Shizuku` in **ADB mode** needs an already-paired key and an already-running
  adbd. Its boot receiver can drive that, with the caveats in §4.
- On a fresh unrooted phone, *some* manual step (USB `adb`, in-app wireless
  pairing, or one manual exploit run) is unavoidable.

---

## 4. How Shizuku boots today (v13.6.0)

Receiver: `moe.shizuku.manager.receiver.BootCompleteReceiver`, exported,
`directBootAware`, listens for `LOCKED_BOOT_COMPLETED` and `BOOT_COMPLETED`.

```kotlin
if (ShizukuSettings.getLastLaunchMode() == LaunchMethod.ROOT) {
    rootStart(context)              // Shell.cmd(Starter.internalCommand)
} else if (SDK_INT >= 33 &&
           checkSelfPermission(WRITE_SECURE_SETTINGS) == GRANTED &&
           getLastLaunchMode() == LaunchMethod.ADB) {
    adbStart(context)
}
```

Notes that matter:

- Settings are stored in **device protected storage**
  (`ShizukuSettings.getSettingsStorageContext()` uses
  `createDeviceProtectedStorageContext()`), so the mode is readable at
  `LOCKED_BOOT_COMPLETED`.
- The receiver can be disabled entirely by the "Start on boot (root)" toggle
  (`PackageManager.setComponentEnabledSetting` on `BootCompleteReceiver`).
- `rootStart()` requires `Shell.getShell().isRoot`; it does nothing on an
  unrooted device.
- `adbStart()` writes `adb_wifi_enabled=1`, `adb_enabled=1`,
  `adb_allowed_connection_time=0`, starts an `AdbMdns` discovery for
  `_adb-tls-connect._tcp`, waits **3 seconds**, then connects with
  `AdbClient("127.0.0.1", port, key)` and runs
  `Starter.internalCommand` (`<nativeLibraryDir>/libshizuku.so --apk=<apk>`).
- The app only ever connects over **127.0.0.1**; the missing piece is the port.

Why the ADB path is fragile:

- `WRITE_SECURE_SETTINGS` must have been granted (normally once, by `adb`).
- mDNS discovery needs a network. `AdbMdns.onServiceResolved()` additionally
  requires the resolved address to equal one of the device's interface
  addresses. With Wi-Fi off there is nothing to resolve.
- Turning Wi-Fi **off** or **disconnecting** makes the framework write
  `ADB_WIFI_ENABLED=0`, which sets `persist.adb.tls_server.enable=0` and stops
  adbd's TLS server (`AdbDebuggingManager` broadcast receiver). Booting while
  connected to an *untrusted* network also sets it back to 0.
- Known upstream bug: `NetworkOnMainThreadException` in the boot path
  (RikkaApps/Shizuku#2564), plus the long-standing "no Wi-Fi at boot" issue
  (#1227).

Shizuku's permission (`moe.shizuku.manager.permission.API_V23`) is a one-time
user tap; it persists. It cannot be auto-granted.

---

## 5. Running ADB without Wi-Fi

This is the part that makes a no-Wi-Fi design possible.

- adbd's wireless TLS listener binds **0.0.0.0**, not the Wi-Fi address:
  `network_inaddr_any_server(port_, SOCK_STREAM)` in
  `packages/modules/adb/daemon/adb_wifi.cpp` (`TlsServer::Start`), with
  `TlsServer(0)` → a random port each boot.
- The port is announced as `service.adb.tls.port`. Its SELinux type is
  `adbd_prop`, declared with `system_internal_prop` (`private/property.te`) and
  is not in `core_property_type` (the attribute the policy documents as
  "readable to everyone"), so it is **not readable from an app domain**.
- Connecting over loopback therefore needs *port discovery*: a scan of
  `127.0.0.1` (cheap, no permissions) or a patched Shizuku.
- TLS auth has no interactive fallback: `adbd_tls_verify_cert()`
  (`daemon/auth.cpp`) accepts only certificates whose public key is already in
  `adb_keys`; an unknown key fails the handshake. So for the TLS path, pairing
  is mandatory. (Classic TCP auth *does* prompt — that is the trick in §6.)
- `persist.adb.tls_server.enable=1` survives reboots and adbd starts the TLS
  server on every boot. `persist.adb.tcp.port` is also read by adbd
  (`daemon/main.cpp`), but nothing in the UI writes it — only root can.

Also relevant:

- adbd is a `disabled` init service. It is started by `ctl.start adbd` from
  `AdbService.setAdbEnabled()` when the USB or wireless setting flips to 1, or
  by `init.usb.rc` (`on boot` → `sys.usb.config=${persist.sys.usb.config}`) when
  `persist.sys.usb.config` contains `adb`.
- `adb tcpip <port>` only sets the volatile `service.adb.tcp.port`, so it does
  not survive a reboot. `persist.adb.tcp.port` does.

---

## 6. Recommended design

### 6.1 One-time setup (manual, during the first successful run)

Add to the existing "Get root shell" flow an *Install auto-root* step, executed
in the root shell that `timer shell` already gives us:

```sh
# 1. our own key, generated once by the app (RSA 2048, kept in app-private storage)
cat /data/local/tmp/timeroot.pub >> /data/misc/adb/adb_keys
chown system:shell /data/misc/adb/adb_keys
chmod 0640 /data/misc/adb/adb_keys

# 2. keep a local TCP listener across reboots
setprop persist.adb.tcp.port 5555

# 3. make sure adbd actually starts at boot (USB debugging setting)
#    persist.sys.usb.config normally already contains "adb" if the user
#    enabled USB debugging for Shizuku's setup; verify, don't force.
getprop persist.sys.usb.config

# 4. no 7-day key expiry
settings put global adb_allowed_connection_time 0

# 5. reload keys / restart adbd
setprop ctl.restart adbd
```

The public key must be in Android's 524-byte `RSAPublicKey` blob format
(`len` in 32-bit words, `n0inv`, `modulus`, `rr`, `exponent`, all little
endian); `adb_keys` stores `base64(blob) comment`. Note the distinction:
`A_AUTH RSAPUBLICKEY` sends that **base64 text line** (NUL-terminated), not the
binary blob — adbd passes it straight to the confirmation dialog. ~40 lines
with `BigInteger`. Verified byte-identical to a real `adbkey.pub`.

If writing `adb_keys` directly is undesirable, the alternative is to append
nothing and let TimerRoot connect once to `:5555` with an unknown key; adbd
shows the normal "Allow USB debugging?" dialog and writes the key itself on
"Always allow". The app still has to build the same public key blob, so the
code is the same; the only difference is one user tap.

Result: on every later boot, `adbd` listens on `tcp:5555` even with no Wi-Fi
and no cable, and TimerRoot's key is already trusted.

### 6.2 Every boot (no user interaction, no Wi-Fi)

```
BootReceiver (directBootAware)
  └─ AutoRootService (foreground, type=specialUse)
       ├─ per-boot guard (boot id)
       ├─ connect 127.0.0.1:5555  (minimal ADB client, CNXN/AUTH/OPEN)
       ├─ if `Shizuku.pingBinder()` is false:
       │     open shell:  and run  <libshizuku.so> --apk=<base.apk>
       ├─ wait for Shizuku binder, check permission, bindUserService()
       ├─ install bundled assets/timer if missing or wrong
       ├─ `timer target` must print `target=lynx` before running anything
       ├─ once per boot: `timer fake`  (late-load KernelSU, `KSU_LOADED`)
       │  or `timer shell`            (root shell held by the app)
       └─ notification: running / done / needs attention
```

Why the ADB client is small: only CNXN, AUTH (sign SHA-1 token with RSA, PKCS#1
v1.5), OPEN `shell:<cmd>`, WRTE, and reading until CLSE. No TLS, no SPAKE2, no
mDNS. ~300 lines of Java, no new dependencies.

Why it still matches the requested stack: the ADB shell is used only to start
Shizuku (exactly `Starter.internalCommand`), then everything else is the current
Shizuku `UserService` path, unchanged. The ADB shell is also a fallback if
Shizuku fails to start: the exploit can be run directly from it, since it is
uid 2000 / `u:r:shell:s0`.

### 6.3 Alternatives, and why they are worse

**A. Rely on Shizuku root mode.** Zero new bootstrap code, zero Wi-Fi
dependency — but only on a device that is already rooted. Worth keeping as the
"if `su` works, use it" branch.

**B. Stock Shizuku ADB boot path.** Works today when Wi-Fi is up, the network
is trusted, the app has `WRITE_SECURE_SETTINGS`, and the receiver is enabled.
This is what the user already has; it is not a no-Wi-Fi solution and it can
silently turn itself off when Wi-Fi changes.

**C. Fork Shizuku, replace `AdbMdns` with a loopback scan.** ~50 lines, keeps
Shizuku's own key/pairing. But it means shipping and re-signing Shizuku, users
must uninstall the official app, re-pair, and re-grant permissions. Only worth
it if TimerRoot must not own an ADB key.

**D. In-app wireless pairing (SPAKE2) + TLS + loopback port scan.** No
first-root and no PC, but ~1.5–2k lines (or vendoring `dadb`, which is Kotlin)
and still fails whenever the framework disables `ADB_WIFI_ENABLED`.

**E. `adb tcpip` from a PC.** Does not persist (`service.adb.tcp.port` is
volatile), so it cannot help on later boots.

---

## 7. TimerRoot implementation plan (Phase 1)

Files:

- `app/src/main/AndroidManifest.xml`
  - `RECEIVE_BOOT_COMPLETED`, `FOREGROUND_SERVICE`,
    `FOREGROUND_SERVICE_SPECIAL_USE`, `POST_NOTIFICATIONS`.
  - `<receiver android:name=".BootReceiver" android:exported="false"
    android:directBootAware="true">` with `LOCKED_BOOT_COMPLETED` and
    `BOOT_COMPLETED`.
  - `<service android:name=".AutoRootService"
    android:foregroundServiceType="specialUse">` plus the
    `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` property.
- `BootReceiver.java`: reads the auto-root flag from **device protected**
  prefs; if enabled, `startForegroundService(...)`.
- `AutoRootService.java`: the state machine above. Keep a notification, and
  keep the service alive while the root process is held.
- `AutoRoot.java`: shared config (enabled, action = `fake`|`shell`), boot-id
  guard, and log parsing.
- `AdbLocal.java` (Phase 2 / §6): minimal localhost ADB client.
- `MainActivity`: an "Auto-root on boot" switch (device protected prefs), a
  one-time "Install auto-root channel" action shown only when a root shell is
  open, and a "Grant Shizuku permission" path that fires when the service
  reports `permission != 0`.

Ordering and retries:

- `BOOT_COMPLETED` can arrive before adbd or Shizuku are ready. Poll with
  backoff (e.g. every 5 s for 3 minutes) instead of failing once.
- Handle `LOCKED_BOOT_COMPLETED` early (root mode can start there; ADB mode
  usually cannot) and `BOOT_COMPLETED` as the main attempt.
- Do not start a `dataSync` FGS; use `specialUse`.
- Do not download the binary at boot; `assets/timer` is already bundled and
  `UserService.install()` copies it from the APK.

Per-boot guard:

```java
long bootTime = System.currentTimeMillis() - SystemClock.elapsedRealtime();
// store bootTime; if unchanged (within ~30 s), this is the same boot → skip
```

One attempt per boot, and never retry after a failure:

- `timer shell` / `timer fake` park a process on failure and the app already
  warns "reboot before retrying".
- Read `/data/local/tmp/timer.log`; if it contains `parking without reap`,
  `no successful plant`, or `KSU_STALE`, stop and notify. Do not loop.

State to keep in device protected prefs:

- `auto_root` (bool), `auto_root_action` (`fake`|`shell`), `last_boot_time`,
  `last_result`, `setup_done`.

---

## 8. Gotchas

- **Shizuku permission** is a user tap. If it was revoked, the boot run must
  post a notification that opens `MainActivity` with the permission request
  pending; it cannot grant itself.
- **Shizuku boot receiver can be disabled** by its "Start on boot (root)"
  switch. `pm enable moe.shizuku.manager/...BootCompleteReceiver` works only
  with shell, so expose it as a diagnostic, not as the primary path.
- **`ADB_WIFI_ENABLED` flips itself to 0** when Wi-Fi is turned off, when the
  network disconnects, or when booting on an untrusted network. A no-Wi-Fi
  design should use the classic TCP port (§6), not the TLS server.
- **`persist.adb.tcp.port` must be written by root** and needs a one-time
  on-device verification on the Pixel: confirm `adbd` starts without a cable
  and listens on 5555 after reboot (`ss -ltn` / `getprop`). If a future Pixel
  build ignores it, fall back to the loopback TLS scan + pairing.
- **USB debugging stays on** in this design (that is what makes adbd start at
  boot). Turning it off kills the channel; detect it and notify.
- **The exploit is one-shot per boot.** `openRoot()` blocks up to 300 s and
  succeeds only if the race lands; auto-retrying can corrupt state.
- **Binary/target check** must stay: run `timer target` and require
  `target=lynx` before every attempt, otherwise a wrong build can corrupt the
  kernel.
- **`/data/local/tmp` and `/data/local/tmp/timer.log` persist across boots**, so
  clear or timestamp the log before a run to avoid matching an old success.
- **Root does not survive reboot**; auto-root means re-exploiting every boot,
  not installing a permanent su (the KSU late-load is also per-boot).
- **QEMU cannot validate any of this.** The boot receiver, adbd startup
  ordering, key authorization, and FGS restrictions all need real hardware.

---

## 9. One-time user checklist

Rooted device (easiest):

1. Install Shizuku; start it in root mode; enable "Start on boot".
2. Grant TimerRoot the Shizuku permission once.
3. Enable "Auto-root on boot" in TimerRoot.

Unrooted device, no-Wi-Fi path (§6):

1. Run the exploit once manually from TimerRoot.
2. In the root shell, press "Install auto-root channel" (writes `adb_keys`,
   `persist.adb.tcp.port`, `adb_allowed_connection_time=0`).
3. Enable "Auto-root on boot" and reboot.

After step 3 every boot is hands-off and needs no Wi-Fi. The first root always
requires that one manual step.

---

## 10. Android 17 field notes (Pixel 7a, CP3A.261005.002.A1)

Measured on the attached device, not inferred from AOSP:

- Build `google/lynx/lynx:17/CP3A.261005.002.A1/16269273:user/release-keys`,
  SDK 37, kernel `6.1.162-android14-11-g9dd05ae3a1de-ab16261587`,
  `ro.debuggable=0`, `ro.adb.secure=1`, no `su`.
- Shizuku `13.6.0.r1086.2650830c`, targetSdk 36. Its
  `moe.shizuku.manager.permission.API_V23` still has protectionLevel `0x1`
  (dangerous runtime permission); once granted it persists.
- **Shizuku's own boot receiver did not start the server.** `am_proc_start`
  logged `BootCompleteReceiver` at `19:20:02`, but no `shizuku_server` came
  up; the user launched `StarterActivity` at `19:20:18`. The 3-second
  `AdbMdns` window is too short on Android 17 (and there is no mDNS without
  Wi-Fi). This is why TimerRoot has to drive the start itself.
- `adbd` runs as uid 2000 in `u:r:adbd:s0`. `adb tcpip 5555` makes it listen
  on `::`/`0.0.0.0:5555`, and shell can connect to both `127.0.0.1:5555`
  and `::1:5555`. **Restarting adbd kills `shizuku_server`** (the ADB-mode
  server belongs to the adb session), so the boot path must never restart
  adbd while it is needed.
- `persist.adb.tcp.port` is read by adbd (`daemon/main.cpp`: it falls back
  from `service.adb.tcp.port` to `persist.adb.tcp.port`), so a root-written
  value survives reboot. Shell cannot write it:
  `setprop persist.adb.tcp.port 5555` fails for uid 2000.
- The TLS listener is live on a random port (`dumpsys adb` showed `34207`,
  later `41607`), but `service.adb.tls.port` and
  `persist.adb.tls_server.enable` are `adbd_prop`/`system_adbd_prop`; shell
  reads them as empty and logcat shows `avc: denied { read } ... adbd_prop`.
  Port scanning therefore stays a fallback, not the main path.
- Android 17 still runs `AdbWifiNetworkMonitor.onLost()` → `setAdbEnabled(false)`
  for Wi-Fi, so "adb over Wi-Fi" is not a boot-safe channel. A device that
  boots with Wi-Fi off never enables it.
- `ACCESS_LOCAL_NETWORK` is auto-granted to both apps because they target
  SDK 36; it only becomes a runtime permission at targetSdk 37.
- `adb_keys` lives in `/data/misc/adb` (mode 0640 `system:shell`) and is not
  readable by apps or shell. adbd reloads it per auth attempt, so no adbd
  restart is needed after appending a key — but the write itself needs root
  **and** a permissive SELinux domain (`adb_keys_file` / `adbd_prop` are not
  writable from `u:r:shell:s0` while enforcing). The exploit's own
  `permissive` mode clears the kernel's enforcing flag without KernelSU, and
  the root shell can then write `/data/property/persistent_properties`; the
  key file itself still needs `CAP_DAC_OVERRIDE`, which the uid-0 shell does
  not have, so one "Always allow" tap remains for the first connection.
- Auth details confirmed against `packages/modules/adb`:
  - tokens are 20 random bytes, regenerated by adbd on every failed attempt;
  - the response is `SHA1withRSA` over the raw token (PKCS#1 v1.5);
  - `A_AUTH RSAPUBLICKEY` carries the base64 key line as a NUL-terminated
    string, not the 524-byte blob;
  - an unknown key raises "Allow USB debugging? / Always allow from this
    computer". Tapping it writes the key to `adb_keys`/the framework keystore,
    so **only the first connection needs a tap**; later boots use the
    signature path with no UI.

## 11. Implemented in 0.38

Files:

| File | Purpose |
| --- | --- |
| `BootReceiver.java` | `directBootAware`; `LOCKED_BOOT_COMPLETED` starts Shizuku early, `BOOT_COMPLETED` runs the bind + exploit. |
| `AutoRootService.java` | `specialUse` FGS state machine: prestart at locked boot, then wait for unlock → reuse or start Shizuku → restart once so the binder is pushed → bind `UserService` → install asset → check `target=lynx` → `openRoot()` once. Stays alive after success so the root shell survives. |
| `RestartJobService.java` | `JobScheduler` job (1 s latency, 4 s deadline) that starts `AutoRootService` in a fresh process after the boot path kills itself. |
| `AutoRoot.java` | Device-protected prefs, per-boot and restart guards, key pair, rotating log. |
| `AdbKey.java` | RSA 2048 generation and the exact 524-byte public blob / key line. |
| `AdbLocal.java` | CNXN/AUTH/OPEN/WRTE/CLSE only; no TLS, mDNS or pairing. |
| `MainActivity` | Auto-root toggle, notification permission, "Install channel", "Run auto-root now", log viewer. |
| `p7a/timer_p7a.c` | Adds the `permissive` mode: one plant writes `selinux_state`, retried three times. |

Behaviour:

- Two boot stages. `LOCKED_BOOT_COMPLETED` arrives seconds after the kernel
  starts, so it is used to start `shizuku_server` over the localhost ADB
  channel; the service then stays foreground with "waiting for unlock".
  `BOOT_COMPLETED` is delivered after the first unlock on Android 17 and runs
  the rest. The split exists because `BinderSender.checkPermission` reads the
  credential-encrypted user: while the device is locked, no binder is pushed
  and `bindUserService` cannot work, no matter how early Shizuku came up.
- The prestart stage retries the starter (four tries) because it runs while
  parts of the system are still coming up; the starter itself is confirmed
  with `pidof shizuku_server`, since it daemonizes and exits 0 immediately.
- The boot stage reuses a server that prestart already started instead of
  calling the starter again (the starter kills the old process first).
- Guard: `bootId = (currentTimeMillis - elapsedRealtime) / 30s`; one claim per
  boot, so `LOCKED_BOOT_COMPLETED` + `BOOT_COMPLETED`, a retry, or a second
  service start cannot trigger the exploit twice. The claim is released if the
  device is still locked when the boot stage runs, so that boot can be retried
  from the app. A scheduled restart is exempt from the guard and is allowed
  twice per boot.
- `specialUse` FGS (allowed from `BOOT_COMPLETED` on 15/16/17); a partial
  wake lock covers the exploit window.
- Shizuku binder delivery needs a uid `gone -> active` transition. At boot the
  app process exists before `shizuku_server`, so `BinderSender` never pushes
  the binder. Starting another process of the same uid (`:probe`) is not
  enough. The boot path therefore kills its own process and lets a
  `JobScheduler` job start it again; the new process receives the binder
  through `ShizukuProvider` before `Application.onCreate`.
- Failures are one-shot: a parked exploit already means "reboot", so the
  service reports the reason and does not loop.
- The ADB starter command is the same one Shizuku uses:
  `<nativeLibraryDir>/libshizuku.so --apk=<base.apk>`, located with
  `pm path` so no package-visibility or cross-app file access is needed.
- "Install channel" runs entirely from the app: `timer permissive` clears the
  kernel enforcing flag, `openRoot()` gets a uid-0 shell, and that shell
  appends the protobuf record `0a 1c 0a 14 "persist.adb.tcp.port" 12 04
  "5555"` to `/data/property/persistent_properties` (Android 17 ignores the
  legacy per-name files). It also sets
  `adb_allowed_connection_time 0` and tries to append the key to `adb_keys`.
  `setprop` and `adb_keys` still fail because the shell domain has no
  capabilities; the key needs one "Always allow" tap.

Verified on the Pixel 7a (`CP3A.261005.002.A1`, SDK 37, Wi-Fi off):

Fresh-process variant (the APK update had killed the prestart process, so
`BinderSender` delivered the binder on its own):

```
22:53:39  received android.intent.action.LOCKED_BOOT_COMPLETED
22:53:45  prestart starter 1: launched
22:53:46  prestart: server is up, waiting for unlock
          (device left at the lock screen for 13 min; shizuku_server pid 3621 stayed up)
23:07:34  received android.intent.action.BOOT_COMPLETED      (immediately after unlock)
23:07:35  Shizuku is already running
23:07:36  installed 2108688 bytes (uid=2000)
23:07:36  timer shell
23:07:49  success: root shell ready
```

Normal variant (the prestart process survives to unlock, so the restart branch
is required):

```
23:15:00  received android.intent.action.LOCKED_BOOT_COMPLETED
23:15:03  prestart: server is up, waiting for unlock
23:17:28  received android.intent.action.BOOT_COMPLETED      (immediately after unlock)
23:17:44  Shizuku server is already up from the prestart
23:17:44  server is up, no binder yet; restarting the app process
23:17:46  restart job: starting auto-root
23:17:46  resuming this boot after the binder restart
23:17:47  installed 2108688 bytes (uid=2000)
23:17:47  timer shell
23:18:16  success: root shell ready
```

After that boot: `isForeground=true` on `AutoRootService`, `shizuku_server` and
`com.kpgc.timerroot:timer` alive, a `uid=0` `sh` child under it, and adbd
listening on `*:5555` from `persist.adb.tcp.port`.

The earlier single-stage runs (`BOOT_COMPLETED` only) were verified end to end
twice with Wi-Fi off: `22:11:54` → success at `22:12:50`, and `22:32` → success
at `22:32:53`. `Install channel` was also verified end-to-end from the app:
`permissive ok` (4 s), root shell in ~70 s, `PROP_PRESENT size=13283`, and the
property survived a real reboot.

After that boot: `isForeground=true` on `AutoRootService`, `shizuku_server`
and `com.kpgc.timerroot:timer` alive, a `uid=0` `sh` child under it, and adbd
listening on `*:5555` from `persist.adb.tcp.port`. `Install channel` was also
verified end-to-end from the app: `permissive ok` (4 s), root shell in ~70 s,
`PROP_PRESENT size=13283`, and the property survived a real reboot.

