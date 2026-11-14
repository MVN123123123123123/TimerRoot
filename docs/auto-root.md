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
       ├─ once per boot: `timer shell` (root shell held by the app)
       ├─ then `timer fake`, replanted up to 3x
       │     (fake cred -> ksud late-load -> `KSU_LOADED`, SELinux off)
       ├─ `su -c id` must report `u:r:ksu:s0`, then `keepPermissive()`
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
  - `<provider android:name="rikka.shizuku.ShizukuProvider"
    android:directBootAware="true">` so `shizuku_server` can deliver its binder
    while the credential-encrypted user is locked.
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
- `LOCKED_BOOT_COMPLETED` is the main attempt: start Shizuku there and run the
  exploit at BFU. `BOOT_COMPLETED` is a retry for a failure that happened
  before the exploit started.
- Do not start a `dataSync` FGS; use `specialUse`.
- Do not download the binary at boot; `assets/timer` is already bundled and
  `UserService.install()` copies it from the APK.

Per-boot guard:

```java
long bootTime = System.currentTimeMillis() - SystemClock.elapsedRealtime();
// store bootTime; if unchanged (within ~30 s), this is the same boot → skip
```

One exploit per boot; retry only failures that happened before it:

- `timer shell` / `timer fake` park a process on failure and the app already
  warns "reboot before retrying".
- The boot claim is released only when the failure happened before
  `openRoot()`; a retry then cannot double-run the exploit.
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
  succeeds only if the race lands; auto-retrying can corrupt state. The one
  exception is a missed burst: the exploit itself replants up to three times
  in `shell`/`permissive` mode without reaping the parked zombie, and
  `AutoRootService` uses the same bound when it replants the `fake` stage.
  Anything after `KSU_LOADED` (or a `KSU_STALE` / missing-manager verdict) is
  final and must not be retried.
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
  key file itself still needs `CAP_DAC_OVERRIDE`, which the shell-domain
  uid-0 shell does not have, so one "Always allow" tap remains for the first
  connection. KernelSU's `su` runs as `u:r:ksu:s0` with full capabilities,
  so Install channel uses it when a module is already loaded and the tap is
  only needed on a first bootstrap without one.
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
| `BootReceiver.java` | `directBootAware`; `LOCKED_BOOT_COMPLETED` starts Shizuku early and runs the exploit at BFU, `BOOT_COMPLETED` only retries when the BFU attempt failed before the exploit. After a soft restart both broadcasts only resume Shizuku and republish the result. |
| `AutoRootService.java` | `specialUse` FGS state machine: at locked boot reuse/start Shizuku → bind at BFU → install asset → check `target=lynx` → `openRoot()` → `timer fake` → `keepPermissive()` → `ksud soft-reboot`. Stays alive after success so the root shell survives. |
| `RestartJobService.java` | Fallback binder-push restart when the server is up but its binder never arrived (used after unlock, not at BFU). |
| `AutoRoot.java` | Device-protected prefs, per-boot and restart guards, key pair, rotating log. |
| `AdbKey.java` | RSA 2048 generation and the exact 524-byte public blob / key line. |
| `AdbLocal.java` | CNXN/AUTH/OPEN/WRTE/CLSE only; no TLS, mDNS or pairing. |
| `MainActivity` | Home tab (status, root/KernelSU actions, device details, update banner), Log tab, and a Settings tab for Shizuku, the exploit binary, auto-root, the boot screen, restarts and update checks. |
| `UpdateChecker.java` | Reads the `TimerRoot.apk` asset's `versionCode` from the GitHub releases API and caches the result; never installs anything. |
| `p7a/timer_p7a.c` | Adds the `permissive` mode: one plant writes `selinux_state`, retried three times. |

Behaviour:

- Direct-boot-aware provider is the key. When `shizuku_server` starts, its
  `RunnableC2088g0` hands the binder to the manager and then to every installed
  package that requests `moe.shizuku.manager.permission.API_V23`
  (`ShizukuService.B`), using `getContentProviderExternal` on `<pkg>.shizuku`.
  With `android:directBootAware="true"` on `ShizukuProvider`, the provider can
  be instantiated while the credential-encrypted user is locked, so the binder
  arrives at BFU. The permission check reads package-manager state, which is
  also available at BFU. Verified on the Pixel 7a below.
- Two boot stages, both attempt the exploit. `LOCKED_BOOT_COMPLETED` arrives
  seconds after the kernel starts; the service starts or reuses
  `shizuku_server` over the localhost ADB channel and runs the whole chain
  immediately. `BOOT_COMPLETED` is only a retry for a failure that happened
  before the exploit (no binder, permission, bind, install or target check).
  After a successful BFU run the receiver ignores `BOOT_COMPLETED` outright,
  so the live notification, FGS and root shell are not touched.
- The prestart stage retries the starter (four tries) because it runs while
  parts of the system are still coming up; the starter itself is confirmed
  with `pidof shizuku_server`, since it daemonizes and exits 0 immediately.
- The boot stage reuses a server that prestart already started instead of
  calling the starter again (the starter kills the old process first).
- Guard: `bootId = (currentTimeMillis - elapsedRealtime) / 30s`; one claim per
  boot, so `LOCKED_BOOT_COMPLETED` + `BOOT_COMPLETED`, a retry, or a second
  service start cannot trigger the exploit twice. The claim is released on any
  failure before `openRoot()` starts, so a later retry is still possible; once
  `openRoot()` has run the claim is kept, because the exploit is one-shot.
- `specialUse` FGS (allowed from `BOOT_COMPLETED` on 15/16/17); a partial
  wake lock covers the exploit window.
- Binder-restart fallback: if the server is up but its binder never arrived
  after unlock, the service kills its own process and a `JobScheduler` job
  starts it again, giving the uid a `gone -> active` transition. At BFU the
  path deliberately does not use this (jobs may be deferred while locked); it
  leaves the boot claim free and lets the post-unlock `BOOT_COMPLETED` retry.
- Failures are one-shot once the exploit has started: a parked exploit already
  means "reboot", so the service reports the reason and does not loop.
- KernelSU is part of the boot chain, not a manual extra: after `openRoot()`
  the service runs `timer fake`, which late-loads the manager's module and
  clears the kernel enforcing flag in the same plant (no separate `timer
  permissive` run). The stage is replanted up to three times, because the
  plant is a race and the exploit itself replants three times in `shell` and
  `permissive` mode; a missed burst parks a process and is otherwise
  harmless. Success is decided by the kernel, not by the stage output:
  `su -c id` must report `u:r:ksu:s0` (SukiSU Ultra tears the stage shell down
  before it can print `KSU_LOADED`), and `keepPermissive()` then re-applies
  `setenforce 0` because the module forces enforcing back ~0.4 s after load.
  A KernelSU failure keeps the working root shell and is reported as
  `root shell ready; KernelSU failed: ...`.
- Soft restart after success (`softRestart()` in `UserService`, driven by
  `maybeSoftRestart()`). A late-loaded module is in the kernel but its boot
  stages never ran, so its mounts and Zygisk are missing until a real reboot.
  The service ends the run with `ksud soft-reboot`, which is exactly what the
  manager's *soft reboot* button does: reset `sys.boot_completed`, run the
  `emulated-soft-reboot` stage scripts, `stop`, `start`, then replay
  `post-fs-data` / `services` / `boot-completed`. The kernel never goes down,
  so `su` keeps returning `u:r:ksu:s0`, the module stays loaded and the parked
  exploit processes stay parked. It runs only after a successful late-load
  (`KernelSU active`), once per real boot: `soft_restart_boot` stores the boot
  id, which survives a userspace restart, so the resumed system cannot loop.
  A missing `soft-reboot` subcommand (KernelSU < 3.x) is logged and the claim is
  released; the success stays valid.
- A userspace restart re-sends `LOCKED_BOOT_COMPLETED` and `BOOT_COMPLETED`
  while the exploit must not run again. The receiver detects
  `soft_restart_boot == bootId` and takes `ACTION_AFTER_RESTART` instead, which
  only starts Shizuku and republishes `last_result` in the notification.
  `claimResumeAfterRestart()` makes sure only the first of the two broadcasts
  acts, since which arrives first depends on the lock state. The status screen
  is deliberately *not* brought back: the completed result was already on
  screen (or in the notification) before the restart, and the device comes
  back to the lock screen, so `maybeSoftRestart()` records
  `boot_ui_seen_boot` for this boot id. `bootUiWanted()` returns false for the
  resumed process, which keeps both `maybeShow()` and the full-screen intent
  away while still updating the notification to **Jailbreak mode ready**. The
  mark is cleared if the restart turns out to be unavailable, so the page can
  still show when nothing happened.
- The ADB starter command is the same one Shizuku uses:
  `<nativeLibraryDir>/libshizuku.so --apk=<base.apk>`, located with
  `pm path` so no package-visibility or cross-app file access is needed.
- "Install channel" runs entirely from the app. If KernelSU is already
  loaded it uses its `su` (uid 0 with full capabilities, `u:r:ksu:s0`);
  otherwise `timer permissive` clears the kernel enforcing flag and
  `openRoot()` opens the shell-domain uid-0 shell. The shell appends the
  protobuf record `0a 1c 0a 14 "persist.adb.tcp.port" 12 04 "5555"` to
  `/data/property/persistent_properties` (Android 17 ignores the legacy
  per-name files). It also sets `adb_allowed_connection_time 0` and writes
  the key to `adb_keys`. Through KernelSU's `su` the key lands in one go and
  needs no dialog; from the shell-domain root shell the append fails
  (`adb_keys` is 0640 `system:shell` and that shell has no
  `CAP_DAC_OVERRIDE`), so the app reports `KEY_LOCKED` and one "Always
  allow" tap remains for the first connection.

Verified on the Pixel 7a (`CP3A.261005.002.A1`, SDK 37, Wi-Fi off), with the
device still BFU for the whole run (`dumpsys user` → `State: RUNNING_LOCKED`,
unlock time unknown):

```
17:11:39.178  BinderSender: Uid 10326 starts
17:11:39.219  ShizukuProvider: binder received
17:11:39.221  ShizukuServerLog: attachApplication from com.kpgc.timerroot
17:11:39.245  debug hook started AutoRootService (temporary test receiver)
17:11:39.269  prestart: Shizuku is already running
17:11:39.294  user service com.kpgc.timerroot:timer started (uid 2000)
17:11:39.627  installed 2108688 bytes (uid=2000)
17:11:39.753  timer shell
17:12:17.668  success: root shell ready
```

After that: `isForeground=true` on `AutoRootService`, `shizuku_server` and
`com.kpgc.timerroot:timer` alive, a `uid=0` `sh -i` child under `timer`, and the
user still locked. The temporary debug receiver used to trigger this run was
removed from the final APK.

Before the provider fix, the same localhost ADB channel was verified end to end
after unlock (`BOOT_COMPLETED` → success), including the binder-restart branch.
Those runs proved the starter, the user service and the exploit; the BFU run
above adds the missing direct-boot binder delivery. `Install channel` was also
verified end-to-end from the app: `permissive ok` (4 s), root shell in ~70 s,
`PROP_PRESENT size=13283`, and the property survived a real reboot.

KernelSU at BFU (same build, still `State: RUNNING_LOCKED` when the last line
was logged):

```
17:57:07  auto: root shell ready; loading KernelSU
17:57:09  auto: timer fake
17:57:27  [+] plant1 free_seen=1 burst hit=0 after 15002ms
17:57:27  auto: KernelSU attempt 2: the exploit parked before loading ksud
17:57:29  auto: timer fake
17:57:46  [ksu] uapi manager=6 kernel=6 preloaded=0
17:57:46  KSU_LOADED
17:57:46  auto: KernelSU active: selinux=Permissive (after 1s)
17:57:46  auto: success: root shell ready; KernelSU active (selinux=Permissive (after 1s))
```

Checked while still locked: `su -c id` → `uid=0(root) ... context=u:r:ksu:s0`,
`getenforce` → `Permissive`, `kernelsu 565248 0 - Live ... (O)` in
`/proc/modules`, `/data/adb/ksud` and `/data/adb/ksu/bin` rewritten by that
boot's late-load, and the live notification became **Jailbreak mode ready**.
The manager was a repackaged SukiSU (`pewhkk.neduyw.pgwdfo`), found by the
`/data/app` scan rather than by package name.

The first fake attempt in that log shows the failure mode the replant exists
for: a plant missed its burst (`burst hit=0`) and parked. The second attempt
hit both plants and loaded the module. Both attempts' parked processes stay
alive until the next reboot, by design.


---

## Boot status screen (BFU)

The boot path can display a full-screen status page while it runs, so the
user can see whether auto-root is still working or already done without
unlocking. It is implemented as `BootStatusActivity`, a `directBootAware`
activity with `showWhenLocked` and `turnScreenOn`, and it reads all of its
state from device-protected storage.

What it shows:

- a self-drawn animated gradient background, a still-image slideshow, or a
  muted looping video copied by the user into
  `files/bootui/background.video` / `background.image0`;
- a spinner while running, a green check on success, a red cross on failure;
- the current stage (`starting Shizuku...`, `running the exploit...`,
  `loading KernelSU... 20s`, ...) and how long that stage has been running;
- a short hint that unlocking is allowed at any time, plus a top-corner
  **Turn off** action (disables auto-root for future boots without touching
  the run in progress) and a **Hide** action. Once the first run since a
  soft restart finishes successfully, **Turn off** disappears and only
  **Hide** remains.

### How it gets on screen

Android blocks background activity starts. Two exemptions are used:

1. **Full-screen intent** (primary). The ongoing notification lives on a
   separate high-importance, silent channel and carries
   `setFullScreenIntent(BootStatusActivity.pendingIntent(this), true)`.
   Android 14+ gates this behind the `USE_FULL_SCREEN_INTENT` app-op and the
   *full-screen notifications* special access; before 14 the permission is
   granted at install.
2. **Display over other apps** (opportunistic). `SYSTEM_ALERT_WINDOW` is a
   background-activity-launch exemption, so `maybeShow()` can call
   `startActivity` directly. Newer releases may still refuse this, which is
   why the full-screen intent is the real path.

`AutoRootService` grants both app-ops from its own uid-0 shell after
`openRoot()` succeeds (`appops set com.kpgc.timerroot ... allow`). The same
commands run from **Install channel**, and **Allow overlay** / **Full-screen**
open the corresponding Settings pages for the first run. Without either
access the ordinary progress notification remains the fallback; auto-root
itself does not depend on the screen.

### State transport

`AutoRoot.stage()` / `stageText()` / `stageTime()` / `stageState()` keep the
current line, timestamp and 0/1/-1 state in the `auto_root` device-protected
SharedPreferences. The service publishes with `commit()` (the activity polls
every 500 ms) and `AutoRootService.show()` / `finish()` update it on every
stage change, so the screen and the notification never disagree.

### Limits

- This is not a replacement for `/system/media/bootanimation.zip`: that file
  lives on a read-only partition, and AOSP's boot animation only reads
  `/product`, `/system`, `/oem` and `/apex` paths.
- It cannot be a true live wallpaper over the keyguard; the activity paints
  its own background instead.
- It appears when TimerRoot's process starts (`LOCKED_BOOT_COMPLETED`), not
  during the kernel/init boot animation.
- It never traps the user: `Hide` finishes the activity and returns to the
  keyguard (so a PIN or pattern can be entered), biometric unlock works while
  it is visible, and after a terminal state on an unlocked device it closes
  itself after ~6 s.

### Across a soft restart

A soft restart kills the activity with the rest of the app, and the resumed
system re-sends `LOCKED_BOOT_COMPLETED` / `BOOT_COMPLETED`. The receiver takes
the resume path, which republishes `last_result` and starts Shizuku. The page
does **not** come back: the completed result was on screen before the restart,
so the user already knows the phone is rooted and only needs the lock screen.
`maybeSoftRestart()` records `boot_ui_seen_boot` for this boot id (which
survives a userspace restart), `bootUiWanted()` then returns false, and both
`maybeShow()` and the notification's full-screen intent stay away for the
resumed process. The notification still becomes **Jailbreak mode ready**, so a
pull-down is enough to confirm the outcome. If the restart turns out to be
unavailable, the mark is cleared and the success page stays visible.
