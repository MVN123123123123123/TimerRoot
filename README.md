# TimerRoot

Android front end for **CVE-2026-98260** (POSIX CPU timer use-after-free), the
same class of bug as CVE-2026-64560. One tap gives you a root shell and then
late-loads **KernelSU** (`u:r:ksu:s0`).

The exploit source is included (`p7a/timer_p7a.c`) and is conf-driven: every
kernel-specific constant lives in a HOCON profile under `conf/`, selected at
runtime from `uname -r` and the userspace page size. This repository is the app
shell around it: UI, state detection and the Shizuku plumbing needed to run a
shell-domain exploit from an ordinary app.

## Why the app needs Shizuku

An app runs as `untrusted_app` and cannot read `/sys/kernel/tracing`, which the
exploit needs for its leak and trigger. TimerRoot therefore starts a **Shizuku
user service**, which Shizuku runs as the shell user (`uid 2000`,
`u:r:shell:s0`). The exploit binary executes inside that process, so it gets
the same environment it would have from `adb shell`.

```
MainActivity (untrusted_app)
  └─ Shizuku user service (uid 2000, u:r:shell:s0)
       ├─ extracts assets/timer to /data/local/tmp/timer
       └─ runs it; on success keeps /system/bin/sh alive
```

## Requirements

- Android 12+ (`minSdk 30`), arm64
- [Shizuku](https://shizuku.rikka.app/) running (start it from the Shizuku app
  via wireless debugging, or over ADB)
- For unattended boots: one **Install channel** while a root shell is open, then
  one *Always allow* tap for TimerRoot's ADB key. After that the exploit runs on
  its own at every boot, before the first unlock (see
  [Auto-root on boot](#auto-root-on-boot))
- One supported manager installed, for the `Load KernelSU` path:
  [KernelSU](https://github.com/tiann/KernelSU),
  [KernelSU-Next](https://github.com/rifsxd/KernelSU-Next), or
  [SukiSU Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra)
- A device running one of the kernels this port covers (see
  [Supported devices](#supported-devices)):
  `6.1.162-android14-11-g9dd05ae3a1de-ab16261587` (4K and 16K, Pixel 6 through
  Pixel 10a) or `6.6.127-android15-8-g91d825611104-ab16252310-4k` (Pixel 10
  series). The upstream binary targets
  `6.12.69-android16-6-g242e1a07f878-ab15865446-4k` and will not work here.

## Getting the exploit binary

The exploit is build-specific: the timer call site, `cred` layout and
`task_struct` offsets differ per kernel, and a binary built for another build
will corrupt the kernel instead of failing safely.

The binary no longer hard-codes a profile: every kernel address and structure
offset comes from a HOCON file under `conf/`, and the app picks one for the
running kernel:

- `release` must equal `uname -r`. A trailing `-4k` is optional on both
  sides, so `...-ab16252310` and `...-ab16252310-4k` are the same kernel.
- When the profile sets `page_size`, `sysconf(_SC_PAGESIZE)` must match too.
  This is how the 4K and 16K builds of 6.1.162 are told apart; they share a
  release string.
- Profiles under `conf/dirty/` have a release string that is not unique to one
  vendor build (`-maybe-dirty`), so `device_model`, `android_release` and
  (when present) `sdk_int` must also match the device.

`UserService` extracts `assets/conf/**.conf` to
`/data/local/tmp/timer-conf`, chooses the first match, and runs the binary as:

```
/data/local/tmp/timer --conf /data/local/tmp/timer-conf/<match>.conf shell
```

`--conf` is mandatory. It can be given to the NDK build directly, which is
useful for probing a profile from `adb shell`:

```bash
timer --conf conf/6.1.162-android14-11-g9dd05ae3a1de-ab16261587.conf target
```

The app also passes `--protocol 2`, the app/binary interface version. This is a
compatibility handshake: the old TimerRoot APKs predate the conf rewrite, so
they start the binary without `--conf`/`--protocol`. The new binary then refuses
to run and prints:

```
[!] BREAKING CHANGE: TimerRoot app is too old
[!] OLD_APP_DETECTED app_protocol=0 required=2
```

The notice is written to the app log and `/data/local/tmp/timer_last.log`. It
tells the user to update TimerRoot and install the exploit again. This matters
because the app and the downloaded `timer` are versioned independently: a new
timer must never run under an old app with the wrong (or no) kernel profile.
Manual `--conf <file>` runs are still allowed without `--protocol` for
debugging.

The reverse direction is guarded too. `/data/local/tmp/timer` survives an app
update, so an updated APK can meet a timer from before the conf rewrite. That
binary has no argument parser, and would read `--conf <file>` as an unknown
mode and run a legacy plant, so `UserService` scans the installed binary for
the literal `TIMER_PROTOCOL=2` marker before using it. A binary without the
marker is refused with:

```
BREAKING CHANGE: the installed timer is too old for this app.
```

and the user is told to press **Download exploit** (or Prepare) again. Both
checks are cheap and side-effect free: the binary is never executed to probe
it.

The bundled `conf/` covers the 6.1.162 profiles (4K and 16K), the 6.6.127
Pixel 10 profile, upstream's 6.6/6.12 vendor profiles for other devices, and
two dirty vendor profiles, all imported from `rikumi/TimerRoot`.

The binary is not committed (`assets/timer` is gitignored). Build it and drop it
in place, or use **Download exploit**, which fetches the release asset,
extracts the confs from the APK, and installs it directly:

```
installed 2106912 bytes, 10 confs (uid=2000)
target=lynx
device=lynx
kernel=6.1.162-android14-11-g9dd05ae3a1de-ab16261587
pagesize=4096
profile=6.1.162-android14-11-g9dd05ae3a1de-ab16261587.conf
conf=/data/local/tmp/timer-conf/6.1.162-android14-11-g9dd05ae3a1de-ab16261587.conf
timer_site=0xffffffc008192f7c
protocol=2
TIMER_PROTOCOL=2
```

On a Pixel 10 the same `target=lynx` check passes and the kernel line reports
`6.6.127-android15-8-g91d825611104-ab16252310-4k`.

After installing, the app always runs `timer target` and refuses any binary
whose `target=` line does not match `target=lynx`.

The port derives every constant from the factory `boot.img` of that build
(kallsyms + BTF), so re-derive them before using it on a different kernel.
Adding a kernel means adding one `conf/*.conf`; the source does not change.

The binary is MIT licensed by its authors; only use it on hardware you own, and
only when your kernel matches the build it was ported to.

## Supported devices

The exploit is tied to a kernel build, not to a device name. One binary serves
every profile below; the app selects the `conf/*.conf` that matches the running
kernel release and userspace page size, and refuses to run when nothing
matches.

### 6.1.162 (4K and 16K)

`6.1.162-android14-11-g9dd05ae3a1de-ab16261587`, the GKI kernel shipped in the
`CP3A.261005.002.A1` and `CP3A.261005.005` factory images. Every device in this
table ships that exact kernel payload.

**Only the Pixel 7a and Pixel 9a have actually been run on hardware.**
Everything else in this table ships the same kernel and is expected to work,
but has not been run, so treat it as untested.

| Device | Codename | Factory build | Status |
|---|---|---|---|
| Pixel 6 | `oriole` | `CP3A.261005.002.A1` | untested |
| Pixel 6 Pro | `raven` | `CP3A.261005.002.A1` | untested |
| Pixel 6a | `bluejay` | `CP3A.261005.002.A1` | untested |
| Pixel 7 | `panther` | `CP3A.261005.002.A1` | untested |
| Pixel 7 Pro | `cheetah` | `CP3A.261005.002.A1` | untested |
| **Pixel 7a** | `lynx` | `CP3A.261005.002.A1` | **tested** |
| Pixel Fold | `felix` | `CP3A.261005.002.A1` | untested |
| Pixel Tablet | `tangorpro` | `CP3A.261005.002.A1` | untested |
| Pixel 8 | `shiba` | `CP3A.261005.005` | untested |
| Pixel 8 Pro | `husky` | `CP3A.261005.005` | untested |
| Pixel 8a | `akita` | `CP3A.261005.005` | untested |
| Pixel 9 | `tokay` | `CP3A.261005.005` | untested |
| Pixel 9 Pro | `caiman` | `CP3A.261005.005` | untested |
| Pixel 9 Pro XL | `komodo` | `CP3A.261005.005` | untested |
| Pixel 9 Pro Fold | `comet` | `CP3A.261005.005` | untested |
| **Pixel 9a** | `tegu` | `CP3A.261005.005` | **tested** |
| Pixel 10a | `stallion` | `CP3A.261005.005` | untested |

Every factory image in this table contains the same kernel payload: the 4K
`boot.img` kernel is byte-identical (16,637,222 bytes) across all 17 devices,
so this is the same binary, not merely the same version string.

Devices whose factory image also ships a `kernel_16k` (Pixel 8, 8 Pro, 8a, 9,
9 Pro, 9 Pro XL, 9a and 10a) can boot the 16K-page build of that same kernel.
Those images are byte-identical too, and share the 4K kernel's release string,
so they have a separate profile:
`conf/6.1.162-android14-11-g9dd05ae3a1de-ab16261587-16k.conf`. The app picks it
by `sysconf(_SC_PAGESIZE)`; the 4K build uses the profile without the `-16k`
suffix. The Pixel 9a 16K image was verified end-to-end in QEMU as well
(`timer verify` and `timer fake`).

### 6.6.127 (4K)

`6.6.127-android15-8-g91d825611104-ab16252310-4k`, shipped by the Pixel 10
series in the same `CP3A.261005.005` build number. The profile is
`conf/6.6.127-android15-8-g91d825611104-ab16252310-4k.conf`:

| Device | Codename | Status |
|---|---|---|
| **Pixel 10** | `frankel` | **verified in QEMU** |
| **Pixel 10 Pro** | `blazer` | **verified in QEMU** |
| **Pixel 10 Pro XL** | `mustang` | **verified in QEMU** |
| **Pixel 10 Pro Fold** | `rango` | **verified in QEMU** |

All four factory images contain a byte-identical kernel payload (36,866,560
bytes, SHA-256 `0226c3be4224b02884d4f9b332aee58ec06c65b2263265e80f2498332ef15c06`),
so one profile covers all of them. The 6.6 profile was verified end-to-end
(`timer verify` and `timer fake`) in a QEMU VM booting the factory kernel; it
has not been flashed on physical Pixel 10 hardware yet.

If your device is not in these tables, or its status is untested, check the
`kernel=` line first (the app runs `timer --conf ... target` and logs it), and
compare it with the conf you intend to use. Do not run the exploit on a kernel
that does not match. A device with no matching conf is refused instead of
falling back to another profile.

## Build

### Android Studio / Gradle

Open the project and build, or:

```bash
./gradlew assembleDebug
```

The project needs the Android SDK with platform 36 and build-tools 36. The
Shizuku API is pulled from Maven (`dev.rikka.shizuku:api`). The build copies
the repository's `conf/` into the APK as `assets/conf/`; no separate step is
needed.

### Without Gradle

`scripts/build.ps1` builds and signs an APK with just the SDK, `javac`, `d8`,
`aapt2` and `apksigner`. It vendors nothing: it compiles the app together with
the Shizuku API sources, so clone those first:

```powershell
git clone https://github.com/RikkaApps/Shizuku-API
scripts/build.ps1 -Sdk "C:\Users\<you>\AppData\Local\Android\Sdk"
```

## Usage

### 1. Start Shizuku

Shizuku has to be running before TimerRoot can do anything: it is the process
that provides the shell user the exploit needs. Shizuku stops on every reboot,
so this is the first step each time.

**Wireless debugging (no PC after the first pairing)**

1. Enable developer options: Settings -> About device -> tap *Build number* 7x.
2. Settings -> System -> Developer options -> **Wireless debugging** -> on.
3. Open the Shizuku app -> **Start** -> *Start via wireless debugging*.
4. Allow the notification, then in *Pair device with pairing code* enter the
   6-digit code shown on the phone.
5. Shizuku reports "Shizuku is running" (the notification says the server is up).

**Over USB**

With the phone connected and USB debugging authorised:

```bash
adb shell sh /sdcard/Android/data/moe.shizuku.privileged.api/start.sh
```

Newer Shizuku releases may not ship that script any more; if it is missing, use
the wireless debugging route above.

Check that the server is up:

```bash
adb shell ps -A | grep shizuku_server
# shell  12345  1  ...  shizuku_server
```

`ps` showing only `moe.shizuku.privileged.api` means the manager app is open but
the server is **not** running; the exploit cannot start until it is.

### 2. First launch

1. Open TimerRoot.
2. When Shizuku asks *Allow TimerRoot to access Shizuku?*, choose
   **Allow all the time**.
3. The card turns **Ready** (Shizuku connected, no root yet). If it still says
   `Not connected`, press `Shizuku` in the tools row to request again.

### 3. Install the binary

Press **Download exploit** to fetch the release asset, or `Prepare` to extract a
binary you built into `app/src/main/assets/timer`. Either path installs it to
`/data/local/tmp/timer`, unpacks the bundled confs to
`/data/local/tmp/timer-conf`, and then checks the target. **Download exploit**
publishes the confs from the APK before installing the downloaded binary;
**Prepare** installs both from the APK:

```
installed 2106912 bytes, 10 confs (uid=2000)
target=lynx
device=lynx
kernel=6.1.162-android14-11-g9dd05ae3a1de-ab16261587
pagesize=4096
profile=6.1.162-android14-11-g9dd05ae3a1de-ab16261587.conf
conf=/data/local/tmp/timer-conf/6.1.162-android14-11-g9dd05ae3a1de-ab16261587.conf
timer_site=0xffffffc008192f7c
protocol=2
TIMER_PROTOCOL=2
```

`timer target` loads and validates the conf as well, so a mismatch (release,
page size, missing field) is reported there before any trigger runs.

`Diagnose` runs `timer ids`, which only probes the tracefs page event ids and
never touches the timer queue.

### 4. Get root shell

One tap. The app escalates, keeps a `uid=0` shell inside the service, and then
starts the KernelSU late-load automatically:

```
[child] woke uid=0
root shell ready - loading KernelSU...
Loading KernelSU... 12s
KSU_LOADED
```

The card goes **Root shell** -> **Jailbreak mode** (`u:r:ksu:s0`). The loader
finds the installed manager's `libksud.so` and loads that manager's module.
Known package names (`me.weishu.kernelsu`, `com.rifsxd.ksunext`,
`com.sukisu.ultra`) are tried first, then any package available to user 0 that
ships `libksud.so`. Repackaged managers with randomized package names are
supported, including builds that rename `libksud.so` to an unrelated `.so`
(it is identified by size and the `late-load` marker). The loader then compares
the manager's uapi version with the module the kernel reports (`ksud debug
info`). If a module from an earlier run is still loaded and its uapi does not
match, it prints `KSU_STALE` instead of pretending success: a kernel module
cannot be replaced without a reboot, and a mismatch is exactly what makes the
manager show `not installed` (for example KernelSU-Next's uapi 5 module with
SukiSU Ultra's uapi 6 manager). If the KernelSU stage loses its race, the card
turns red with `KernelSU failed`, and you should reboot before retrying.

KernelSU re-enables SELinux about half a second after it loads, so the app
immediately retries `su -c setenforce 0` (over ~12s) and confirms with
`getenforce`. A successful run therefore ends on `SELinux: Permissive`.

### 5. Reboot

Use the `Reboot` pill. It goes through the service (`svc power reboot`), so it
works even when no root shell is open yet. Rebooting is also the only clean way
to remove parked processes and to unload KernelSU.

After rebooting, TimerRoot can repeat the whole chain by itself: Shizuku is
stopped and KernelSU is gone, but the auto-root service starts Shizuku over a
localhost ADB channel while the device is still at the lock screen, binds it at
BFU and runs the exploit once per real boot.

### 6. Auto-root on boot

1. Get a root shell once (step 4).
2. Press **Install channel**. It runs `timer permissive` (clears the kernel's
   SELinux flag through the exploit), opens a root shell and appends
   `persist.adb.tcp.port=5555` to `/data/property/persistent_properties`, so
   adbd listens on localhost at every boot even with Wi-Fi off. It also
   disables the 7-day ADB key expiry. KernelSU is not required for this step.
3. Reboot. The first localhost connection shows the normal *Allow USB
   debugging?* dialog; tap **Always allow**. The key is then in `adb_keys`, so
   later boots use signature auth with no UI.

From then on a foreground service runs on every real boot.
`LOCKED_BOOT_COMPLETED` (seconds after the kernel starts) starts Shizuku over
`127.0.0.1:5555` and runs the exploit right away, before the user unlocks. This
works because TimerRoot's Shizuku provider is `directBootAware`: when
`shizuku_server` starts it hands its binder to every app that declares
`API_V23`, and with a direct-boot-aware provider that delivery also works while
credential-encrypted storage is still locked. If the binder does not arrive,
`BOOT_COMPLETED` retries after unlock; the per-boot guard still allows only one
exploit run. The service stays in the foreground to keep the root shell alive.
**Run auto-root now** repeats it on demand; the history is under
**Auto-root log**.

After the root shell is up, the boot path continues on its own: it runs
`timer fake` (the same endgame as **Load KernelSU** in step 4), which
late-loads the installed manager's module and clears the kernel's SELinux flag
in the same plant. The loader usually finishes within ~20 s of the exploit and
the notification changes to **Jailbreak mode ready**:

```
17:57:07  root shell ready; loading KernelSU
17:57:27  KernelSU attempt 2: the exploit parked before loading ksud
17:57:46  KernelSU active: selinux=Permissive (after 1s)
17:57:46  success: root shell ready; KernelSU active (selinux=Permissive (after 1s))
```

The plant is a race, so the stage is replanted up to three times; a missed
burst parks a process and leaves the boot usable, which is exactly what the
exploit itself does for `shell` and `permissive`. The last line is the result
stored in the auto-root log: `KernelSU active` means `/system/bin/su -c id`
reported `u:r:ksu:s0` and `getenforce` stayed `Permissive`. If the manager is
missing (or its module is incompatible) the root shell is kept and the
notification says `Root shell ready` with the KernelSU reason instead.

### Boot status screen

**Boot screen** (on by default) shows a full-screen status page over the lock
screen while the boot path runs, so the progress is visible before the first
unlock. It renders its own animated background, or a still image slideshow, or
a muted looping video, with a spinner that turns into a green check on success
and a red cross on failure. The page also shows how long the current stage has
been running and has **Hide** and **Open TimerRoot** buttons; **Hide** only
closes the page (it will not pop back for the rest of that boot), and once the
device is unlocked and the run has finished the page closes itself after a few
seconds.

Android only lets an app put an activity over the keyguard in two sanctioned
ways:

- **Allow overlay** (`SYSTEM_ALERT_WINDOW`, *Display over other apps*), which
  is also the background-activity-launch exemption; or
- a notification with a **full-screen intent** (`USE_FULL_SCREEN_INTENT`),
  which needs the *full-screen notifications* special access on Android 14+
  (**Full-screen** opens that settings page).

The status activity is used opportunistically when overlay access exists, and
the foreground notification carries a full-screen intent as the primary path.
Without either permission the normal progress notification is still shown, and
auto-root is unaffected.

Both special accesses are app-ops, so the boot path grants them from its own
uid-0 shell after the root shell is ready (`appops set ... allow`); the
buttons exist for the very first run and for devices where the user revoked
them. After the first root they stay granted.

**Background** picks an image or video from the document picker and copies it
into device-protected storage (`files/bootui/background.image0` or
`background.video`), because normal app files are not readable before the
first unlock. **Clear** removes it and returns to the animated background.
**Preview** opens the same screen immediately, without waiting for a boot.

This is a status screen, not a replacement for the system boot animation:
`/system/media/bootanimation.zip` is on a read-only partition and AOSP's
boot animation no longer reads `/data/local`. The page appears as soon as
TimerRoot's own process starts, which is after `LOCKED_BOOT_COMPLETED`, and it
never blocks the keyguard: **Hide** returns to the lock screen so a PIN or
pattern can be entered (biometric unlock works without hiding), and after a
terminal state on an unlocked device the page closes itself.

BFU is a normal operating point, not a fallback. A password-protected device
does not need to be unlocked first: the exploit runs at the lock screen and the
root shell is already waiting when you unlock. KernelSU is loaded at the same
point, so SukiSU/SukiSU Ultra and friends report an initialised manager as soon
as you unlock and open them.

Without the channel, auto-root still works when Shizuku is already running
(for example started by hand over Wi-Fi).

The status card reflects what is actually live, detected by running
`su -c id` and checking for `u:r:ksu:s0`:

| card | meaning |
|---|---|
| Not connected | Shizuku is not running / not bound |
| Ready | Shizuku connected, no root yet |
| Root shell | `uid=0`, `u:r:shell:s0` |
| Jailbreak mode | KernelSU loaded, `su` works in `u:r:ksu:s0` |


## Safety

This is a kernel exploit. Read this before pressing anything.

- **Do not kill a parked process.** The exploit keeps a process alive with the
  fake credential page pinned in socket buffers. Reaping it can panic the
  kernel. Reboot is the only clean way to remove it.
- **A reboot clears everything**: KernelSU, the root shell and the parked
  processes. That is the intended way to stop.
- **SELinux is left permissive** until the next reboot.
- A failed attempt leaves a stale timerqueue node; other apps may crash until
  you reboot.
- Only use this on a device you own or are explicitly allowed to modify.

## Layout

```
app/src/main/java/com/kpgc/timerroot/MainActivity.java        UI and state
app/src/main/java/com/kpgc/timerroot/UserService.java         runs as the shell user
app/src/main/java/com/kpgc/timerroot/AutoRootService.java     boot-time state machine
app/src/main/java/com/kpgc/timerroot/BootStatusActivity.java  BFU status screen
app/src/main/java/com/kpgc/timerroot/AutoRoot.java            guards, key and log
app/src/main/java/com/kpgc/timerroot/AdbLocal.java            minimal localhost ADB client
app/src/main/java/com/kpgc/timerroot/AdbKey.java              RSA key generation
app/src/main/java/com/kpgc/timerroot/BootReceiver.java        BOOT_COMPLETED entry point
app/src/main/java/com/kpgc/timerroot/RestartJobService.java   binder-push restart
app/src/main/aidl/com/kpgc/timerroot/IUserService.aidl        service interface
app/src/main/assets/timer                                     exploit binary (not in git)
conf/*.conf                                                   per-kernel HOCON profiles
conf/dirty/*.conf                                             profiles with an identity check
p7a/timer_p7a.c                                               exploit source (conf-driven)
app/build.gradle                                              packages conf/ as assets/conf/
scripts/build.ps1                                             Gradle-free build
docs/auto-root.md                                             research and field notes
```

## Credits

- Exploit: [YuKongA/CVE-2026-98260](https://github.com/YuKongA/CVE-2026-98260)
  (MIT), based on work by woshigenm and the other 98260 ports.
- [Shizuku](https://github.com/RikkaApps/Shizuku) and
  [Shizuku-API](https://github.com/RikkaApps/Shizuku-API) (Apache-2.0) by Rikka.
- KernelSU (GPL-2.0), KernelSU-Next, and SukiSU Ultra for the late-load path.
- [rikumi/TimerRoot](https://github.com/rikumi/TimerRoot): the HOCON
  conf-driven profile mechanism, runtime conf selection (release, page size and
  dirty-device identity checks), and the vendor profiles under `conf/` were
  ported from this project.
- Original repository that this fork based on: [kpgc10kai/TimerRoot](https://github.com/kpgc10kai/TimerRoot)

## License

MIT for the app code in this repository. The exploit binary and the Shizuku API
keep their own licenses.
