# Installation and usage

Everything the app needs to run, every screen and action it exposes, and the
boot automation. For the project overview see the [README](../README.md);
for toolchains and signing see [Building](building.md); for kernel/profile
coverage see [Supported devices](supported-devices.md).

> **Research use only.** Use TimerRoot only on hardware you own or are
> explicitly allowed to modify.

## Prerequisites

- **Android 12 or newer** (`minSdk 30`) on **arm64**. The exploit is arm64-only.
- **A supported kernel** with a matching profile in `conf/`. The app never
  falls back to a different profile: no match means it refuses to run. Check
  with `uname -r`, `getprop ro.product.device` and `getconf PAGESIZE`, then see
  [Supported devices](supported-devices.md).
- **[Shizuku](https://shizuku.rikka.app/) running.** TimerRoot runs as
  `untrusted_app` and cannot read `/sys/kernel/tracing`, so the exploit runs in
  a Shizuku user service as the shell user (`uid 2000`, `u:r:shell:s0`).
- **A KernelSU manager for the late-load**, unless you only want the temporary
  root shell:
  - Generic mode: [KernelSU](https://github.com/tiann/KernelSU),
    [KernelSU-Next](https://github.com/rifsxd/KernelSU-Next) or
    [SukiSU Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra).Others not guaranteed to work.
  - Samsung mode: the [diabl0w/KernelSU](https://github.com/diabl0w/KernelSU)
    Samsung build only (manager version starts with `samsung-v`). Other
    managers are rejected.
- **A settled device.** Wait **2-3 minutes after the first login following a
  boot** before running the exploit. Startup work competes for RAM, swap and
  CPU, and that shrinks the race window the exploit depends on.
- **USB debugging left on** if you plan to use auto-root. The boot channel
  needs `adbd` to start by itself; see [Auto-root](#auto-root).

## 1. Install the app

Install the APK from the
[releases page](https://github.com/MVN123123123123123/TimerRoot/releases), or
build it yourself with [Building](building.md). The release tag also carries
the matching `timer` exploit binary and the app's source snapshot.

Android will refuse to update an existing install signed with a different key.
Use the same signing key for later builds, or uninstall the old app first.

## 2. Start Shizuku

Shizuku stops on every reboot, so this is step one each time.

1. Open the **Shizuku** app.
2. Choose **Start via wireless debugging** and pair with the code shown.
3. Open **TimerRoot** and allow Shizuku access (**Allow all the time**).
   The status card turns **Ready**.

If the card stays **Not connected**, press **Shizuku** under *Tools* on the
Home tab, or **Check & grant access** in Settings. That logs the binder and
permission state, requests the permission if needed, and binds the user
service.

## 3. Install the exploit binary
Install it from the app after Shizuku is connected, under **Settings -> Exploit**:

- **Download exploit** fetches the prebuilt `timer` from the release asset,
  downloads it over HTTP, extracts the per-kernel profiles from the APK, and
  installs everything. This is the normal path for release users.
- **Prepare binary** installs the copy bundled inside the APK
  (`app/src/main/assets/timer`). It only works when the APK was built with a
  binary in place; it is the path for local builds.

Both actions:

1. copy the binary to `/data/local/tmp/timer` (mode `0755`);
2. extract `assets/conf/**.conf` to `/data/local/tmp/timer-conf`;
3. run `timer target`.

A binary whose target check fails is rejected before anything touches the
kernel.

### Exploit binary and profiles

The exploit is tied to a kernel **build**, not a device name. The timer call
site, `cred` layout and `task_struct` offsets differ per build, and a binary
built for another kernel corrupts the kernel instead of failing safely. One
binary serves every profile in this repository: every kernel-specific constant
lives in a HOCON file under `conf/`, and the app picks the file at runtime:

- `release` must equal `uname -r`. A trailing `-4k` is optional on both sides,
  so `...-ab16252310` and `...-ab16252310-4k` are the same kernel.
- When the profile sets `page_size`, `sysconf(_SC_PAGESIZE)` must match too.
  This is how the 4K and 16K builds of 6.1.162 are told apart; they share a
  release string.
- Profiles under `conf/dirty/` have a release string that is not unique to one
  vendor build (`-maybe-dirty`), so `device_model`, `android_release` and
  (when present) `sdk_int` must also match the device.
- Samsung profiles use `release_prefix` under `conf/samsung/` and are only
  scanned in Samsung mode. The prefix is matched at `-` boundaries.

`UserService` extracts the confs, chooses the first match, and runs:

```
/data/local/tmp/timer --conf /data/local/tmp/timer-conf/<match>.conf shell
```

`--conf` is mandatory. You can also pass it to a manually built binary, which
is useful for probing a profile from `adb shell`:

```bash
timer --conf conf/6.1.162-android14-11-g9dd05ae3a1de-ab16261587.conf target
```

The app also passes `--protocol 3`, the app/binary interface version:

- An old app that starts the new binary without `--conf`/`--protocol` gets a
  refusal: `OLD_APP_DETECTED app_protocol=0 required=3`. Update the app and
  install the exploit again.
- An old binary left in `/data/local/tmp` from before the conf rewrite is
  detected by scanning for the literal `TIMER_PROTOCOL=2` marker, without
  executing it, and refused. Press **Download exploit** (or **Prepare**) again.
- Manual `--conf <file>` runs are still allowed without `--protocol` for
  debugging.

`timer --conf <profile> target` prints the selected release, page size, profile
and call-site address, for example:

```
target=lynx
device=lynx
kernel=6.1.162-android14-11-g9dd05ae3a1de-ab16261587
pagesize=4096
profile=6.1.162-android14-11-g9dd05ae3a1de-ab16261587.conf
conf=/data/local/tmp/timer-conf/6.1.162-android14-11-g9dd05ae3a1de-ab16261587.conf
timer_site=0xffffffc008192f7c
```

`timer --conf <profile> selfcheck` re-checks the profile's internal invariants
without touching the kernel and exits non-zero on failure, so it is safe to
script. `PORT_LOG.md` records the derivation of every bundled profile.

Adding a kernel means adding one `conf/*.conf`; the source does not change.The
per-profile evidence is in [PORT_LOG.md](../PORT_LOG.md).

## 4. Get root

1. Open TimerRoot with Shizuku connected.
2. Press **Get root shell** and confirm.
3. The app escalates to a `uid=0` shell in the shell domain, keeps it open,
   late-loads KernelSU, and retries `setenforce 0`. Success ends on
   `SELinux: Permissive`; the card shows **Jailbreak mode**.
4. **Reboot** when finished (**Settings -> Reboot device**). It is the only
   clean way to remove parked processes and unload KernelSU.

On Samsung devices, **Get root shell** runs the combined DEFEX/KDP chain
instead; there is no separate KernelSU step. See [Samsung mode](#samsung-mode).

If the KernelSU stage loses its race, the card turns red with
`KernelSU failed`; reboot before retrying. A stale or mismatched module is
reported as `KSU_STALE` instead of pretending success.

## 5. The app, screen by screen

### Home

The status card is derived from `su -c id` and the Shizuku binder:

| Card | Meaning |
|---|---|
| Not connected | Shizuku is not running or not bound |
| Ready | Shizuku connected, no root yet |
| Root shell | `uid=0`, `u:r:shell:s0` |
| Jailbreak mode | KernelSU loaded, `su` works in `u:r:ksu:s0` |

**Actions**

- **Get root shell** runs the exploit once and keeps a root shell open.
  Samsung mode runs the DEFEX/KDP chain instead.
- **Load KernelSU** late-loads a manager module through the fake credential.
  It needs an existing root shell and is unavailable in Samsung mode, where the
  main chain already loads the bundled `ksud`.
- **Stop root** closes the root shell TimerRoot is holding. It does not unload
  KernelSU and does not clean up parked exploit processes; reboot for that.

**Device** rows show the effective mode (generic or Samsung), model, running
kernel, `ksud` state, KernelSU state, SELinux mode and seccomp filter mode.

**Tools**

- **Shizuku** logs `running`, `permission`, `pre-v11` and `bound`, requests the
  permission when needed, and binds the service.
- **Diagnose** runs the exploit's `ids` mode, which probes tracefs page event
  ids without arming a timer; it is safe to run repeatedly.

### Log

The Log tab collects app and shell-service activity, including the app/binary
protocol checks, install output, `timer target`, exploit output and
auto-root/restart decisions. **Copy** puts the buffer on the clipboard;
**Clear** empties it.

### Settings

**Shizuku**

- **Check & grant access** — the same check as the Home tool.

**Exploit**

- **Prepare binary** — install the copy bundled in the APK.
- **Download exploit** — fetch the latest release binary and install it with
  the confs.

**Device mode**

- **Samsung mode** — force the Samsung DEFEX/KDP chain on or off.
- **Use automatic detection** — clear the override; Samsung devices select it
  automatically from `Build.MANUFACTURER` / `Build.BRAND`.

**Auto-root**

- **Auto-root** — run the exploit once per real boot.
- **Run now** — run the boot sequence immediately. Do not use it if the
  exploit already ran this boot.
- **Install channel** — one-time persistent localhost ADB setup (see below).
- **View auto-root log** — open the rotating auto-root history in the Log tab.

**Boot screen**

- **Boot status screen** — show progress over the lock screen.
- **Background** — pick an image or video; it is copied into device-protected
  storage so it is available before unlock.
- **Preview** — open the status page now.
- **Allow overlay** / **Full-screen** — grant the two background-activity
  exemptions. Without either, the ordinary progress notification remains.
- **Clear background** — remove the saved image/video.

**Restart**

- **Auto soft restart** — after a successful KernelSU load, restart the Android
  userspace so modules and Zygisk start.
- **Restart Android** — request that userspace restart on demand.
- **Reboot device** — a real reboot; the clean way to unload KernelSU and clear
  parked processes.

**Updates**

- **Check for updates** — check GitHub at most once a day.
- **Check now** — check immediately.
- **Open releases** — open the releases page. The app never installs an APK
  by itself.

## Auto-root

The first root cannot be automatic: an app cannot obtain the shell user without
either root or an ADB key already authorized on the device. Every boot after a
successful one-time setup can be automatic. The design and field notes are in
[Auto-root research](auto-root.md).

### One-time setup

1. Root once (either generic or Samsung mode).
2. Press **Install channel** in **Settings -> Auto-root**. This must run while
   the app holds a root shell; the button uses it, or KernelSU's `su` when a
   module is already loaded.
3. Enable **Auto-root**.
4. Reboot. If Android shows **Allow USB debugging?** on the first connection,
   tap **Always allow** once.

**Install channel** sets up a persistent localhost ADB channel:

- writes `persist.adb.tcp.port 5555` into
  `/data/property/persistent_properties` (Android 17 ignores the legacy
  per-name property files);
- sets `adb_allowed_connection_time 0` so the key does not expire;
- appends TimerRoot's own public key to `/data/misc/adb/adb_keys` when it can;
- grants the app its overlay and full-screen-intent app-ops.

When KernelSU is already active, the key write runs through `su` (uid 0 with
full capabilities) and needs no dialog. From the exploit's shell-domain root
shell, `adb_keys` is `0640 system:shell` and that shell has no
`CAP_DAC_OVERRIDE`, so the app reports `KEY_LOCKED` and one **Always allow**
tap is still needed for the first connection.

Without the channel, auto-root can still work when Shizuku starts on its own
(its own boot path or root mode) and can reach its server over Wi-Fi.

### On every boot

A `directBootAware` receiver handles `LOCKED_BOOT_COMPLETED`, starts the
`specialUse` foreground service, and the service:

1. claims the boot id, so `LOCKED_BOOT_COMPLETED` + `BOOT_COMPLETED`, retries,
   and a second service start cannot run the exploit twice;
2. reuses or starts `shizuku_server` over `127.0.0.1:5555`;
3. waits for the Shizuku binder, checks the permission and binds the user
   service;
4. installs the bundled asset if needed, requires `target=lynx`, and runs
   `timer shell`;
5. runs `timer fake` (late-loads KernelSU and clears enforcing), replanting up
   to three times on a missed race;
6. verifies `su -c id` reports `u:r:ksu:s0`, re-applies `setenforce 0`, and
   optionally performs the userspace soft restart.

`BOOT_COMPLETED` is only a retry for a failure that happened before the
exploit started; after a successful locked-boot run it is ignored. The service
stays alive after success so the root shell survives, and the notification
reports running / done / needs attention. A userspace restart re-sends both
broadcasts; the receiver detects the same boot id, only starts Shizuku, and
republishes the last result instead of re-running the exploit.

The optional **Boot screen** shows the stage and elapsed time over the lock
screen, with **Hide** and **Turn off** actions. It appears when TimerRoot's
process starts at boot, not during the kernel/init boot animation, and it never
blocks unlocking. Full-screen intent is the primary path; overlay permission is
opportunistic.

### Limits and recovery

- **The exploit is one-shot per boot.** A missed burst can park a process;
  reboot before retrying. The service stops after a parked exploit, `KSU_STALE`
  or a missing manager, and does not loop.
- **USB debugging must stay on** in the channel design; that is what makes
  `adbd` start at boot. Turning it off kills the channel.
- **Unlocking may still be needed** if the boot path cannot get the Shizuku
  binder before unlock; `BOOT_COMPLETED` retries after unlock. The boot screen
  itself never requires unlocking.
- **Root never survives a reboot.** Auto-root re-runs the exploit each boot; it
  does not install a permanent `su`.
- **`/data/local/tmp/timer.log` persists across boots.** The app timestamps and
  clears the run before matching a result.
- Use **View auto-root log** to see the boot decisions, prestart retries,
  stage changes and failure reason.

## Samsung mode

Samsung mode is selected automatically when `Build.MANUFACTURER` or
`Build.BRAND` is `samsung`, and can be forced under **Settings -> Device mode**.
It uses `conf/samsung/*.conf`, runs the unified `fake` chain (`--samsung`),
clears the child's DEFEX `creds_fast_hash` slot, moves the worker to
`u:r:init:s0`, bind-mounts the bundled diabl0w/KernelSU `assets/samsung/libksud.so`
over `/system/bin/logcat` (KDP-safe), and leaves SELinux to `ksud`'s own
restore. There is no generic manager discovery and no second late-load stage.

Requirements:

- a matching Samsung profile (see [Supported devices](supported-devices.md#samsung));
- the [diabl0w/KernelSU](https://github.com/diabl0w/KernelSU) Samsung build.
  The app identifies it by the manager `versionName` prefix (`samsung-v*`).
  Upstream KernelSU with the same package name, KernelSU-Next and SukiSU Ultra
  are rejected rather than late-loading a mismatched module;
- the bundled `ksud` shipped as `assets/samsung/libksud.so`.

**Get root shell** runs the whole chain and **Load KernelSU** is not used. An
unsupported Samsung kernel is refused with a message to turn Samsung mode off
and use a generic profile. The app also refuses a binary that does not carry
the `TIMER_SAMSUNG=1` marker instead of passing `--samsung` to an old build.

## Soft restart, reboot and cleanup

- **Restart Android** performs a userspace soft restart, like KernelSU's *soft
  reboot*: reset `sys.boot_completed`, run the restart stages, stop/start, and
  replay `post-fs-data` / `services` / `boot-completed`. The kernel stays up,
  KernelSU stays loaded and parked exploit processes stay parked. It takes
  about a minute and closes every app. It needs KernelSU 3.x for the
  `ksud soft-reboot` subcommand.
- **Reboot device** is a real boot. It is the only clean way to unload
  KernelSU, clear parked processes and return SELinux to enforcing.

## Safety

- **Do not kill a parked process.** The exploit keeps a process alive with the
  fake credential page pinned in socket buffers. Reaping it can panic the
  kernel.
- **A reboot clears everything**: KernelSU, the root shell and parked
  processes.
- **A soft restart is not a reboot**: the kernel stays up, KernelSU stays
  loaded and parked processes stay parked.
- SELinux is left permissive until the next reboot.
- A failed attempt can leave a stale timerqueue node; other apps may crash
  until you reboot.
- Only use this on a device you own or are explicitly allowed to modify.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Card stays **Not connected** | Shizuku stopped or permission denied | Start Shizuku, then **Shizuku** / **Check & grant access** and allow access |
| App refuses to run / no profile | No `conf/` matches `uname -r` and page size | Check `uname -r`, `getconf PAGESIZE`; add a profile (see [Supported devices](supported-devices.md), [SKILL.md](../SKILL.md)) |
| **Prepare binary** does nothing useful | APK has no bundled `assets/timer` | Use **Download exploit**, or build the binary and rebuild the app |
| `rejected: ... not built for this kernel` | Installed binary or profile does not match | Install the correct binary/profile again; do not bypass the target check |
| `OLD_APP_DETECTED app_protocol=0 required=3` | App is older than the binary | Update the app and install the exploit again |
| `installed timer is too old for this app` | Old binary survived an app update | Press **Download exploit** (or **Prepare**) again |
| **Root failed** | The exploit lost its race or parked | Reboot and retry once after the device settles |
| **KernelSU failed** | Late-load race, trigger missed, or SELinux stage missed | Reboot before retrying; check the `[ksu]` lines in the Log tab |
| `KSU_STALE` | A stale or mismatched module is loaded | Reboot; use a manager matching the profile's `ksu_kmi` |
| `KSU_MISSING` | No supported manager, or wrong KMI | Install a supported manager for this kernel and retry |
| Auto-root does not run | Disabled, channel missing, USB debugging off, or no permission/binder | Enable **Auto-root**, run **Install channel**, keep USB debugging on, check **View auto-root log** |
| Auto-root asks for **Allow USB debugging?** | First connection with a new key | Tap **Always allow** once |
| `KEY_LOCKED` | Shell-domain root cannot write `adb_keys` | Tap **Always allow** once, or install the channel while KernelSU `su` is active |
| Boot screen does not appear | Neither overlay nor full-screen access granted | Grant **Allow overlay** or **Full-screen**; the notification is the fallback |
| Other apps crash after a failed attempt | Stale timerqueue node or parked process | Reboot; do not retry on the dirty device |
