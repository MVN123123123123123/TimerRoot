# TimerRoot

**Research use only.** Use it only on hardware you own or are explicitly allowed to modify.

> **Wait 2-3 minutes after the first login following a boot** before running the exploit. Background startup work competes for RAM, swap and CPU, which the exploit depends on.
>
> To root automatically, install Shizuku and run TimerRoot once by hand first.

Android app for **CVE-2026-98260** (POSIX CPU timer use-after-free). One tap gives a root shell in the shell domain, then late-loads **KernelSU** (`u:r:ksu:s0`).

The exploit is in `p7a/timer_p7a.c` and is conf-driven: every kernel-specific constant lives in a HOCON profile under `conf/`, selected at runtime from `uname -r` and the userspace page size. This repository is the app shell around it: UI, state detection and the Shizuku plumbing needed to run a shell-domain exploit from an ordinary app.

## Requirements

- Android 12+ (`minSdk 30`), arm64.
- [Shizuku](https://shizuku.rikka.app/) running. Apps run as `untrusted_app` and cannot read `/sys/kernel/tracing`, so the exploit runs inside a Shizuku user service as the shell user (`uid 2000`, `u:r:shell:s0`).
- A supported kernel: there must be a matching `conf/*.conf`. No match means the app refuses to run; it never falls back to another profile.
- A manager for the generic late-load: [KernelSU](https://github.com/tiann/KernelSU), [KernelSU-Next](https://github.com/rifsxd/KernelSU-Next) or [SukiSU Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra). Samsung mode instead requires the [diabl0w/KernelSU](https://github.com/diabl0w/KernelSU) Samsung build.

## Quick start

1. **Start Shizuku.** It stops on every reboot, so this is step one each time: open the Shizuku app -> **Start** -> *Start via wireless debugging*, then pair with the code shown. Older releases over USB: `adb shell sh /sdcard/Android/data/moe.shizuku.privileged.api/start.sh`.
2. **Open TimerRoot** and allow Shizuku access (**Allow all the time**). The card turns **Ready**. If it stays `Not connected`, press **Shizuku** under *Tools*, or **Check & grant access** in Settings.
3. **Install the exploit.** Settings -> *Exploit* -> **Download exploit** (fetches the release asset) or **Prepare binary** (uses a locally built `app/src/main/assets/timer`). Both install `/data/local/tmp/timer`, unpack the confs to `/data/local/tmp/timer-conf`, and run `timer target` to verify the kernel.
4. **Get root.** One tap. The app escalates, keeps a `uid=0` shell, late-loads KernelSU, and retries `setenforce 0`. Success ends on `SELinux: Permissive`; the card shows **Jailbreak mode**.
5. **Reboot** when finished (Settings -> **Reboot device**). It is the only clean way to remove parked processes and unload KernelSU.

The exploit binary is not committed (`assets/timer` is gitignored). See [docs/supported-devices.md](docs/supported-devices.md#getting-the-exploit-binary) for conf matching, the app/binary protocol, and `timer target` / `selfcheck` output.

If the KernelSU stage loses its race, the card turns red with `KernelSU failed`. Reboot before retrying. A stale or mismatched module is reported as `KSU_STALE` instead of pretending success.

## Auto-root on boot

Root once, press **Install channel**, reboot, and tap **Always allow** on the one-time ADB key dialog. From then on a foreground service starts Shizuku over localhost ADB at `LOCKED_BOOT_COMPLETED` and runs the exploit before the first unlock, once per real boot. It then late-loads KernelSU and performs a userspace soft restart so modules and Zygisk start.

Use **Run auto-root now** to repeat on demand; history is under **Auto-root log**. The optional **Boot screen** shows progress over the lock screen. Details and field notes: [docs/auto-root.md](docs/auto-root.md).

## Samsung mode

Selected automatically when `Build.MANUFACTURER` or `Build.BRAND` is `samsung`, or manually under **Settings -> Device mode**. It uses `conf/samsung/*.conf` and the pinned [diabl0w/KernelSU](https://github.com/diabl0w/KernelSU) Samsung build (manager version `samsung-v*`); other managers are rejected rather than mismatched. The bundled profiles target kernels `6.1.162-android14-11` (Galaxy S24 / S26 Ultra) and `5.15.189-android13-8-33641424` (Galaxy A15 5G); an unsupported kernel is refused. See [Samsung mode](docs/supported-devices.md#samsung-mode).

## Supported devices

The exploit is tied to a kernel build, not a device name. One binary serves every profile; the app picks the conf that matches the running kernel and page size.

**Hardware-tested:** Pixel 7a (`lynx`) and Pixel 9a (`tegu`) on 6.1.162. Everything else is QEMU-verified from the factory kernel or untested.

| Kernel family | Devices |
|---|---|
| 6.1.162 (4K/16K) | Pixel 6 through Pixel 10a |
| 6.6.127 | Pixel 10 series |
| 6.12.69 | Pixel 11 series, Xiaomi 17 series |
| 6.1.138 | Redmi Note 15 Pro / Pro+ 5G |
| 6.6.118 | Xiaomi 15, Redmi Note 15/17 |
| 6.12.30 / 6.12.69 / 5.15.194 | Redmi Note 15/17 standalone payloads |
| 6.18.21 | Xiaomi 18 series, Pad 9 Pro Max |

Full build numbers, payload hashes and per-profile notes: [docs/supported-devices.md](docs/supported-devices.md).

## Status card

Detected by running `su -c id` and checking for `u:r:ksu:s0`:

| Card | Meaning |
|---|---|
| Not connected | Shizuku is not running / not bound |
| Ready | Shizuku connected, no root yet |
| Root shell | `uid=0`, `u:r:shell:s0` |
| Jailbreak mode | KernelSU loaded, `su` works in `u:r:ksu:s0` |

## Updates

Settings -> *Updates* checks GitHub at most once a day; **Check now** does it on demand. The app only opens the releases page and never installs an APK by itself.

## Build

```bash
./gradlew assembleDebug
```

Requires Android SDK platform 36 and build-tools 36. Shizuku's API comes from Maven. The build copies `conf/` into the APK as `assets/conf/`.

Without Gradle, `scripts/build.ps1` builds and signs an APK using only the SDK, `javac`, `d8`, `aapt2` and `apksigner`. Clone [Shizuku-API](https://github.com/RikkaApps/Shizuku-API) first, then:

```powershell
scripts/build.ps1 -Sdk "C:\Users\<you>\AppData\Local\Android\Sdk"
```

## Safety

- **Do not kill a parked process.** The exploit keeps a process alive with the fake credential page pinned in socket buffers. Reaping it can panic the kernel.
- **A reboot clears everything**: KernelSU, the root shell and parked processes.
- **A soft restart is not a reboot**: the kernel stays up, KernelSU stays loaded and parked processes stay parked.
- SELinux is left permissive until the next reboot.
- A failed attempt can leave a stale timerqueue node; other apps may crash until you reboot.
- Only use this on a device you own or are explicitly allowed to modify.

## Layout

```
app/                      Android app (UI, Shizuku service, auto-root)
conf/*.conf               per-kernel HOCON profiles
conf/dirty/*.conf         profiles with a device identity check
conf/samsung/*.conf       Samsung DEFEX/KDP profiles
p7a/timer_p7a.c           exploit source (conf-driven)
scripts/build.ps1         Gradle-free build
docs/auto-root.md         auto-root and boot-screen research
docs/supported-devices.md device tables, profile details, credits
PORT_LOG.md               per-gate port record (F1-F6 evidence)
```

## Credits

- Exploit: [YuKongA/CVE-2026-98260](https://github.com/YuKongA/CVE-2026-98260) (MIT), based on work by woshigenm and the other 98260 ports. Analysis: [InfinityCore](https://github.com/V4bel/InfinityCore).
- [Shizuku](https://github.com/RikkaApps/Shizuku) / [Shizuku-API](https://github.com/RikkaApps/Shizuku-API) (Apache-2.0) by Rikka.
- KernelSU (GPL-2.0), [diabl0w/KernelSU](https://github.com/diabl0w/KernelSU), KernelSU-Next and SukiSU Ultra.
- [rikumi/TimerRoot](https://github.com/rikumi/TimerRoot): HOCON profile mechanism, runtime conf selection and vendor profiles.
- Original repository: [kpgc10kai/TimerRoot](https://github.com/kpgc10kai/TimerRoot).

Per-device profile sources are credited in [docs/supported-devices.md#credits](docs/supported-devices.md#credits).

## License

MIT for the app code in this repository. The exploit binary and the Shizuku API keep their own licenses.
