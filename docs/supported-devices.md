# Supported devices and exploit profiles

Detailed companion to the main [README](../README.md). The exploit is tied to a
kernel build, not to a device name. One binary serves every profile here; the
app selects the `conf/*.conf` that matches the running kernel release and
userspace page size, and refuses to run when nothing matches.

## Getting the exploit binary

The exploit is build-specific: the timer call site, `cred` layout and
`task_struct` offsets differ per kernel, and a binary built for another build
will corrupt the kernel instead of failing safely.

The binary does not hard-code a profile: every kernel address and structure
offset comes from a HOCON file under `conf/`, and the app picks one for the
running kernel:

- `release` must equal `uname -r`. A trailing `-4k` is optional on both sides,
  so `...-ab16252310` and `...-ab16252310-4k` are the same kernel.
- When the profile sets `page_size`, `sysconf(_SC_PAGESIZE)` must match too.
  This is how the 4K and 16K builds of 6.1.162 are told apart; they share a
  release string.
- Profiles under `conf/dirty/` have a release string that is not unique to one
  vendor build (`-maybe-dirty`), so `device_model`, `android_release` and
  (when present) `sdk_int` must also match the device.

`UserService` extracts `assets/conf/**.conf` to `/data/local/tmp/timer-conf`,
chooses the first match, and runs the binary as:

```
/data/local/tmp/timer --conf /data/local/tmp/timer-conf/<match>.conf shell
```

`--conf` is mandatory. It can be given to the NDK build directly, which is
useful for probing a profile from `adb shell`:

```bash
timer --conf conf/6.1.162-android14-11-g9dd05ae3a1de-ab16261587.conf target
```

The app also passes `--protocol 3`, the app/binary interface version. This is a
compatibility handshake: old TimerRoot APKs predate the conf rewrite, so they
start the binary without `--conf`/`--protocol`. The new binary then refuses to
run and prints:

```
[!] BREAKING CHANGE: TimerRoot app is too old
[!] OLD_APP_DETECTED app_protocol=0 required=3
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
Pixel 10 profile, a 6.12.69 Pixel 11 profile, the 6.1.138 / 6.6.118 / 6.12.69 /
6.18.21 profiles for the Xiaomi 15/17/18 and Redmi Note 15/17 families, the
6.12.30 / 6.12.69 / 5.15.194 profiles for the Redmi Note 15/17 models that
ship standalone payloads, and vendor profiles for other devices carried over
from `rikumi/TimerRoot`. See [Credits](#credits) for where each profile came
from.

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
`PORT_LOG.md` records the F1-F6 derivation for each bundled profile.

`timer --conf <profile> selfcheck` re-checks a profile's internal invariants
without touching the kernel, and is what the F6 gate runs:

```
[selfcheck] profile=6.18.21-android17-5-g805aa6adea19-abogki565292102-4k.conf
[selfcheck] ok   slab_size 0x2000 == page_size << slab_order (0x2000)
[selfcheck] ok   timer_site_low21 0x1a726c == timer_site & 0x1fffff
...
[selfcheck] ok   timer_alloc 0x180 <= slab_size 0x2000
[selfcheck] info last object node=0x1ee0 cred_end=0x1fb0 slab=0x2000 (fits)
[selfcheck] ok (0 failures)
```

It exits non-zero on any failure, so it is safe to script.

The binary is MIT licensed by its authors; only use it on hardware you own, and
only when your kernel matches the build it was ported to.

## Supported devices

Status legend:

- **tested** — run on physical hardware.
- **verified in QEMU** — the shipped aarch64 binary ran against that factory
  kernel under `qemu-system-aarch64`, through `target`, `ids`, `probe`, `leak`
  and `verify` (F7-F11). The kernel is the real one; the userspace, SELinux
  policy and KernelSU are not, so this does not replace a hardware run.
- **untested** — derived from the factory image only.

### 6.1.162 (4K and 16K)

`6.1.162-android14-11-g9dd05ae3a1de-ab16261587`, the GKI kernel shipped in the
`CP3A.261005.002.A1` and `CP3A.261005.005` factory images. Every device in this
table ships that exact kernel payload.

**Only the Pixel 7a and Pixel 9a have actually been run on hardware.**
Everything else in this table ships the same kernel and is expected to work;
the 4K and 16K profiles both pass F7-F11 under QEMU, but no other device in
this table has been run on hardware.

| Device | Codename | Factory build | Status |
|---|---|---|---|
| Pixel 6 | `oriole` | `CP3A.261005.002.A1` | verified in QEMU |
| Pixel 6 Pro | `raven` | `CP3A.261005.002.A1` | verified in QEMU |
| Pixel 6a | `bluejay` | `CP3A.261005.002.A1` | verified in QEMU |
| Pixel 7 | `panther` | `CP3A.261005.002.A1` | verified in QEMU |
| Pixel 7 Pro | `cheetah` | `CP3A.261005.002.A1` | verified in QEMU |
| **Pixel 7a** | `lynx` | `CP3A.261005.002.A1` | **tested** |
| Pixel Fold | `felix` | `CP3A.261005.002.A1` | verified in QEMU |
| Pixel Tablet | `tangorpro` | `CP3A.261005.002.A1` | verified in QEMU |
| Pixel 8 | `shiba` | `CP3A.261005.005` | verified in QEMU |
| Pixel 8 Pro | `husky` | `CP3A.261005.005` | verified in QEMU |
| Pixel 8a | `akita` | `CP3A.261005.005` | verified in QEMU |
| Pixel 9 | `tokay` | `CP3A.261005.005` | verified in QEMU |
| Pixel 9 Pro | `caiman` | `CP3A.261005.005` | verified in QEMU |
| Pixel 9 Pro XL | `komodo` | `CP3A.261005.005` | verified in QEMU |
| Pixel 9 Pro Fold | `comet` | `CP3A.261005.005` | verified in QEMU |
| **Pixel 9a** | `tegu` | `CP3A.261005.005` | **tested** |
| Pixel 10a | `stallion` | `CP3A.261005.005` | verified in QEMU |

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

### 6.6.127 (4K) — Pixel 10 series

`6.6.127-android15-8-g91d825611104-ab16252310-4k`, shipped by the Pixel 10
series in the same `CP3A.261005.005` build number. The profile is
`conf/6.6.127-android15-8-g91d825611104-ab16252310-4k.conf`:

| Device | Codename | Status |
|---|---|---|
| Pixel 10 | `frankel` | verified in QEMU |
| Pixel 10 Pro | `blazer` | verified in QEMU |
| Pixel 10 Pro XL | `mustang` | verified in QEMU |
| Pixel 10 Pro Fold | `rango` | verified in QEMU |

All four factory images contain a byte-identical kernel payload (36,866,560
bytes, SHA-256 `0226c3be4224b02884d4f9b332aee58ec06c65b2263265e80f2498332ef15c06`),
so one profile covers all of them. The 6.6 profile was verified end-to-end
(`timer verify` and `timer fake`) in a QEMU VM booting the factory kernel; it
has not been flashed on physical Pixel 10 hardware yet. The 2026-11 mass run
re-ran it from the factory `boot.img` and it passes F7-F11.

### 6.12.69 (4K) — Pixel 11 series

`6.12.69-android16-6-g70777328ed0e-ab16108597-4k`, built into the
`CD1A.261005.003` and `CD1A.261005.003.b1` factory images. Profile:
`conf/6.12.69-android16-6-g70777328ed0e-ab16108597-4k.conf`.

| Device | Codename | Factory build | Status |
|---|---|---|---|
| Pixel 11 | `cubs` | `CD1A.261005.003` | verified in QEMU |
| Pixel 11 Pro | `grizzly` | `CD1A.261005.003` | verified in QEMU |
| Pixel 11 Pro XL | `kodiak` | `CD1A.261005.003` | verified in QEMU |
| Pixel 11 Pro Fold | `yogi` | `CD1A.261005.003` | verified in QEMU |

All four images (and both build suffixes) carry a byte-identical kernel payload
(SHA-256 `4417511834260f72c1b6a5bb9b9f809dfb6734b20fd7e8aa156c3c1f91f0f97b`),
so one profile covers them. This is the only profile in this repository whose
`task_alloc_bytes` is not `0x12c0`/`0x1840`: the bootconfig vendor extension is
`android_arch_task_struct_size=784`, giving `0x1750`.

### 6.1.138 (4K) — Redmi Note 15 Pro series

| Device | Codename | Factory build | Profile | Status |
|---|---|---|---|---|
| Redmi Note 15 Pro+ 5G | `flourite` | `OS3.0.318.0.WPRCNXM` | `conf/6.1.138-android14-11-g0c3d559bcd85-ab14529422.conf` | verified in QEMU |
| Redmi Note 15 Pro 5G | `lapis` | `OS3.0.309.0.WPPCNXM` | `conf/6.1.138-android14-11-g51f8c580613d-ab13911623.conf` | verified in QEMU |

These two share the 6.1 `__pi_` VA layout (`0xffffffc008...`) and the 4-byte
`cred.usage` that shifts the whole fake cred, but they are **different kernel
payloads** with different `do_timer_create` call sites, so each has its own
profile. Both set `pcp_free = 1`: 6.1 frees the order-1 slab through the PCP
lists, so the reclaim is also gated on `/proc/slabinfo`, the same gate used by
the tested 6.1.162 Pixel profile.

### 6.6.118 (4K) — Xiaomi 15, Redmi Note 15/17

| Device | Codename | Factory build | Profile | Status |
|---|---|---|---|---|
| Xiaomi 15 | `dada` | `OS3.0.307.0.WOCCNXM` | `conf/6.6.118-android15-8-gc44b714366cc-abogki519650608-4k.conf` | verified in QEMU |
| Redmi Note 15 5G | `kunzite` | `OS3.0.304.0.WPQCNXM` | `conf/6.6.118-android15-8-ge56cf6b09cca-ab15511674-4k.conf` | verified in QEMU |
| Redmi Note 17 5G | `mist` | `OS3.0.311.0.WPUCNXM` | `conf/6.6.118-android15-8-g666ad52b8230-ab15657065-4k.conf` | verified in QEMU |
| Redmi Note 17 Pro 5G | `iolite` | `OS3.0.314.0.WDQCNXM` | `conf/6.6.118-android15-8-gb9cc6ec16bc8-abogki536571621-4k.conf` | verified in QEMU |

All four are 6.6 GKI kernels with only two distinct text layouts: dada and
iolite share `do_timer_create` returning at `0xffffffc080195d94`, kunzite and
mist at `...d48`. `task_alloc_bytes` stays `0x12c0` for all four: these
`vendor_boot`/`dtb`/`dtbo` images carry no `android_arch_task_struct_size=`
parameter, and `task_struct_vendor_size_setup()` only adds the extension when
the parameter is present.

Note that the reference port
[`quyicheng03-boop/CVE-2026-98260-dada-android`](https://github.com/quyicheng03-boop/CVE-2026-98260-dada-android)
is titled "dada" but was built for
`6.6.118-...-gb9cc6ec16bc8-abogki536571621`, i.e. this repository's **iolite**.
The kernel payload hashes match; the name in that project is a misnomer.

### Standalone-payload variants (6.12.30, 6.12.69, 5.15.194) — Redmi Note 15/17

These four models do not ship the shared payloads above, so each has its own
profile. Three are 4G models; `brussels` is the 5G Redmi Note 17 Pro Max. All
are 4K-page builds. The three 6.12 kernels carry
`android_arch_task_struct_size=512` in their vendor boot configuration, so
`task_alloc_bytes` is `0x1440 + 0x200 = 0x1640`; zephyr is the repository's
only 5.15 profile, has no vendor-size extension, and keeps the `fork_init()`
size of `0x1200`.

| Device | Codename | Factory build | Kernel | Profile | Status |
|---|---|---|---|---|---|
| Redmi Note 15 4G | `spinel` | `OS3.0.303.0.WPGMIXM` | `6.12.69-...-ab15889839-4k` | `conf/6.12.69-android16-6-g014ca48a80ee-ab15889839-4k.conf` | verified in QEMU |
| Redmi Note 15 Pro 4G | `charoite` | `OS3.0.304.0.WPFMIXM` | `6.12.30-...-ab13847919-4k` | `conf/6.12.30-android16-5-g6e872b4863d6-ab13847919-4k.conf` | verified in QEMU |
| Redmi Note 17 4G | `zephyr` | `OS3.0.311.0.WBUMIXM` | `5.15.194-...-ab15004895` | `conf/5.15.194-android13-8-00015-gf5526d1116e5-ab15004895.conf` | verified in QEMU |
| Redmi Note 17 Pro Max 5G | `brussels` | `OS3.0.311.0.WDRMIXM` | `6.12.69-...-abogki537510563-4k` | `conf/6.12.69-android16-6-g586bfab1b9c5-abogki537510563-4k.conf` | verified in QEMU |

`spinel` and `brussels` share a kernel version but not a payload, so they have
separate profiles. `charoite` is 6.12.30 and has no landlock cred blob
(`selinux_blob_off = 0`). `zephyr` is the 5.15 outlier: its `cred.usage` is a
4-byte `atomic_t`, `timer_alloc` is `0x108`, and it sets `pcp_free = 1` because
5.15 frees the order-1 slab through the PCP lists (the same slabinfo gate as
the 6.1 profiles). All four were checked for the `begin_new_exec()` call order
(F1), derive their constants from the factory `boot.img`/`vendor_boot.img`, and
pass F7-F11 in QEMU.

### 6.12.69 (4K) — Xiaomi 17 series

`conf/6.12.69-android16-6-g43b5ab7e247d-abogki558343811-4k.conf` covers the
Xiaomi 17 Pro Max. The rest of the 17 series ships a different kernel payload
(`6.12.69-...-abogki561813157`), which is already covered by the upstream profile
`conf/6.12.69-android16-6-g43b5ab7e247d-abogki561813157-4k.conf` imported from
`rikumi/TimerRoot`; the factory `boot.img` of each device below was checked to
confirm it is the same payload that profile was built from.

| Device | Codename | Factory build | Kernel build | Status |
|---|---|---|---|---|
| Xiaomi 17 Pro Max | `popsicle` | `OS4.0.5.0.XPBCN` | `...-abogki558343811` | verified in QEMU |
| Xiaomi 17 | `pudding` | `OS4.0.5.0.XPCCNXM` | `...-abogki561813157` | verified in QEMU |
| Xiaomi 17 Pro | `pandora` | `OS4.0.5.0.XBLCNXM` | `...-abogki561813157` | verified in QEMU |
| Xiaomi 17 Ultra | `nezha` | `OS4.0.5.0.XPACNXM` | `...-abogki561813157` | verified in QEMU |
| Xiaomi 17 Max | `byron` | `OS4.0.3.0.XAFCNXM` | `...-abogki561813157` | verified in QEMU |

The `abogki561813157` payload is byte-identical (SHA-256
`ed9e27aa606772d058684e023fcb2d3dca876505be90227cc8ca5e5d5b95622b`) on
pudding, pandora, nezha and byron.

### 6.18.21 (4K) — Xiaomi 18 series and Pad 9 Pro Max

| Device | Codename | Factory build | Profile | Status |
|---|---|---|---|---|
| Xiaomi 18 Pro | `hongkong` | `OS4.0.29.0.XFRCN` | `conf/6.18.21-android17-5-g284297031c53-abogki555938958-4k.conf` | verified in QEMU |
| Xiaomi 18 Pro Max | `madrid` | `OS4.0.27.0.XEOCN` | same as above | verified in QEMU |
| Xiaomi 18 Fold | `lhasa` | `OS4.0.26.0.XPNCNXM` | `conf/6.18.21-android17-5-g805aa6adea19-abogki565292102-4k.conf` | verified in QEMU |
| Xiaomi Pad 9 Pro Max | `yingtian` | `OS4.0.16.0.XBMCNXM` | same as above | verified in QEMU |

hongkong and madrid share a byte-identical kernel payload (SHA-256
`0a3cf0d220490927ce1ee9db380adfdd20930fc0e602b97dd652d610bbe9d3fe`); lhasa and
yingtian share theirs (SHA-256
`cde87cd70206f21db4359aa1148f5f68e693ffefb11108dffde99c07c8c5ad88`).

These are the only profiles in this repository with the 6.18 object layout:
`sizeof(struct k_itimer)` grew to `0x180` and `cpu_timer` moved to `+0xe0`, so
`timer_alloc` and the new `timer_node_off` field both differ from every other
profile. `task_alloc_bytes` is `0x1280 + 0x400 = 0x1680`, and
`selinux_blob_off` is `0x10`, because landlock contributes an 11-byte cred blob
ahead of SELinux in the runtime `CONFIG_LSM` order.

If your device is not in these tables, or its status is untested, check the
`kernel=` line first (the app runs `timer --conf ... target` and logs it), and
compare it with the conf you intend to use. Do not run the exploit on a kernel
that does not match. A device with no matching conf is refused instead of
falling back to another profile.

## Samsung mode

Samsung mode is selected automatically when `Build.MANUFACTURER` or
`Build.BRAND` is `samsung`, and is available as a manual toggle under
**Settings -> Device mode** (with **Use automatic detection** to clear the
override). It uses `conf/samsung/*.conf`, runs the unified `fake` chain
(`--samsung`), clears the child's DEFEX `creds_fast_hash` slot, moves the
worker to `u:r:init:s0`, bind-mounts the bundled diabl0w/KernelSU
`assets/samsung/libksud.so` over `/system/bin/logcat` (KDP-safe), and leaves
SELinux to `ksud`'s own restore. There is no generic manager discovery and no
second late-load stage.

Samsung mode is pinned to the
[diabl0w/KernelSU](https://github.com/diabl0w/KernelSU) Samsung build. That
build keeps the upstream `me.weishu.kernelsu` package name, so the app
identifies it by its manager `versionName` prefix (`samsung-v*`, for example
`samsung-v2.2`). A missing manager, the upstream KernelSU with the same
package name, KernelSU-Next, or SukiSU Ultra is rejected with an explanation
instead of late-loading a mismatched module.

The bundled Samsung profiles target `6.1.162-android14-11` (SM-S921N Galaxy
S24 / SM-S948U Galaxy S26 Ultra), the builds SamTimer was tested on and derived
its offsets from, `5.15.189-android13-8-33641424` (SM-A1560 Galaxy A15 5G) and
`5.15.197-android13-8-34343818-abS911BXXUAGZIF` (SM-S911B Galaxy S23), which
were ported here from their own factory `boot.img` and verified in QEMU, and
`6.6.127-android15-8-abogkiS741BXXS3AZK1-4k` (SM-S741B Galaxy S26 FE) and
`6.6.127-android15-8-p87b1ce1-abogkiS937BXXUBDZJB-4k` (SM-S937B Galaxy S25
Edge), both also ported here from their factory `boot.img` and verified in
QEMU. F7–F11 pass for every ported profile; the S26 FE and S25 Edge ports also
completed the `--samsung` DEFEX write chain. F12/F13 still need a device. A
Samsung device
on an unsupported kernel is refused with a message to turn Samsung mode off
and use a generic profile. The app rejects a binary that does not carry the
`TIMER_SAMSUNG=1` marker instead of passing `--samsung` to an old generic
build.

| Device | Codename | Factory build | Profile | Status |
|---|---|---|---|---|
| Galaxy S24 / S26 Ultra | SM-S921N / SM-S948U | — | `conf/samsung/samsung-s26u-6.1.162.conf` | untested |
| Galaxy A15 5G | `a15xzh` (SM-A1560) | `BP4A.251205.006` / `A1560ZHSAEZG1` | `conf/samsung/samsung-a15xzh-5.15.189.conf` | verified in QEMU |
| Galaxy S23 | SM-S911B | `S911BXXUAGZIF` (EUX) | `conf/samsung/samsung-s23-5.15.197.conf` | verified in QEMU |
| Galaxy S26 FE | SM-S741B | `S741BXXS3AZK1` (EUX) | `conf/samsung/samsung-s26fe-6.6.127.conf` | verified in QEMU |
| Galaxy S25 Edge | SM-S937B | `S937BXXUBDZJB` (EUX) | `conf/samsung/samsung-s25edge-6.6.127.conf` | verified in QEMU |

The `a15xzh` profile is the first 5.15 Samsung one, so it also carries the
5.15 geometry: 4-byte `cred.usage`, `timer_alloc 0x108`, `task_alloc_bytes
0x1200` with no vendor-size extension, and `pcp_free = 1`. It sets
`ksu_kmi = "android13-5.15"`. F7–F11 and the `--samsung fake` write chain
(`defex_hash` → `fake_cred` → `selinux_state` → uid/euid repair) were verified
in QEMU; the late-load itself needs a device, so F12/F13 stay pending. The
factory kernel calls the Knox hypervisor, so its QEMU run used a throwaway
patched `Image` — the constants still come from the unmodified factory
artifacts.

The `samsung-s25edge` profile is the first S25-series one. The S25 family
(Edge / S25 / S25+ / S25 Ultra) ships the `p87b1ce1` 6.6.127 build, which is
not the S741B S26 FE kernel, so `timer_site` (`0xffffffc0801962b0`),
`copy_process_low21` (`0xac474`) and every symbol were re-derived from the
SM-S937B factory `boot.img`. It has the same 6.6 cred/task layout as S26 FE
(8-byte `cred.usage`, `cred 0xb8`, `task_struct 0x12c0` with cred at
`+0x820`) and the same DEFEX shape (`creds_fast_hash` is its own symbol at
`creds_hash + 0x40000`, indexed directly for `pid <= 0x8000`). Its
`release_prefix` pins the full `…abogkiS937BXXUBDZJB-4k` banner: the other
S25-series images embed a different firmware string, so they are refused
rather than run against this profile until each is derived from its own
factory kernel.

The `samsung-s23` profile is the second 5.15 Samsung one and the first
S23-series one. The S23+ and S23 Ultra share its `34343818` build number but
ship different `ab` firmware strings and different text layouts, so its
`release_prefix` pins the full `5.15.197-android13-8-34343818-abS911BXXUAGZIF`
banner and the other S23 models are refused until each gets its own profile.
It carries the same 5.15 geometry as `a15xzh` (4-byte `cred.usage`, `cred
0xb0`/`cred_jar 0xc0`, `timer_alloc 0x108`, `task_struct 0x1200` with cred at
`+0x798`, `pcp_free = 1`) and the same DEFEX shape as the 6.6 Samsung ports
(`creds_fast_hash` is its own symbol at `creds_hash + 0x40000`, indexed
directly for `pid <= 0x8000`). `ksu_kmi = "android13-5.15"`. Its factory kernel
also calls the Knox hypervisor, so the QEMU run used a throwaway patched
`Image`; every constant comes from the unmodified factory artifacts.

## Credits

- Exploit: [YuKongA/CVE-2026-98260](https://github.com/YuKongA/CVE-2026-98260)
  (MIT), based on work by woshigenm and the other 98260 ports. Vulnerability
  discovery and the public analysis come from
  [InfinityCore](https://github.com/V4bel/InfinityCore).
- [Shizuku](https://github.com/RikkaApps/Shizuku) and
  [Shizuku-API](https://github.com/RikkaApps/Shizuku-API) (Apache-2.0) by Rikka.
- KernelSU (GPL-2.0), [diabl0w/KernelSU](https://github.com/diabl0w/KernelSU)
  (the pinned Samsung build), KernelSU-Next, and SukiSU Ultra for the
  late-load path.
- [rikumi/TimerRoot](https://github.com/rikumi/TimerRoot): the HOCON
  conf-driven profile mechanism, runtime conf selection (release, page size and
  dirty-device identity checks), and the vendor profiles under `conf/` were
  ported from this project.
- Original repository that this fork based on:
  [kpgc10kai/TimerRoot](https://github.com/kpgc10kai/TimerRoot)

The Xiaomi / Redmi profiles below were derived from each device's own factory
`boot.img` (kallsyms + BTF) with the port procedure in
[SKILL.md](../SKILL.md), and cross-checked against these target-specific ports.
None of their code is vendored; they are credited as the source of the object
layout, the page-reuse strategy and the constant tables that were re-derived
and verified here.

- [zsw125/o3root](https://github.com/zsw125/o3root) — Xiaomi `yingtian` /
  `lhasa`, kernel `6.18.21-android17-5-g805aa6adea19-abogki565292102`. Source
  of the 6.18 object layout (`k_itimer` `0x180`, `cpu_timer` at `+0xe0`),
  the extended `cred_security_struct`, the `selinux_state - 7` write and the
  `init_user_ns` slide derivation. Basis for
  `conf/6.18.21-android17-5-g805aa6adea19-abogki565292102-4k.conf`.
- [quyicheng03-boop/CVE-2026-98260-popsicle-android](https://github.com/quyicheng03-boop/CVE-2026-98260-popsicle-android)
  — Xiaomi `popsicle`, kernel `6.12.69-android16-6-g43b5ab7e247d-abogki558343811`.
  Source of the 6.12 order-1 slab geometry (32 objects of `0x100`) and the
  three-stage SELinux / UID / capabilities chain. Basis for
  `conf/6.12.69-android16-6-g43b5ab7e247d-abogki558343811-4k.conf`.
- [starriv/CVE-2026-98260-Xiaomi-17-Pro-Max](https://github.com/starriv/CVE-2026-98260-Xiaomi-17-Pro-Max)
  — second reference for the same `6.12.69-...-abogki558343811` kernel; used to
  cross-check the `popsicle` constants.
- [quyicheng03-boop/CVE-2026-98260-nezha-android](https://github.com/quyicheng03-boop/CVE-2026-98260-nezha-android)
  and [4627488/cve-2026-98260-nezha](https://github.com/4627488/cve-2026-98260-nezha)
  — Xiaomi `nezha`, kernel `6.12.69-android16-6-g43b5ab7e247d-abogki561813157`.
  Used to confirm that `pudding` / `pandora` / `nezha` / `byron` share this
  payload and the upstream `...-abogki561813157` profile.
- [addxemmm/CVE-2026-98260-pudding-android](https://github.com/addxemmm/CVE-2026-98260-pudding-android)
  — Xiaomi `pudding`, same `...-abogki561813157` kernel; source of the
  `libc`-free syscall path and the identity gate used while validating that
  profile.
- [quyicheng03-boop/CVE-2026-98260-dada-android](https://github.com/quyicheng03-boop/CVE-2026-98260-dada-android)
  — despite the name, built for `6.6.118-...-gb9cc6ec16bc8-abogki536571621`,
  which is the kernel of this repository's `iolite`. Source of the 6.6
  order-1 slot count (31) and the `free_slab` correlation approach. Basis for
  `conf/6.6.118-android15-8-gb9cc6ec16bc8-abogki536571621-4k.conf`.
