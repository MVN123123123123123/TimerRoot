# Supported devices

The exploit is tied to a **kernel build**, not to a device name. One binary
serves every profile here; the app selects the `conf/*.conf` that matches the
running kernel release and userspace page size, and refuses to run when nothing
matches. Detailed profile-matching rules are in
[Installation](installation.md#exploit-binary-and-profiles).

Status legend:

| Status | Meaning |
|---|---|
| **tested** | Run on physical hardware. |
| **verified in QEMU** | The shipped aarch64 binary ran against that factory kernel in `qemu-system-aarch64`, through `target`, `ids`, `probe`, `leak` and `verify` (F7-F11). The kernel is real; userspace, SELinux policy and KernelSU are not, so this does not replace a hardware run. |
| **untested** | Profile exists but has not been run, or not even booted in QEMU (see the per-family notes). |

**Only the Pixel 7a and Pixel 9a have been run on hardware.** Every other row
is QEMU verification or untested.

To identify your device:

```bash
adb shell getprop ro.product.device
adb shell getprop ro.build.fingerprint
adb shell uname -r
adb shell getconf PAGESIZE
```

## Google

### Pixel 6 through Pixel 10a — 6.1.162 (4K and 16K)

Profiles:

- 4K pages: `conf/6.1.162-android14-11-g9dd05ae3a1de-ab16261587.conf`
- 16K pages: `conf/6.1.162-android14-11-g9dd05ae3a1de-ab16261587-16k.conf`

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

### Pixel 10 series — 6.6.127 (4K)

Profile: `conf/6.6.127-android15-8-g91d825611104-ab16252310-4k.conf`

| Device | Codename | Factory build | Status |
|---|---|---|---|
| Pixel 10 | `frankel` | `CP3A.261005.005` | verified in QEMU |
| Pixel 10 Pro | `blazer` | `CP3A.261005.005` | verified in QEMU |
| Pixel 10 Pro XL | `mustang` | `CP3A.261005.005` | verified in QEMU |
| Pixel 10 Pro Fold | `rango` | `CP3A.261005.005` | verified in QEMU |

### Pixel 11 series — 6.12.69 (4K)

Profile: `conf/6.12.69-android16-6-g70777328ed0e-ab16108597-4k.conf`

| Device | Codename | Factory build | Status |
|---|---|---|---|
| Pixel 11 | `cubs` | `CD1A.261005.003` | verified in QEMU |
| Pixel 11 Pro | `grizzly` | `CD1A.261005.003` | verified in QEMU |
| Pixel 11 Pro XL | `kodiak` | `CD1A.261005.003` | verified in QEMU |
| Pixel 11 Pro Fold | `yogi` | `CD1A.261005.003` | verified in QEMU |

## Samsung

Samsung devices use **Samsung mode** and the profiles in `conf/samsung/`. It is
selected automatically on a Samsung device, or manually under
**Settings -> Device mode**. See [Samsung mode](installation.md#samsung-mode).

| Device | Model | Factory build | Profile | Status |
|---|---|---|---|---|
| Galaxy S24 / S26 Ultra | SM-S921N / SM-S948U | — | `conf/samsung/samsung-s26u-6.1.162.conf` | untested |
| Galaxy A15 5G | SM-A1560 (`a15xzh`) | `BP4A.251205.006` / `A1560ZHSAEZG1` | `conf/samsung/samsung-a15xzh-5.15.189.conf` | verified in QEMU |
| Galaxy S23 | SM-S911B | `S911BXXUAGZIF` (EUX) | `conf/samsung/samsung-s23-5.15.197.conf` | verified in QEMU |
| Galaxy S26 FE | SM-S741B | `S741BXXS3AZK1` (EUX) | `conf/samsung/samsung-s26fe-6.6.127.conf` | verified in QEMU |
| Galaxy S25 Edge | SM-S937B | `S937BXXUBDZJB` (EUX) | `conf/samsung/samsung-s25edge-6.6.127.conf` | verified in QEMU |

## Xiaomi and Redmi

### Redmi Note 15 Pro series — 6.1.138 (4K)

| Device | Codename | Factory build | Profile | Status |
|---|---|---|---|---|
| Redmi Note 15 Pro+ 5G | `flourite` | `OS3.0.318.0.WPRCNXM` | `conf/6.1.138-android14-11-g0c3d559bcd85-ab14529422.conf` | verified in QEMU |
| Redmi Note 15 Pro 5G | `lapis` | `OS3.0.309.0.WPPCNXM` | `conf/6.1.138-android14-11-g51f8c580613d-ab13911623.conf` | verified in QEMU |

### Xiaomi 15, Redmi Note 15 and Redmi Note 17 — 6.6.118 (4K)

| Device | Codename | Factory build | Profile | Status |
|---|---|---|---|---|
| Xiaomi 15 | `dada` | `OS3.0.307.0.WOCCNXM` | `conf/6.6.118-android15-8-gc44b714366cc-abogki519650608-4k.conf` | verified in QEMU |
| Redmi Note 15 5G | `kunzite` | `OS3.0.304.0.WPQCNXM` | `conf/6.6.118-android15-8-ge56cf6b09cca-ab15511674-4k.conf` | verified in QEMU |
| Redmi Note 17 5G | `mist` | `OS3.0.311.0.WPUCNXM` | `conf/6.6.118-android15-8-g666ad52b8230-ab15657065-4k.conf` | verified in QEMU |
| Redmi Note 17 Pro 5G | `iolite` | `OS3.0.314.0.WDQCNXM` | `conf/6.6.118-android15-8-gb9cc6ec16bc8-abogki536571621-4k.conf` | verified in QEMU |

### Redmi Note 15 and Note 17 — standalone payloads

These models do not ship the shared payloads above, so each has its own
profile.

| Device | Codename | Factory build | Kernel | Profile | Status |
|---|---|---|---|---|---|
| Redmi Note 15 4G | `spinel` | `OS3.0.303.0.WPGMIXM` | `6.12.69` | `conf/6.12.69-android16-6-g014ca48a80ee-ab15889839-4k.conf` | verified in QEMU |
| Redmi Note 15 Pro 4G | `charoite` | `OS3.0.304.0.WPFMIXM` | `6.12.30` | `conf/6.12.30-android16-5-g6e872b4863d6-ab13847919-4k.conf` | verified in QEMU |
| Redmi Note 17 4G | `zephyr` | `OS3.0.311.0.WBUMIXM` | `5.15.194` | `conf/5.15.194-android13-8-00015-gf5526d1116e5-ab15004895.conf` | verified in QEMU |
| Redmi Note 17 Pro Max 5G | `brussels` | `OS3.0.311.0.WDRMIXM` | `6.12.69` | `conf/6.12.69-android16-6-g586bfab1b9c5-abogki537510563-4k.conf` | verified in QEMU |

### Xiaomi 17 series — 6.12.69 (4K)

| Device | Codename | Factory build | Kernel build | Status |
|---|---|---|---|---|
| Xiaomi 17 Pro Max | `popsicle` | `OS4.0.5.0.XPBCN` | `...-abogki558343811` | verified in QEMU |
| Xiaomi 17 | `pudding` | `OS4.0.5.0.XPCCNXM` | `...-abogki561813157` | verified in QEMU |
| Xiaomi 17 Pro | `pandora` | `OS4.0.5.0.XBLCNXM` | `...-abogki561813157` | verified in QEMU |
| Xiaomi 17 Ultra | `nezha` | `OS4.0.5.0.XPACNXM` | `...-abogki561813157` | verified in QEMU |
| Xiaomi 17 Max | `byron` | `OS4.0.3.0.XAFCNXM` | `...-abogki561813157` | verified in QEMU |

Profiles:

- `conf/6.12.69-android16-6-g43b5ab7e247d-abogki558343811-4k.conf`
- `conf/6.12.69-android16-6-g43b5ab7e247d-abogki561813157-4k.conf`

### Xiaomi 18 series and Pad 9 Pro Max — 6.18.21 (4K)

| Device | Codename | Factory build | Profile | Status |
|---|---|---|---|---|
| Xiaomi 18 Pro | `hongkong` | `OS4.0.29.0.XFRCN` | `conf/6.18.21-android17-5-g284297031c53-abogki555938958-4k.conf` | verified in QEMU |
| Xiaomi 18 Pro Max | `madrid` | `OS4.0.27.0.XEOCN` | same as above | verified in QEMU |
| Xiaomi 18 Fold | `lhasa` | `OS4.0.26.0.XPNCNXM` | `conf/6.18.21-android17-5-g805aa6adea19-abogki565292102-4k.conf` | verified in QEMU |
| Xiaomi Pad 9 Pro Max | `yingtian` | `OS4.0.16.0.XBMCNXM` | same as above | verified in QEMU |

## OPPO

Imported vendor profiles. There is no factory image for these in the port
workspace, so they could not be booted in QEMU; see the notes.

| Device | Model | Kernel | Profile | Status |
|---|---|---|---|---|
| OPPO Pad mini | OPD2515 | `6.12.58-android16-6-g7704a1ae279b-ab15213644-4k` | `conf/6.12.58-android16-6-g7704a1ae279b-ab15213644-4k.conf` | untested |
| OPPO Pad mini | OPD2515 | `6.12.69-android16-6-g242e1a07f878-ab15865446-4k` | `conf/6.12.69-android16-6-g242e1a07f878-ab15865446-4k.conf` | untested |
| OPPO Find X8s | PKT110 | `6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k` | `conf/6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k.conf` | untested |

## realme

| Device | Model | Factory build | Kernel | Profile | Status |
|---|---|---|---|---|---|
| realme (CN) | RMX6699 | 16.0.0.263 | `6.6.66-android15-8-g29d86c5fc9dd-abogki428889875-4k` | `conf/6.6.66-android15-8-g29d86c5fc9dd-abogki428889875-4k.conf` | untested |

## Meizu

These devices use `conf/dirty/*.conf` because their release string is not
unique to one vendor build. The app also matches `device_model`,
`android_release` and `sdk_int` before using the profile.

| Device | Model | Android | Kernel | Profile | Status |
|---|---|---|---|---|---|
| Meizu 21 Pro | MEIZU 21 Pro | 16 (SDK 36) | `6.1.25-android14-11-maybe-dirty` | `conf/dirty/6.1.25-android14-11-maybe-dirty.conf` | untested |
| Meizu 22 | MEIZU 22 | 16 (SDK 36) | `6.6.66-android15-8-maybe-dirty-4k` | `conf/dirty/6.6.66-android15-8-maybe-dirty-4k.conf` | untested |

Both run Flyme 12.6.0.0A.

## Detailed notes

### Verification levels and known gaps

- **tested** means a cold boot, a settled device and the full chain ran on
  hardware. Only the Pixel 7a (`CP3A.261005.002.A1`) and Pixel 9a
  (`CP3A.261005.005`) meet that bar.
- **verified in QEMU** means F7-F11 passed against the unmodified factory
  kernel (or a throwaway vendor-hook-patched `Image` where the factory kernel
  calls Knox/RKP, noted under Samsung). F12 (`permissive`) and F13 (`fake`)
  cannot run there because the initramfs has no SELinux policy and no KernelSU.
  A QEMU pass is not a hardware substitute.
- **untested** rows fall into two groups: profiles whose factory artifacts are
  in the workspace but that have no hardware run, and imported profiles with no
  factory artifact in the workspace (the OPPO, realme and Meizu rows), which
  could not even join the QEMU mass run.
- If your device is in a table but its status is untested, check the `kernel=`
  line first (the app runs `timer --conf ... target` and logs it) and compare
  it with the conf you intend to use. Do not run the exploit on a kernel that
  does not match. A device with no matching conf is refused instead of falling
  back to another profile.

### Google Pixel

- The 6.1.162 rows all ship the same GKI kernel payload. The 4K `boot.img`
  kernel is byte-identical (16,637,222 bytes) across all 17 devices, so this is
  the same binary, not merely the same version string.
- Devices whose factory image also ships a `kernel_16k` (Pixel 8, 8 Pro, 8a, 9,
  9 Pro, 9 Pro XL, 9a and 10a) can boot the 16K-page build of that same kernel.
  Those images are byte-identical too and share the 4K kernel's release string,
  so they have a separate profile selected by `sysconf(_SC_PAGESIZE)`. The
  Pixel 9a 16K image was verified end-to-end in QEMU as well.
- The Pixel 10 series (6.6.127) ships one byte-identical kernel payload
  (36,866,560 bytes, SHA-256
  `0226c3be4224b02884d4f9b332aee58ec06c65b2263265e80f2498332ef15c06`), so one
  profile covers all four devices. It has not been flashed on physical Pixel 10
  hardware.
- The Pixel 11 series (6.12.69) likewise carries one byte-identical payload
  across both build suffixes (SHA-256
  `4417511834260f72c1b6a5bb9b9f809dfb6734b20fd7e8aa156c3c1f91f0f97b`). Its
  `task_alloc_bytes` is `0x1750`, not `0x12c0`: the vendor extension
  `android_arch_task_struct_size=784` is added to `sizeof(task_struct)`.

### Samsung

- Samsung mode uses `conf/samsung/*.conf`, the unified `fake` chain
  (`--samsung`), DEFEX `creds_fast_hash` clearing, a worker in `u:r:init:s0`,
  and the bundled diabl0w/KernelSU `ksud` bind-mounted over
  `/system/bin/logcat` for KDP safety. It is pinned to the
  [diabl0w/KernelSU](https://github.com/diabl0w/KernelSU) Samsung build, whose
  manager version starts with `samsung-v`; other managers are rejected.
- The S24 / S26 Ultra row is **untested** on purpose. Its constants were ported
  from the SamTimer reference 6.1.162 build, whose factory `boot.img` is not in
  the port workspace. Its generic `release_prefix = "6.1.162-android14-11"`
  also prefix-matches a different 6.1.162 image, so the QEMU harness booted a
  lookalike and failed base calibration. The row stays untested until the
  S24/S26 Ultra factory image is fetched and the constants re-derived.
- The A15 5G (`a15xzh`) is the first 5.15 Samsung profile: 4-byte `cred.usage`,
  `timer_alloc 0x108`, `task_alloc_bytes 0x1200`, `pcp_free = 1` and
  `ksu_kmi = "android13-5.15"`. Its factory kernel calls the Knox hypervisor,
  so the QEMU run used a throwaway patched `Image`; the constants still come
  from the unmodified factory artifacts. F7-F11 and the `--samsung fake` write
  chain were verified; F12/F13 need a device.
- The S23 profile pins the full `5.15.197-android13-8-34343818-abS911BXXUAGZIF`
  banner. The S23+ and S23 Ultra share the `34343818` build number but ship
  different `ab` strings and text layouts, so they are refused until each gets
  its own profile. Its QEMU run also used a throwaway patched `Image` because
  of Knox.
- The S26 FE profile pins `6.6.127-android15-8-abogkiS741BXXS3AZK1-4k`. The
  S25 Edge profile (`p87b1ce1`) is the first S25-series one; the S25 family
  shares its kernel build, but the other S25 images embed a different firmware
  string and are refused rather than run against this profile. Both were
  verified in QEMU, including the DEFEX write chain; F12/F13 still need a
  device. The S25 Edge QEMU boot used the five-word vendor-hook shim described
  in its port section.

### Xiaomi and Redmi

- The 6.1.138 pair (`flourite`, `lapis`) share the 6.1 `__pi_` VA layout
  (`0xffffffc008...`) and the 4-byte `cred.usage`, but they are **different
  kernel payloads** with different `do_timer_create` call sites, so each has
  its own profile. Both set `pcp_free = 1`: 6.1 frees the order-1 slab through
  the PCP lists, so reclaim is also gated on `/proc/slabinfo`, the same gate
  used by the 6.1.162 Pixel profile.
- The 6.6.118 group has only two distinct text layouts: `dada` and `iolite`
  share a `do_timer_create` return at `0xffffffc080195d94`; `kunzite` and
  `mist` share `...d48`. `task_alloc_bytes` stays `0x12c0` for all four,
  because their `vendor_boot`/`dtb`/`dtbo` images carry no
  `android_arch_task_struct_size=` parameter.
- The reference port
  [`quyicheng03-boop/CVE-2026-98260-dada-android`](https://github.com/quyicheng03-boop/CVE-2026-98260-dada-android)
  is titled "dada" but was built for
  `6.6.118-...-gb9cc6ec16bc8-abogki536571621`, which is this repository's
  **iolite**. The kernel payload hashes match; the name in that project is a
  misnomer.
- The four standalone-payload Redmi Note 15/17 models do not ship the shared
  payloads above. `spinel` and `brussels` share a kernel version but not a
  payload, so they have separate profiles. `charoite` is 6.12.30 and has no
  landlock cred blob (`selinux_blob_off = 0`). The three 6.12 kernels carry
  `android_arch_task_struct_size=512`, giving `task_alloc_bytes = 0x1440 +
  0x200 = 0x1640`. `zephyr` is the repository's only 5.15 profile: 4-byte
  `cred.usage`, `timer_alloc 0x108`, no vendor-size extension so
  `task_alloc_bytes` stays `0x1200`, and `pcp_free = 1`.
- The Xiaomi 17 series is split by payload: `popsicle` has its own profile,
  while `pudding`, `pandora`, `nezha` and `byron` share a byte-identical
  `...-abogki561813157` payload (SHA-256
  `ed9e27aa606772d058684e023fcb2d3dca876505be90227cc8ca5e5d5b95622b`) and the
  upstream profile imported from `rikumi/TimerRoot`.
- The 6.18.21 profiles are the only ones with the 6.18 object layout:
  `sizeof(struct k_itimer)` grew to `0x180`, `cpu_timer` moved to `+0xe0`, and
  `timer_node_off` is `0xe0`. `task_alloc_bytes` is `0x1280 + 0x400 = 0x1680`,
  and `selinux_blob_off` is `0x10` because landlock contributes an 11-byte cred
  blob ahead of SELinux in the runtime `CONFIG_LSM` order. `hongkong`/`madrid`
  and `lhasa`/`yingtian` each share a byte-identical payload (SHA-256
  `0a3cf0d220490927ce1ee9db380adfdd20930fc0e602b97dd652d610bbe9d3fe` and
  `cde87cd70206f21db4359aa1148f5f68e693ffefb11108dffde99c07c8c5ad88`
  respectively).

### OPPO, realme and Meizu

- The three OPPO profiles and the realme profile are imported vendor profiles
  from `rikumi/TimerRoot`. No factory image for them is in the port workspace,
  so F7-F11 could not be run: they pass the parser, release/page-size matching
  and the F6 `selfcheck` invariants, but they have no QEMU evidence. One was
  derived from a device dump (`boot_a` from the running realme RMX6699), so
  there is no factory image to boot even in principle.
- The two Meizu profiles live under `conf/dirty/` because
  `...-maybe-dirty` is not unique to one vendor build. They also match
  `device_model` (`MEIZU 21 Pro` / `MEIZU 22`), `android_release` (`16`) and
  `sdk_int` (`36`). Their factory artifacts are not in the workspace either,
  so their symbols could not be cross-checked against a vmlinux; F6 passes but
  F2/F3 remain unverified.

### Profile matching rules

- `release` must equal `uname -r`; a trailing `-4k` is optional on both sides.
- When `page_size` is set, `sysconf(_SC_PAGESIZE)` must match. This is how the
  4K and 16K builds of 6.1.162 are told apart.
- `conf/dirty/` profiles additionally check `device_model`,
  `android_release` and `sdk_int`.
- `conf/samsung/` profiles use `release_prefix` (matched at `-` boundaries) and
  are only scanned in Samsung mode. The generic scanner never sees them.
- A profile must never be selected by device name alone; the kernel build is
  the identity.

### Adding support

Adding a kernel means adding one `conf/*.conf`; the exploit source does not
change. The profile must be derived from the exact factory
`boot.img`/`vendor_boot.img` (kallsyms + BTF),for the procedure and
[PORT_LOG.md](../PORT_LOG.md) for the evidence format. Do not add a row here as
`tested` until F15/F16 pass on hardware.
