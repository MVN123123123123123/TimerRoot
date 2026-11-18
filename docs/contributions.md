# Contributions and credits

TimerRoot builds on a part of other people's exploit research, root managers, Shizuku
plumbing and vendor-specific kernel ports. This page lists every project this
repository took code, constants or a design from. None of the target-specific
ports below are vendored: their code is not in this tree, and they are credited
as the source of the object layout, page-reuse strategy or constant tables that
were re-derived here.

## Upstream projects

| Project | License | Used for |
|---|---|---|
| [YuKongA/CVE-2026-98260](https://github.com/YuKongA/CVE-2026-98260) | MIT | The exploit itself, including the trigger, spray, erase/reap primitive and the `target`/`shell`/`fake` modes. |
| [V4bel/InfinityCore](https://github.com/V4bel/InfinityCore) | — | Public vulnerability discovery and analysis of CVE-2026-98260. |
| [RikkaApps/Shizuku](https://github.com/RikkaApps/Shizuku) | Apache-2.0 | The shell-domain execution environment the exploit runs in. |
| [RikkaApps/Shizuku-API](https://github.com/RikkaApps/Shizuku-API) | Apache-2.0 | The user-service AIDL, provider and client API used by the app. |
| [tiann/KernelSU](https://github.com/tiann/KernelSU) | GPL-2.0 | Generic KernelSU late-load path. |
| [diabl0w/KernelSU](https://github.com/diabl0w/KernelSU) | GPL-2.0 | The pinned Samsung build (`samsung-v*`) used by Samsung mode and its bundled `ksud`. |
| [rifsxd/KernelSU-Next](https://github.com/rifsxd/KernelSU-Next) | GPL-2.0 | Supported generic late-load manager. |
| [SukiSU-Ultra/SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra) | GPL-2.0 | Supported generic late-load manager. |
| [rikumi/TimerRoot](https://github.com/rikumi/TimerRoot) | — | The HOCON conf-driven profile mechanism, runtime conf selection (release, page size and dirty-device identity checks), and the vendor profiles under `conf/` that were ported from it. |
| [kpgc10kai/TimerRoot](https://github.com/kpgc10kai/TimerRoot) | — | Original repository this fork is based on. |
| [jonrazta89/SamTimer](https://github.com/jonrazta89/SamTimer) | — | Samsung Galaxy S24 / S26 Ultra constants (DEFEX, KDP and ksud layout) used as the basis of `conf/samsung/samsung-s26u-6.1.162.conf`. |

The exploit lineage also includes **woshigenm** and the other public 98260
ports that the upstream exploit was built from.

## Per-device profile sources

The Xiaomi / Redmi / Samsung profiles below were derived from each device's own
factory `boot.img` (kallsyms + BTF) with the procedure in
[SKILL.md](../SKILL.md), and cross-checked against these target-specific ports.

- [zsw125/o3root](https://github.com/zsw125/o3root) — Xiaomi `yingtian` /
  `lhasa`, kernel `6.18.21-android17-5-g805aa6adea19-abogki565292102`. Source
  of the 6.18 object layout (`k_itimer` `0x180`, `cpu_timer` at `+0xe0`), the
  extended `cred_security_struct`, the `selinux_state - 7` write and the
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

The other Xiaomi / Redmi profiles (`flourite`, `lapis`, `dada`, `kunzite`,
`mist`, `spinel`, `charoite`, `zephyr`, `brussels`, `hongkong`, `madrid`) were
derived from their own factory images without a target-specific port to
cross-check against. The OPPO, realme and Meizu profiles are imported vendor
profiles from `rikumi/TimerRoot`. the Samsung profiles are mostly self-ported.

## License notes

The app code in this repository is MIT. The exploit keeps its authors' MIT
license. Shizuku and Shizuku-API are Apache-2.0. KernelSU and its variants are
GPL-2.0. See [LICENSE](../LICENSE) for the app license text.
