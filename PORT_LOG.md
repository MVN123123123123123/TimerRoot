# Port log

Per-gate evidence for every profile added to `conf/`. The procedure is
[`SKILL.md`](SKILL.md); this file is the record that it was followed.

A gate is only marked **pass** when it was actually run. F7–F11 were run
against the factory kernels in QEMU. Gates that need real userspace or
hardware (F12–F16) stay **pending**, and the README separates
`verified in QEMU` from `tested`.

Two things were run before the QEMU pass, and neither replaced a device run:

- `validate_conf.py` re-derives every constant from the factory `vmlinux` +
  BTF and diffs it against the conf.
- A throwaway x86 host build of `timer_p7a.c`, with the one `uname` line
  patched to accept `FAKE_REL`, was used to exercise `load_conf()` against
  every profile: `target` mode and `selfcheck` mode, plus a deliberately wrong
  banner to confirm it is refused. This checks the parser, the release match,
  the page-size check, the F6 invariants and the `target=` output — but it is
  **not** the aarch64 binary, and it does not touch a real kernel.

The shipped aarch64 binary was then run against the factory kernels in
`qemu-system-aarch64`: 18 of the 22 profiles pass F7–F11 there, including
every profile added for the Redmi Note 15/17 ports. Section
[F14](#f14--qemu-mass-run) has the per-profile table and the procedure.
F12 and F13 need a device.

Everything below was derived from the **factory `boot.img` of the exact build**
named in each section, never from a running device.

---

## Method

All profiles were produced with the same tools, kept out of the repository
in `/mnt/integral/timerroot-port/work/xi/`:

| tool | purpose |
|---|---|
| `get_hdr.py` | reads the `payload.bin` header via HTTP range requests |
| `fetch_part.py` | pulls one partition out of the OTA zip with 24 × 256 KiB range workers |
| `fetchvb.sh`, `fetchdtbo_all.sh` | same for `vendor_boot` / `dtbo` |
| `derive.py` | `timer_site`, `copy_process_low21`, kallsyms, BTF sizes |
| `sitecheck.py` | resolves *which* `kmem_cache_alloc*` call feeds `posix_timers_cache` / `task_struct_cachep` |
| `blobsim2.py` | `selinux_blob_off` from the runtime `CONFIG_LSM` registration order |
| `evidence.py` | regenerates the F2–F5 tables below straight from vmlinux + BTF |
| `validate_conf.py` | F6 invariants plus a cross-check of every conf against its vmlinux |

`unpack_bootimg`, `vmlinux-to-elf`, `bpftool`, `llvm-objdump`, `nm` from the
usual toolchain. No kernel source, no running device, no `slabinfo`.

The OTA zips are ~10 GB each, so they were read with HTTP range requests and
never downloaded whole; the extracted `boot.img` / `vendor_boot.img` /
`dtbo.img` / `vmlinux` stay outside the repository.

---

## Vulnerability check (F1 prerequisite)

`SKILL.md` requires the bug to still be present. For each kernel,
`begin_new_exec()` was disassembled and the call order checked. The fix moves
`posix_cpu_timers_exit()` past `de_thread()`; the vulnerable order still has
`exit_itimers()` afterwards.

| device | `begin_new_exec` call order | vulnerable |
|---|---|---|
| dada, iolite, kunzite, mist | `exec_mmap`, `exec_task_namespaces`, **`posix_cpu_timers_exit`**, `exit_itimers` | yes |
| flourite, lapis | `exec_mmap`, **`posix_cpu_timers_exit`**, `exit_itimers` | yes |
| lhasa, popsicle | `exec_task_namespaces`, **`posix_cpu_timers_exit`**, `exit_itimers` | yes |
| hongkong, madrid | `exec_mmap`, `exec_task_namespaces`, **`posix_cpu_timers_exit`**, `exit_itimers` | yes |
| Pixel 11 (cubs etc.) | `exec_mmap`, `exec_task_namespaces`, **`posix_cpu_timers_exit`**, `exit_itimers` | yes |

Order at `begin_new_exec` is the whole exploit: the stale `k_itimer` is put on
the timerqueue, `exec_mmap`/`exec_task_namespaces` free and replace the mm and
the nsproxy, `posix_cpu_timers_exit` is the last user of the pids, and
`exit_itimers` is what happens *after* the timerqueue node was already dropped.
Keep `posix_cpu_timers_exit` before `exit_itimers` and the reclaimed slab is
still reachable.

---

## Shared derivations

These are the same reasoning on every device; the per-device values follow.

### `timer_site` (F3)

`posix_timers_cache` is `kmem_cache_create`d in `init_posix_timers()` /
`posixtimer_init()`, and the object is allocated in `do_timer_create()` (6.6 and
6.1) or `alloc_posix_timer()` (6.12 and 6.18). The call is identified **by the
sequence**, not by name: the register feeding `x0` is `adrp`+`ldr` from the
global that the init function stores `kmem_cache_create`'s return value into.
`sitecheck.py` does that dataflow for both globals and prints which one each
call site uses, which is how the 6.18 double-allocation in `do_timer_create`
(profiling vs normal path) was separated.

`timer_site` is the **return address** (`bl` + 4): the caller reloads `x0` there
and the exploit's planted fake timerqueue node is what that reload sees.

### `copy_process_low21` (F3)

The `task_struct` allocation is
`kmem_cache_alloc_node_noprof(task_struct_cachep, ...)`, reached from
`copy_process()` either directly (6.6, 6.12 — `dup_task_struct` is inlined) or
through a standalone `dup_task_struct` (6.1, 6.18). The constant is the low 21
bits of that return address, because the exploit scans trace records for a
21-bit match; on 6.1/6.18 the value was read from the `dup_task_struct` body,
which is where the call actually lives on those builds.

### `timer_alloc` and `timer_node_off` (F4)

`timer_alloc` is the `size` argument to the cache creation, read straight out of
the `mov w1, #…` that precedes the `bl`. `timer_node_off` is
`offsetof(struct k_itimer, it)` + `offsetof(struct cpu_timer, node)`, from BTF;
`struct cpu_timer` starts with `node`, so it is just `offsetof(k_itimer, it)`.
It is `0x78` everywhere except 6.18, where `k_itimer` grew a `rcuref`:

| family | `sizeof(k_itimer)` | `it` | node |
|---|---|---|---|
| 5.15 / 6.1 / 6.6 | `0x108` | `0x78` | `0x78` |
| 6.12 | `0x100` | `0x78` | `0x78` |
| 6.18 | `0x180` | `0xe0` | `0xe0` |

### `cred_*` / `fake_*` (F4)

All offsets come from BTF `struct cred` and the `cred_jar` creation:

```
cred_init: mov w1, #<sizeof cred>; mov w3, #SLAB_HWCACHE_ALIGN|…
```

The object size is `ALIGN(request, 64)`. The only structural difference between
the two layouts is `cred.usage`:

- **8-byte `atomic_long_t usage`** (6.6, 6.12, 6.18): `uid` at `+0x8`,
  `securebits` at `+0x28`, caps at `+0x30`, `security` at `+0x80`.
- **4-byte `atomic_t usage`** (5.15, 6.1): everything shifts down by 8: `uid`
  at `+0x4`, `securebits` at `+0x24`, caps at `+0x28`, `security` at `+0x78`.

`fake_cred_off` stays `0x18` on both because it is a property of the rb_node
erase (`node[0x10]` must fall outside the cred; `node[0x20]` is zeroed and must
land on a uid/gid word), not of the cred layout — see `SKILL.md` §5. The
`fake_*` fields are just `fake_cred_off + cred_<field>_off`, and
`fake_caps_off >= 0x28` avoids the `c[]` overlay colliding with `securebits`.

### `task_alloc_bytes` (F4)

`arch_task_struct_size` starts at `sizeof(struct task_struct)` (BTF) and
`task_struct_vendor_size_setup()` adds `android_arch_task_struct_size` from the
command line, **if the parameter is present**:

```
task_struct_vendor_size_setup:
  …
  bl memparse
  cmp x0, #0x500            ; max vendor ext: 0x500 on 6.18, 0x400 on 6.12/6.6
  b.ls …
  mov w9, #0x1280           ; sizeof(task_struct); 0x1440 on 6.12, 0x12c0 on 6.6
  add w8, w8, w9            ; arch_task_struct_size = vendor + sizeof
  str w8, [x9, #0xf0c]
```

The 6.6/6.1 kernels here all *have* the parameter support (the string is in
`.init.rodata`, `start_kernel` initialises `arch_task_struct_size` to `0x12c0`)
but their factory `boot`/`vendor_boot`/`dtbo` images never set it, so the value
stays `0x12c0`. The 6.12/6.18 images do set it (`=1024` for the 6.18, `=784`
for the Pixel 11), so those caches are bigger:

| family | `sizeof(task_struct)` | vendor ext | `task_alloc_bytes` |
|---|---|---|---|
| 5.15 | `0x1200` | — | `0x1200` |
| 6.1 | `0x12c0` | — | `0x12c0` |
| 6.6 | `0x12c0` | none in image | `0x12c0` |
| 6.18 | `0x1280` | `1024` | `0x1680` |
| 6.12 4G/5G (spinel/charoite/brussels) | `0x1440` | `512` | `0x1640` |
| 6.12 popsicle | `0x1440` | `1024` | `0x1840` |
| 6.12 Pixel 11 | `0x1440` | `784` | `0x1750` |

### `selinux_blob_off` (F5/§4)

This is the one constant that is *not* a kallsyms or BTF lookup, and it is the
one that was wrong in an earlier draft of these profiles. It is the offset of
`task_security_struct` inside the aggregate LSM cred blob, assigned by
`lsm_set_blob_sizes()` in **registration order**, i.e. the runtime
`CONFIG_LSM=` order, not link order:

```
for each lsm in order:
    ALIGN(total, 8)  -> blob->lsm_cred_off
    total += lsm_blob_sizes.lbs_cred
```

`blobsim2.py` reconstructs the order from `__start_lsm_info`/`__end_lsm_info`
plus the built-in `CONFIG_LSM` string, and reads each LSM's `lbs_cred` from its
`<lsm>_blob_sizes` object:

| family | effective order | `lbs_cred` | `selinux_blob_off` |
|---|---|---|---|
| 5.15 zephyr | capability, integrity, selinux | selinux 24 | `0x0` |
| 6.1 flourite/lapis | capability, integrity, selinux | selinux 24 | `0x0` |
| 6.6 dada/iolite/kunzite/mist | capability, selinux, bpf, integrity | selinux 24 | `0x0` |
| 6.12 charoite | capability, selinux, bpf | selinux 24 | `0x0` |
| 6.12 spinel/brussels | capability, **landlock 8**, safesetid, selinux, bpf | landlock 8 | `0x8` |
| 6.12 popsicle | capability, **landlock 8**, safesetid, selinux, bpf | landlock 8 | `0x8` |
| 6.18 lhasa/hongkong/madrid | capability, **landlock 11**, safesetid, selinux, bpf | landlock 11 → ALIGN(11,8)=16 | `0x10` |

The 6.1/6.6 kernels do **not** register a landlock cred blob (there is no
`landlock_blob_sizes` symbol at all, and landlock is absent from the effective
list), so SELinux is the first contributor and its offset is 0. Deriving this
from the `landlock,lockdown,...` string alone would have produced `0x8`/`0x10`
for the 6.6 kernels and corrupted the child's SID.

`selinux_state - 7` was re-validated on every kernel: BTF puts `enforcing` at
`+0` of `struct selinux_state`. On every profile except zephyr the symbol
immediately below `selinux_state - 8` is
`avc_latest_notify_update.notif_lock`, so the `-7` store lands on `enforcing`'s
low byte and not in the preceding lock. zephyr has no adjacent symbol: the
previous object is `sel_netport_hash`, `0x1800` lower, so the 8-byte store at
`selinux_state - 7` lands in padding (not inside another object).

---

## 6.18.21 — Xiaomi 18 Pro / Pro Max / Fold, Pad 9 Pro Max

### hongkong + madrid — `6.18.21-android17-5-g284297031c53-abogki555938958-4k`

- **F1** `hongkong` (Xiaomi 18 Pro) `OS4.0.29.0.XFRCNXM`; `madrid`
  (Xiaomi 18 Pro Max) `OS4.0.27.0.XEOCNXM`. Both 4K pages.
- **F2** kernel `sha256 0a3cf0d220490927ce1ee9db380adfdd20930fc0e602b97dd652d610bbe9d3fe`,
  byte-identical on both devices; 142 294 kallsyms symbols; `.BTF` present.
  `boot.img` sha256 `36fdd3bf…` (hongkong) / `3902bf21…` (madrid).
- **F3** `posixtimer_init` creates the cache with `size=0x180`; the object comes
  from `do_timer_create` via `bl kmem_cache_alloc_noprof` at
  `0xffffffc080211130` → **`timer_site = 0xffffffc080211134`**.
  `copy_process` → `bl kmem_cache_alloc_node_noprof` at `0xffffffc0800f4c0c`
  → **`copy_process_low21 = 0xf4c10`**.
- **F4** BTF: `cred` `0xb8` (uid `0x8`, euid `0x18`, caps `0x30`,
  security `0x80`); `task_struct` `0x1280`, cred `0x908`; `k_itimer` `0x180`,
  `it` `0xe0`. `cred_init` requests `0xb8` → object `0xc0`.
  `task_alloc_bytes = 0x1280 + 0x400 = 0x1680`.
- **F5** `selinux_state 0xffffffc082918630`, `panic_on_warn 0xffffffc08266bf10`,
  `root_user 0xffffffc082691388`, `init_user_ns 0xffffffc0826910d8`,
  `init_ucounts 0xffffffc082692f08`, `init_groups 0xffffffc082692a48`.
  `selinux_blob_off = 0x10` (landlock registers 11 bytes first).
- **F6** `validate_conf.py` cross-checks all six symbols, both call sites and
  the BTF sizes against the vmlinux: 0 errors. `--selfcheck`: 0 failures.

### lhasa + yingtian — `6.18.21-android17-5-g805aa6adea19-abogki565292102-4k`

- **F1** `lhasa` (Xiaomi 18 Fold) `OS4.0.26.0.XPNCNXM`; `yingtian`
  (Pad 9 Pro Max) `OS4.0.16.0.XBMCNXM`. `dump_display.fingerprint` in the
  vendor cmdline reads `lhasa:AndroidX/OS4.0.26.0.XPNCN:user`, which ties that
  image to the build. 4K pages.
- **F2** kernel `sha256 cde87cd70206f21db4359aa1148f5f68e693ffefb11108dffde99c07c8c5ad88`;
  145 896 symbols; BTF present.
- **F3** `alloc_posix_timer` calls `bl kmem_cache_alloc_noprof` at
  `0xffffffc0803a7268` → **`timer_site = 0xffffffc0803a726c`**. The function
  has a second alloc site at `…72cc`, but that one brackets the call with
  `current->alloc_tag` swaps (the `mem_alloc_profiling_key` path), so it is not
  the configured one.
  `copy_process` → `bl kmem_cache_alloc_node_noprof` at `0xffffffc0801f0068`
  → **`copy_process_low21 = 0x1f006c`**.
- **F4** same BTF layout as hongkong: `cred` `0xb8`, `task_struct` `0x1280`
  (cred `0x908`), `k_itimer` `0x180` (`it` `0xe0`).
  `task_alloc_bytes = 0x1680`.
- **F5** `selinux_state 0xffffffc082959630`, `panic_on_warn 0xffffffc0826abf10`,
  `root_user 0xffffffc0826d1388`, `init_user_ns 0xffffffc0826d10d8`,
  `init_ucounts 0xffffffc0826d2f08`, `init_groups 0xffffffc0826d2a48`.
  `selinux_blob_off = 0x10`.
- **F6** 0 errors, `--selfcheck` 0 failures. This is the only family where the
  worst-case object still fits: node `0x1ee0` + cred end `0x1fb0` < `0x2000`.

---

## 6.12.69 — Pixel 11 series

### `6.12.69-android16-6-g70777328ed0e-ab16108597-4k`

- **F1** `cubs` / `grizzly` / `kodiak` / `yogi` (Pixel 11, 11 Pro, 11 Pro XL,
  11 Pro Fold), builds `CD1A.261005.003` and `.b1`. 4K pages.
- **F2** all five `boot.img` variants unpack to the same kernel,
  `sha256 4417511834260f72c1b6a5bb9b9f809dfb6734b20fd7e8aa156c3c1f91f0f97b`
  (cubs, cubs-b1, grizzly, kodiak, yogi each verified separately); 131 885
  symbols; BTF present.
- **F3** cache creation `size=0x100`; `do_timer_create` has two
  `bl kmem_cache_alloc_noprof` sites, `…34fc` and `…3868`. The second also
  brackets the call with `current->alloc_tag` stores, so it is the profiling
  path; the configured one is `…34fc` → **`timer_site = 0xffffffc080363500`**.
  `copy_process` → `bl kmem_cache_alloc_node_noprof` at `…e7f78`
  → **`copy_process_low21 = 0xe7f7c`**.
- **F4** BTF: `cred` `0xb8`; `task_struct` `0x1440`, cred `0x900`;
  `k_itimer` `0x100`, `it` `0x78` → `timer_node_off = 0x78`.
  `task_alloc_bytes = 0x1440 + 0x310 = 0x1750` — the vendor extension here is
  `android_arch_task_struct_size=784`, from the vendor_boot dtb, not 1024.
- **F5** `selinux_state 0xffffffc082887890`, `panic_on_warn 0xffffffc0825dade0`,
  `root_user 0xffffffc082602170`, `init_user_ns 0xffffffc082601ef8`,
  `init_ucounts 0xffffffc082603b08`, `init_groups 0xffffffc082603638`.
  `selinux_blob_off = 0x8`.
- **F6** 0 errors, `--selfcheck` 0 failures. Worst case spills by `0x48` into
  the next object; `run_plant()` retries there by design.

---

## 6.12.69 — Xiaomi 17 Pro Max

### popsicle — `6.12.69-android16-6-g43b5ab7e247d-abogki558343811-4k`

- **F1** `popsicle` (Xiaomi 17 Pro Max) `OS4.0.5.0.XPBCNXM`. 4K pages.
- **F2** kernel `sha256 f6cf6ea11ea55b989b551f97a7cc1f83368ba7d9367d6e1cbd86b1752e82c998`;
  133 626 symbols; BTF present.
- **F3** `init_posix_timers` creates the cache with `size=0x100`;
  `alloc_posix_timer` → `bl kmem_cache_alloc_noprof` at `0xffffffc080579aac`
  → **`timer_site = 0xffffffc080579ab0`**.
  `copy_process` → `bl kmem_cache_alloc_node_noprof` at `0xffffffc080191d38`
  → **`copy_process_low21 = 0x191d3c`**.
- **F4** BTF: `cred` `0xb8`; `task_struct` `0x1440`, cred `0x900`;
  `k_itimer` `0x100`, `it` `0x78`. `task_alloc_bytes = 0x1440 + 0x400 = 0x1840`
  (vendor extension is 1024 here, unlike the Pixel 11).
- **F5** `selinux_state 0xffffffc08289aba0`, `panic_on_warn 0xffffffc0825eade0`,
  `root_user 0xffffffc0826121f0`, `init_user_ns 0xffffffc082611f78`,
  `init_ucounts 0xffffffc082613b88`, `init_groups 0xffffffc0826136b8`.
  `selinux_blob_off = 0x8` (landlock contributes 8 bytes on 6.12).
- **F6** 0 errors, `--selfcheck` 0 failures.

The rest of the 17 series — `pudding`, `pandora`, `nezha`, `byron` — ship a
different kernel (`…-abogki561813157`), which is byte-identical across all four
(`sha256 ed9e27aa…`) and is already covered by the upstream profile
`conf/6.12.69-android16-6-g43b5ab7e247d-abogki561813157-4k.conf`. Their
`boot.img`s were unpacked to confirm they match that payload, so no new profile
was needed.

---

## 6.6.118 — Xiaomi 15, Redmi Note 15 / 17

Four devices, two distinct text layouts. All four are 4K, `cred` `0xb8`,
`task_struct` `0x12c0` (cred `0x820`), `k_itimer` `0x108` (`it` `0x78`),
`copy_process_low21 0xab93c`, `task_alloc_bytes 0x12c0`, and
`selinux_blob_off 0x0` (no landlock cred blob).

| device | codename | build | kernel sha256 (16) | `timer_site` |
|---|---|---|---|---|
| Xiaomi 15 | `dada` | `OS3.0.307.0.WOCCNXM` | `3ea8e88cc67b206d` | `0xffffffc080195d94` |
| Redmi Note 17 Pro 5G | `iolite` | `OS3.0.314.0.WDQCNXM` | `1b79cadcee836a77` | `0xffffffc080195d94` |
| Redmi Note 15 5G | `kunzite` | `OS3.0.304.0.WPQCNXM` | `81181e8321e655ac` | `0xffffffc080195d48` |
| Redmi Note 17 5G | `mist` | `OS3.0.311.0.WPUCNXM` | `b7826ac3d30f03a7` | `0xffffffc080195d48` |

- **F2** 110 239 / 110 305 / 110 104 / 110 109 symbols respectively; BTF
  present on all four.
- **F3** `do_timer_create` → `bl kmem_cache_alloc` (note: the non-`_noprof`
  name on 6.6) at `site − 4`, cache `size=0x108`.
  `copy_process` → `bl kmem_cache_alloc_node` at `0xffffffc0800ab938`
  → `0xab93c`, identical on all four.
- **F4** `cred_init: mov w1, #0xb8` → object `0xc0`.
  `task_struct_vendor_size_setup` exists and adds `0x12c0` only when the
  parameter is present; none of these images sets it.
- **F5** dada/iolite: `selinux_state 0xffffffc08237a378`,
  `panic_on_warn 0xffffffc08212ae0c`, `root_user 0xffffffc08214f220`,
  `init_user_ns 0xffffffc08214ef90`, `init_ucounts 0xffffffc082150cf0`,
  `init_groups 0xffffffc082150780`.
  kunzite/mist: `selinux_state 0xffffffc08236a2e0`,
  `panic_on_warn 0xffffffc08211ae0c`, `root_user 0xffffffc08213f1e0`,
  `init_user_ns 0xffffffc08213ef50`, `init_ucounts 0xffffffc082140cb0`,
  `init_groups 0xffffffc082140740`. All six re-checked against each vmlinux.
- **F6** 0 errors and `--selfcheck` 0 failures on all four.

Note: `quyicheng03-boop/CVE-2026-98260-dada-android` is titled "dada" but was
built for `…-gb9cc6ec16bc8-abogki536571621`, i.e. **iolite** here. It is credited
as the source of the 6.6 slot count and the `free_slab` correlation, not as a
dada reference.

---

## 6.1.138 — Redmi Note 15 Pro series

### flourite — `6.1.138-android14-11-g0c3d559bcd85-ab14529422`

- **F1** `flourite` (Redmi Note 15 Pro+ 5G) `OS3.0.318.0.WPRCNXM`. 4K pages.
- **F2** kernel `sha256 97b2c53022e8c0bd0b279c4c592a196126a6eb0a93647c2957b39dcd5f2dc1c9`;
  101 741 symbols; BTF present.
- **F3** `init_posix_timers` → cache `size=0x108`; `do_timer_create` →
  `bl kmem_cache_alloc` at `0xffffffc008192088`
  → **`timer_site = 0xffffffc00819208c`** (note the 6.1 `__pi_` base
  `0xffffffc008…`). `copy_process` → `bl kmem_cache_alloc_node` at
  `0xffffffc0080ab67c` → **`copy_process_low21 = 0xab680`**.
- **F4** BTF: `cred` `0xb0` — **4-byte `usage`**, so uid `0x4`, euid `0x14`,
  caps `0x28`, security `0x78`; `task_struct` `0x12c0`, cred `0x838`;
  `k_itimer` `0x108`, `it` `0x78`. `cred_init: mov w1, #0xb0` → object `0xc0`.
  `task_alloc_bytes = 0x12c0` (no `task_struct_vendor_size_setup` on 6.1).
- **F5** `selinux_state 0xffffffc00a2293d0`, `panic_on_warn 0xffffffc009fdae08`,
  `root_user 0xffffffc00a000740`, `init_user_ns 0xffffffc00a0004b0`,
  `init_ucounts 0xffffffc00a001fc8`, `init_groups 0xffffffc00a001a60`.
  `selinux_blob_off = 0x0`.
- **F6** 0 errors, `--selfcheck` 0 failures. `pcp_free = 1`: 6.1 frees the
  order-1 slab through the PCP lists, so the reclaim burst is also gated on
  `/proc/slabinfo`, as in the tested 6.1.162 Pixel profile.

### lapis — `6.1.138-android14-11-g51f8c580613d-ab13911623`

- **F1** `lapis` (Redmi Note 15 Pro 5G) `OS3.0.309.0.WPPCNXM`. 4K pages.
- **F2** kernel `sha256 06025bef4202b7635397ce29fafd0a23c780192449b641df0b0fe4be572a0bfd`;
  101 700 symbols; BTF present.
- **F3** `do_timer_create` → `bl kmem_cache_alloc` at `0xffffffc008191af4`
  → **`timer_site = 0xffffffc008191af8`**. `copy_process_low21 = 0xab680`
  (same as flourite).
- **F4/F5** identical layout and symbol values to flourite except
  `timer_site`; `selinux_state` is the same `0xffffffc00a2293d0`, so these two
  differ only in `.text`.
- **F6** 0 errors, `--selfcheck` 0 failures.

The two 6.1 devices are **different kernels**, not one profile with two names:
the `do_timer_create` call sites differ, which is exactly the kind of near-miss
`SKILL.md` F1 warns about.

---

## Redmi Note 15/17 standalone-payload variants

Four devices, four distinct kernel payloads. Three are 4G models; `brussels` is
the 5G Redmi Note 17 Pro Max. All are 4K-page builds and all were checked for
the F1 vulnerability (`posix_cpu_timers_exit` before
`exit_itimers` in `begin_new_exec`). The three 6.12 images carry
`android_arch_task_struct_size=512` in their vendor `dtb`/bootconfig, so
`task_struct_vendor_size_setup()` computes `0x1440 + 0x200 = 0x1640`; the 5.15
image has no vendor-size setup and keeps `0x1200`.

### spinel — `6.12.69-android16-6-g014ca48a80ee-ab15889839-4k`

- **F1** `spinel` (Redmi Note 15 4G) `OS3.0.303.0.WPGMIXM`. 4K pages.
- **F2** kernel `sha256 f64f20093c13ced2dd765235ae1acdc52b19fd7bb143578a883a93dc28f35896`;
  132 087 symbols; BTF present (kernel is LZ4-compressed in `boot.img`, BTF
  extracted from the decompressed Image).
- **F3** `init_posix_timers` → cache `size=0x100`; `do_timer_create` →
  `bl kmem_cache_alloc_noprof` at `0xffffffc0803718f0`
  → **`timer_site = 0xffffffc0803718f4`**. The second site at `…1c60` brackets
  the call with `current->alloc_tag` stores (profiling path).
  `copy_process` → `bl kmem_cache_alloc_node_noprof` at `0xffffffc0800e94a0`
  → **`copy_process_low21 = 0xe94a4`**.
- **F4** BTF: `cred` `0xb8` (uid `0x8`, euid `0x18`, caps `0x30`,
  security `0x80`); `task_struct` `0x1440`, cred `0x900`; `k_itimer` `0x100`,
  `it` `0x78`. `task_alloc_bytes = 0x1440 + 0x200 = 0x1640`.
- **F5** `selinux_state 0xffffffc082888890`, `panic_on_warn 0xffffffc0825dade0`,
  `root_user 0xffffffc082602170`, `init_user_ns 0xffffffc082601ef8`,
  `init_ucounts 0xffffffc082603b08`, `init_groups 0xffffffc082603638`.
  `selinux_blob_off = 0x8` (landlock contributes 8 bytes first).
- **F6** `validate_conf.py` cross-checks both call sites, the six symbols and
  the BTF sizes: 0 errors; `alloc_req_off = 0x10` matches BTF. `--selfcheck`:
  0 failures.

### charoite — `6.12.30-android16-5-g6e872b4863d6-ab13847919-4k`

- **F1** `charoite` (Redmi Note 15 Pro 4G) `OS3.0.304.0.WPFMIXM`. 4K pages.
- **F2** kernel `sha256 e4121682a5dc9e637710642eb4daaea57697f3b501a959715c4cc323f3e15e35`;
  125 378 symbols; BTF present (also LZ4-compressed in `boot.img`).
- **F3** `init_posix_timers` → cache `size=0x100`; `do_timer_create` →
  `bl kmem_cache_alloc_noprof` at `0xffffffc0801e1a10`
  → **`timer_site = 0xffffffc0801e1a14`**. The second site at `…1ec4` is the
  `current->alloc_tag` profiling path. `copy_process` calls
  `dup_task_struct`, whose `bl kmem_cache_alloc_node_noprof` at
  `0xffffffc0800d1594` returns to `0xffffffc0800d1598`
  → **`copy_process_low21 = 0xd1598`**. The second site at `…d1940` is the
  `current->alloc_tag` profiling path.
- **F4** same 6.12 BTF layout as spinel: `cred` `0xb8`, `task_struct` `0x1440`
  (cred `0x900`), `k_itimer` `0x100` (`it` `0x78`).
  `task_alloc_bytes = 0x1640` (vendor extension is 512).
- **F5** `selinux_state 0xffffffc0826784b8`, `panic_on_warn 0xffffffc0823eafe0`,
  `root_user 0xffffffc0824117a0`, `init_user_ns 0xffffffc082411528`,
  `init_ucounts 0xffffffc082413138`, `init_groups 0xffffffc082412c68`.
  `selinux_blob_off = 0x0`: unlike spinel, this kernel does not register a
  landlock cred blob.
- **F6** 0 errors, `--selfcheck` 0 failures.

### zephyr — `5.15.194-android13-8-00015-gf5526d1116e5-ab15004895`

- **F1** `zephyr` (Redmi Note 17 4G) `OS3.0.311.0.WBUMIXM`. 4K pages. This is
  the only 5.15 profile in the repository; the release string has no `-4k`
  suffix.
- **F2** kernel `sha256 7ca3f0c9b3130813fa4d24c9017936acf25dca2c54f7eb7fa716894470aeaa51`;
  159 568 symbols; BTF present. Text/data use the `0xffffffc008…` `__pi_` base.
- **F3** `init_posix_timers` is emitted as
  `__initstub__kmod_posix_timers__386_281_init_posix_timers6.cfi` and calls
  `kmem_cache_create_usercopy("posix_timers_cache", 0x108, …)`.
  `do_timer_create` → `bl kmem_cache_alloc` at `0xffffffc00827ecd8`
  → **`timer_site = 0xffffffc00827ecdc`**. `copy_process` calls
  `dup_task_struct`, whose `bl kmem_cache_alloc` (5.15 has no `_node` variant
  here) at `0xffffffc008132d10` returns to `0xffffffc008132d14`
  → **`copy_process_low21 = 0x132d14`**.
  `validate_conf.py`'s generic `copy_process` regex only matches
  `kmem_cache_alloc.*node`, so this one site was confirmed by `sitecheck.py`
  (source register loads `task_struct_cachep`) rather than by the automated
  cross-check.
- **F4** BTF: `cred` `0xb0` — **4-byte `usage`**, uid `0x4`, euid `0x14`, caps
  `0x28`, security `0x78`; `task_struct` `0x1200`, cred `0x798`; `k_itimer`
  `0x108`, `it` `0x78`. `fork_init()` passes `0x1200` directly to
  `kmem_cache_create_usercopy`; there is no `task_struct_vendor_size_setup`,
  and `arch_task_struct_size` is absent. `pcp_free = 1`: the order-1 slab is
  freed through the PCP lists, so the same slabinfo gate as the 6.1 profiles
  is used.
- **F5** `selinux_state 0xffffffc00adbad88`, `panic_on_warn 0xffffffc00ab0add0`,
  `root_user 0xffffffc00ab32770`, `init_user_ns 0xffffffc00acde250`,
  `init_ucounts 0xffffffc00ab33ff0`, `init_groups 0xffffffc00ab33b28`.
  `selinux_blob_off = 0x0`. The `selinux_state - 8` slot is not another symbol
  (the nearest previous object is `sel_netport_hash`, `0x1800` below), so the
  `-7` store lands in padding rather than in an adjacent lock.
- **F6** 0 errors, `--selfcheck` 0 failures. BTF names the trace event
  `trace_event_raw_kmem_alloc` (not `…_kmem_cache_alloc`); `bytes_req -
  call_site` is still `0x10`, the default.

### brussels — `6.12.69-android16-6-g586bfab1b9c5-abogki537510563-4k`

- **F1** `brussels` (Redmi Note 17 Pro Max 5G) `OS3.0.311.0.WDRMIXM`. 4K pages.
- **F2** kernel `sha256 604c9daab8b9f9889a23b31659f8f9f5e3488350218a3fa88c84e192f0460c3b`;
  133 582 symbols; BTF present.
- **F3** `init_posix_timers` → cache `size=0x100`; `alloc_posix_timer` →
  `bl kmem_cache_alloc_noprof` at `0xffffffc080579aa0`
  → **`timer_site = 0xffffffc080579aa4`**. The second site at `…9b1c` is the
  profiling path. `copy_process` → `bl kmem_cache_alloc_node_noprof` at
  `0xffffffc080194770` → **`copy_process_low21 = 0x194774`**.
- **F4** same 6.12 BTF layout as spinel: `cred` `0xb8`, `task_struct` `0x1440`
  (cred `0x900`), `k_itimer` `0x100` (`it` `0x78`).
  `task_alloc_bytes = 0x1640`.
- **F5** `selinux_state 0xffffffc08289abc8`, `panic_on_warn 0xffffffc0825eade0`,
  `root_user 0xffffffc0826121f0`, `init_user_ns 0xffffffc082611f78`,
  `init_ucounts 0xffffffc082613b88`, `init_groups 0xffffffc0826136b8`.
  `selinux_blob_off = 0x8` (landlock contributes 8 bytes first).
- **F6** 0 errors; `alloc_req_off = 0x10` matches BTF. `--selfcheck`:
  0 failures.

---

## Gate status

| gate | status | note |
|---|---|---|
| F1 identify | pass | banner + build + page size per device, above |
| F2 factory artifacts | pass | vmlinux with kallsyms + `.BTF`, `boot.img` sha256 recorded |
| F3 `timer_site` / `copy_process` | pass | call site resolved by dataflow, disassembly logged |
| F4 cred / task geometry | pass | BTF + `cred_init` / `task_vendor_size_setup` disassembly |
| F5 symbols | pass | kallsyms, `-7` re-checked against the preceding symbol |
| F6 build the profile | pass | `validate_conf.py` 0 errors; `--selfcheck` 0 failures (host build) |
| F7 `timer target` | pass (QEMU) | all 18 profiles print their own `timer_site`, exit 0 |
| F8 `timer ids` | pass (QEMU) | page event ids resolved in every profile |
| F9 `timer probe` | pass (QEMU) | base vote + `pair pfn` agreement on every profile |
| F10 `timer leak` | pass (QEMU) | 512/512 base votes, cred leaked on the first attempt |
| F11 verify | pass (QEMU) | zero-write child reaches `resuid=0/0/0`, `ROOT_SHELL_OK` |
| F12 permissive | pending | needs SELinux policy, not just the LSM being compiled in |
| F13 `timer fake` | pending | needs KernelSU present |
| F14 QEMU | pass | 18/18 profiles, see below |
| F15 hardware | pending | no device |
| F16 app | defer | tables added as `verified in QEMU`; flip to `tested` only after F15 |

### F14 — QEMU mass run

Every conf whose factory Image is in the workspace was booted in
`qemu-system-aarch64 -M virt` at the profile's page size and driven through
the shipped aarch64 binary. **18 of 22 profiles ran and all 18 passed every
gate.** The other four are the imported OPPO/realme profiles
(`6.12.58-…-ab15213644-4k`, `6.12.69-…-g242e1a07f878-ab15865446-4k`,
`6.6.118-…-g9bc34d5b0c79-abogki537459655-4k`,
`6.6.66-…-abogki428889875-4k`), which have no factory artifact in the
workspace — one of them was derived from a device dump, so there is no image
to boot. `logs/mass-final.json` holds the per-profile detail.

| profile | device | slabinfo | F7 | F8 | F9 | F10 | F11 |
|---|---|---|---|---|---|---|---|
| 5.15.194-…-ab15004895 | zephyr | pass | pass | pass | pass | pass | pass |
| 6.1.138-…-ab14529422 | flourite | pass | pass | pass | pass | pass | pass |
| 6.1.138-…-ab13911623 | lapis | pass | pass | pass | pass | pass | pass |
| 6.1.162-…-ab16261587 | tegu (Pixel 8/9) | pass | pass | pass | pass | pass | pass |
| 6.1.162-…-ab16261587-16k | tegu 16K | pass | pass | pass | pass | pass | pass (retry) |
| 6.12.30-…-ab13847919-4k | charoite | pass | pass | pass | pass | pass | pass |
| 6.12.69-…-ab15889839-4k | spinel | pass | pass | pass | pass | pass | pass |
| 6.12.69-…-abogki558343811-4k | popsicle | pass | pass | pass | pass | pass | pass |
| 6.12.69-…-abogki561813157-4k | byron/pudding/nezha | pass | pass | pass | pass | pass | pass |
| 6.12.69-…-abogki537510563-4k | brussels | pass | pass | pass | pass | pass | pass |
| 6.12.69-…-ab16108597-4k | cubs (Pixel 11) | pass | pass | pass | pass | pass | pass |
| 6.18.21-…-abogki555938958-4k | hongkong/madrid | pass | pass | pass | pass | pass | pass |
| 6.18.21-…-abogki565292102-4k | lhasa/yingtian | pass | pass | pass | pass | pass | pass |
| 6.6.118-…-ab15657065-4k | mist | pass | pass | pass | pass | pass | pass |
| 6.6.118-…-abogki536571621-4k | iolite | pass | pass | pass | pass | pass | pass |
| 6.6.118-…-abogki519650608-4k | dada | pass | pass | pass | pass | pass | pass |
| 6.6.118-…-ab15511674-4k | kunzite | pass | pass | pass | pass | pass | pass |
| 6.6.127-…-ab16252310-4k | frankel (Pixel 10) | pass | pass | pass | pass | pass | pass |

This run also supplies the F2 `slabinfo` item that a device was previously
needed for. The booted kernel reports, per profile, a
`posix_timers_cache` object size equal to `timer_alloc` at the conf's
`slab_order`, and a `task_struct` object size equal to `task_alloc_bytes`
once SLUB's alignment padding is taken into account. Two numbers needed
interpretation rather than a raw comparison:

- `task_alloc_bytes` is the *requested* size. SLUB rounds the object up to
  `s->align`, so cubs reports `0x1780` for a requested `0x1750` (alignment
  64). Everything else is already aligned and matches exactly.
- `slab_order` comes from the online CPU count via SLUB's `min_objects`
  heuristic, so the VM is booted with `slub_min_order=<conf slab_order>`
  rather than hoping `-smp` lands on the phone's value.

Five confs omit `page_size`/`slab_order`/`slab_size` and rely on the
documented `conf_defaults()` values; the harness applies the same defaults,
so they are complete profiles, not drafts. The four OPPO/realme confs above
are the only ones still without an image.

A caveat on the F11 rate: the harness runs at `-j 2` on the 12-core build
host. Oversubscribing the vCPUs makes the spray burst miss its 15 s window
(`plant1 burst hit=0 after 15004ms`), and at the extreme it surfaces the
exploit's own `timerqueue_del` → `rb_next` race. Both reproduce at ~10 % under
heavy oversubscription and at 0/40 when the host is not oversubscribed, on
`spinel` as well as `brussels`, so they are pre-existing timing behaviour of
the exploit rather than anything a profile controls. The harness retries F11
once and records both outcomes in `f11_attempts`; the single retry in this
run was the tegu 16K profile, which then passed.

F2's `slabinfo` lines are now confirmed for every profile that has an image.
F12 and F13 stay pending because the QEMU initramfs has neither an SELinux
policy nor KernelSU; those two are the remaining gates that a device has to
supply.

### What has been verified without a device

- Every conf parses, matches its own banner, and prints the expected
  `target=`/`kernel=`/`profile=`/`timer_site=` lines (`target` mode).
- A foreign banner against the same conf is rejected with
  `conf release mismatch` and no kernel access.
- All F6 invariants hold (`--selfcheck`), including the new
  `timer_node_off` rule, on every profile. This is what caught the
  `linear_min/linear_max` invariant being wrong in the first draft of the
  check: on arm64 the kernel image is mapped above the direct map, so
  `timer_site >= linear_max` is the correct assertion. The runtime only bounds
  the *voted base* with that range (`plant_base()` then maps the vote through
  `g_slide`), so the profiles were fine and the check was fixed.
- The aarch64 build is clean with the NDK (`-static -O2 -pthread -Wall`).
- The shipped aarch64 binary itself now runs: F7–F11 pass on all 18 profiles
  that have a factory Image, in `qemu-system-aarch64` at the profile's page
  size. That includes the four Redmi Note 15/17 standalone-payload variants
  and the first 16K boot. See the F14 section above for the per-profile
  table and the two boot parameters the harness has to derive.

### Known follow-ups

- `pudding` / `pandora` / `nezha` / `byron` reuse the upstream
  `…-abogki561813157` profile; they were checked to be the same payload rather
  than given their own confs.
- Running F7–F13 on one device per family would let the rows move from
  `verified in QEMU` to `tested`. This now includes the four Redmi Note 15/17
  standalone-payload variants (three 4G, plus the 5G `brussels`), whose
  profiles are derived and pass F7–F11 in QEMU but have not run on hardware.
- The QEMU harness cannot cover F12/F13: it has no SELinux policy and no
  KernelSU. F12 needs a device whose policy actually enforces, and F13 needs
  a working KSU installation for the matching `ksu_kmi`.
- Four confs are imported OPPO/realme profiles with no factory artifact in
  the workspace (`6.12.58-…-ab15213644-4k`,
  `6.12.69-…-g242e1a07f878-ab15865446-4k`,
  `6.6.118-…-g9bc34d5b0c79-abogki537459655-4k`,
  `6.6.66-…-abogki428889875-4k`). One was derived from a device dump, so
  there is no image to boot and the QEMU pass cannot reach them. Fetching
  the vendor `boot.img` would let them join the run.
- The dirty Meizu 21 Pro/22 confs have no factory artifacts in the workspace
  either. They now pass the F6 invariants (`validate_conf.py` applies
  `conf_defaults()` instead of demanding every field be written out), but
  there is no vmlinux to cross-check their symbols against, so their F2/F3
  rows remain unverified.
