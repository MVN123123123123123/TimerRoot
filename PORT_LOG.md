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

The Samsung pass additionally exercised the `--samsung fake` chain end to end
in QEMU, which is where [the `g_slide` regression](#samsung--g_slide-fix) was
found and fixed. That fix touches the shared code path, so it was re-checked
against generic 5.15 and 6.12 profiles as well.

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
| Pixel 10 Pro (blazer, 6.12.81, 4K and 16K) | `exec_mmap`, `exec_task_namespaces`, **`posix_cpu_timers_exit`**, `exit_itimers` | yes |

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

## 6.12.81 — Pixel 10 Pro, CP4A.261105.040.A1

November 2026 security update. First 6.12.81 profile, and the first Pixel
build in the tree that ships a 6.12 kernel: the Pixel 10 series moved off
6.6.127 onto 6.12.81 with this release.

### `6.12.81-android16-6-g4a1a020d156e-ab16388316-4k`

The `mustang` (Pixel 10 Pro XL) row in the supported-devices table stays
`untested`: this profile was derived from the `blazer` factory image only. The
two devices ship one signed build, but the kernel payload was not compared
against `mustang`'s own image the way the four 6.6.127 images were.

- **F1** `blazer` (Pixel 10 Pro), build `CP4A.261105.040.A1`,
  `android-info.txt` requires
  `board=rango|deepspace|frankel|blazer|mustang`. **4K pages.**
  `begin_new_exec` order:
  `exec_mmap` → `exec_task_namespaces` → **`posix_cpu_timers_exit`** →
  `exit_itimers` — vulnerable.
- **F2** `boot.img` `sha256 1de8708d83ee5f39c1717ee7cf1d5d3098e25874982157ffd3a34653a6cca792`;
  LZ4 payload `23337758d842c8babd0c97d68e54c2db871aa19adbe6dd05ded635467079c56d`;
  raw `Image` `e0c7240d40436d94000dcbae4dfd4a17ff67201021cdce019a46e5a9e9989e8c`;
  132 841 kallsyms symbols; BTF present. `vendor_boot.img`
  `sha256 3116de94d65aac2c29bc4dd2e679c07f72689400498e8c5169f86ecf9902c41a`,
  its vendor command line sets `android_arch_task_struct_size=784`.
- **F3** `init_posix_timers` creates the cache with `size=0x100`; the object
  is allocated in `alloc_posix_timer`, which has two
  `bl kmem_cache_alloc_noprof` sites, `…9398` and `…940c`. The second brackets
  the call with `current->alloc_tag` swaps (`mrs x20, SP_EL0` /
  `str x21, [x20,#0x50]`), so it is the profiling path; the configured one is
  `…9398` → **`timer_site = 0xffffffc0802c939c`**.
  `copy_process` inlines `dup_task_struct`: the first
  `bl kmem_cache_alloc_node_noprof` (x0 from `task_struct_cachep` at
  `0xffffffc0828997d0`) returns to `…9f78` → **`copy_process_low21 = 0xc9f78`**
  (`+0x144` into `copy_process`). The second (`…ac5c`, same cachep, `+0xe2c`)
  is the alloc-tag path and was rejected.
- **F4** BTF: `cred` `0xb8` (`usage` `0x0`/8B, uid `0x8`, euid `0x18`,
  cap `0x30`, security `0x80`); `task_struct` `0x1440`, cred `0x900`;
  `k_itimer` `0x100`, `it` `0x78` → `timer_node_off = 0x78` stays the default.
  `task_alloc_bytes = 0x1440 + 0x310 = 0x1750` — the vendor extension is
  `android_arch_task_struct_size=784` from `vendor_boot`, as on the Pixel 11.
  `cred_init` `mov w1,#0xb8` / flags `0x2110` → `cred_alloc = 0xc0`.
- **F5** `selinux_state 0xffffffc0828eb9a8`, `panic_on_warn 0xffffffc08263ade0`,
  `root_user 0xffffffc082662348`, `init_user_ns 0xffffffc0826620d0`,
  `init_ucounts 0xffffffc082663ce0`, `init_groups 0xffffffc082663810`.
  `selinux_state - 8` is `avc_latest_notif_update.notif_lock` and BTF puts
  `enforcing` at bit 0, so the `-7` store lands on `enforcing`.
  `selinux_blob_off = 0x8`: effective LSM order is
  `capability, landlock, safesetid, selinux, bpf` with `lbs_cred`
  landlock 8 / selinux 24, aggregate blob `0x20`.
- **F6** 0 errors, `--selfcheck` 0 failures. Worst case spills by `0x48` into
  the next object, the designed `run_plant()` retry.

### `6.12.81-android16-6-g4a1a020d156e-ab16388316-16k`

The same factory image also carries a standalone `kernel_16k`. Its release
string has **no `-4k` suffix**, so it is a distinct profile selected by page
size (both the app and `load_conf()` compare `page_size`).

- **F1** same build, 16K pages; `begin_new_exec` order is identical —
  vulnerable.
- **F2** `kernel_16k` `sha256 c57d40d38c258430290c0c428e82aa822adb4c7d25a32514dbe81899faf0ae09`;
  raw `Image` `efa65cbf3472a3cfdd57a8d666c76b9f9fa368898e7214d2365f5e619c7c7f50`;
  132 095 symbols; BTF present. Same `android_arch_task_struct_size=784`.
- **F3** here `dup_task_struct` is a **standalone function** (not inlined), so
  the task_struct site is read from its body: the first
  `bl kmem_cache_alloc_node_noprof` returns to `+0x54`
  → **`copy_process_low21 = 0xdfb48`**; the second (`…dff64`) is the
  alloc-tag path. `do_timer_create` allocates the timer:
  `bl kmem_cache_alloc_noprof` at `…86d0` → **`timer_site = 0xffffc000801f86d4`**
  (the `…8bb0` site is the alloc-tag path).
- **F4** BTF identical to the 4K build: `cred 0xb8`, `task_struct 0x1440`,
  `k_itimer 0x100`/`it 0x78`, `task_alloc_bytes 0x1750`.
- **F5** `selinux_state 0xffffc000828d99b8`, `panic_on_warn 0xffffc00082610de0`,
  `root_user 0xffffc0008263b348`, `init_user_ns 0xffffc0008263b0d0`,
  `init_ucounts 0xffffc0008263cce0`, `init_groups 0xffffc0008263c810`.
  Same LSM order and `selinux_blob_off = 0x8`.
- **F6** 0 errors, `--selfcheck` 0 failures. `slab_order = 0`,
  `slab_size = 0x4000`, `pcp_free = 0` as for the other 16K profile.

**F7–F11** — both page sizes booted in QEMU against the unmodified factory
`Image` and passed every gate on the **first attempt, no retry**
(`logs/mass-blazer.json`):

| profile | slabinfo | F7 | F8 | F9 | F10 | F11 |
|---|---|---|---|---|---|---|
| `…-ab16388316-4k` | pass | pass | pass | pass | pass | pass |
| `…-ab16388316-16k` | pass | pass | pass | pass | pass | pass |

`slabinfo` reported `posix_timers_cache` object `0x100` at order 1 (4K, 32
objects) and order 0 (16K, 64 objects), and `task_struct` `0x1780` — the
requested `0x1750` rounded up to the 64-byte `s->align`, exactly as for cubs.

`validate_conf.py` needed one fix to cover this pair: a 16K profile's release
string is a strict prefix of the 4K one, so the substring test matched the 4K
`vmlinux` and failed the 16K symbols. It now breaks the tie on the sibling raw
`Image`'s page size (the rule `mass.py` already used). With that, the whole
`conf/` suite still validates at 0 errors.

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
- **F15 device gate (yogi, 2026-11-19) — slab-order mismatch, fixed:**
  the first hardware run stopped at
  `[base] made=512 site=… slide=… best=0 count=0` → `base calibration
  failed`.  The phone's `posix_timers_cache` is order 0 (16 objects / 1
  page); the profile declared order 1 (32 / 2), because QEMU validation
  forces `slub_min_order=1` to reproduce that assumption.  With the order-1
  filter, no timer-slab `mm_page_alloc` record matched and the base vote was
  empty.  Reproduced exactly in QEMU by booting the same factory `Image`
  without `slub_min_order=1`; that run prints the same `count=0` line.
  Two fixes:
  - the profile now records `slab_order=0` / `slab_size=4096`; and
  - `calibrate_base()` tries slab orders 0..3, keeps the strongest vote and
    logs `[!] slab geometry mismatch: conf ... device ...; using device
    geometry` before adapting, so a stale profile cannot hard-fail this way
    again.

  QEMU re-run on the order-0 boot with the old order-1 profile: mismatch
  logged, `[base] ... count=512 order=0`, plant `pair pfn` agree=1, child
  `resuid=0/0/0`, `ROOT_SHELL_OK`.  The rebuilt binary is
  `p7a/timer_p7a` (sha256 `4edece26…`) and the app asset.  The 6.12.81
  Pixel 11 profiles still declare order 1 and rely on the runtime detection
  until they get their own hardware run.  Hardware re-test pending.

- **F15 device gate (yogi, 2026-11-19) — spray burst drained before the
  free, fixed:** with base calibration working, every plant on hardware
  logged `free_seen=1 burst hit=0 after 15002ms`, three attempts, then
  `no successful plant -- parking without reap (zombie held)`.  The victim
  slab *is* freed (the trace shows its `mm_page_free`), but no spray
  allocation is in flight when that happens.

  Root cause is the spray schedule, not geometry.  `spray_thread()` sent a
  fixed `SPRAY_POST=10000` per thread in phase 2, and all of phase 1+2
  completed within tens of milliseconds of the plant starting.  The victim
  slab is freed later, inside the child's exec/exit path.  Worse, the pool
  capacity is small and bounded: an unprivileged process cannot raise
  `net.core.wmem_max`, so the socketpair queues accept only a limited
  number of skbs before every `send()` returns `EAGAIN`.  Measured in QEMU
  with Android's `wmem_max=212992`: successful sends stall around 57k and
  millions of later sends fail.  A flat-out burst therefore spends the
  whole capacity in a few milliseconds and then allocates nothing for the
  rest of the 15 s window — exactly the hardware symptom.  QEMU's default
  initramfs never hit it because its `wmem_max` is 16 MB and `SO_SNDBUF`
  was raised to 16 MB, so the queues never filled.

  Three fixes in `p7a/timer_p7a.c`:
  - Phase 2 now *waits* for the parent to see `mm_page_free` for the
    victim pfn (new `g_free_seen`) and only then spends its send budget, so
    the queue capacity is still unused at the only instant the page can be
    taken.  `SPRAY_PRE` dropped 2000 → 256 so phase 1 cannot consume that
    capacity up front.
  - The direct zero-write and permissive retry loops call `pool_reset()`
    per attempt.  Previously attempts 2 and 3 reused queues already
    saturated by attempt 1, so they sent only `EAGAIN` and could never
    reclaim.
  - The result line now logs `send ok=<n> err=<n>` (plus a `free at
    <ms>ms` line) so a starved burst is visible in the device log instead
    of presenting as a bare miss.

  QEMU validation of the fix: with `wmem_max` clamped to Android's 212992
  (the configuration that reproduced `burst hit=0 after 15002ms`),
  the run now logs `free at 1ms send ok=2048 err=0` then `burst hit=1
  after 47ms send ok=14526 err=0` and `ROOT_SHELL_OK`; the same holds with
  default buffers.  Order-0 geometry, 8 CPUs, uid 2000 and a 32k wmem_max
  were each ruled out separately — all of them pass.  `mass.py` gates for
  this profile, the 6.12.81 Pixel 11 set, 6.1.162 and 5.15.194 are all
  PASS; the four `samsung-*` `BOOT-FAIL` rows are pre-existing (that gate
  boots the tegu/blazer images with `qconf=` and never runs the binary —
  those profiles are only ever validated through an `--image` shim).
  The `pool_reset()` change was the one with real regression risk, since
  the Samsung endgame runs five plants back to back on the recycled pool:
  re-ran the s23fe shim under `--samsung fake` and all five stages
  (`defex_hash` ×3, `fake_uid`, `fake_euid`) hit on attempt 1
  (`burst hit=1`, `err=0`), the worker reported `resuid=0/0/0` and the
  chain stopped at `[ksu] ksud missing` / `KSU_MISSING` exactly as
  before.  Rebuilt binary `p7a/timer_p7a` sha256 `3d33c532…`.  Hardware
  re-test pending.

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
  → **`copy_process_low21 = 0x132d14`**. `validate_conf.py` originally only
  matched `kmem_cache_alloc.*node`, so this site was confirmed by
  `sitecheck.py` (the source register loads `task_struct_cachep`); the tool now
  falls back to the unqualified callee and confirms it automatically.
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

### samsung a15xzh — `5.15.189-android13-8-33641424` (Samsung mode)

`conf/samsung/samsung-a15xzh-5.15.189.conf`, for the Samsung Galaxy A15 5G
(SM-A1560). This is the first 5.15 **Samsung** profile and the second profile
under `conf/samsung/`.

- **F1** `samsung/a15xzh/a15x:16/BP4A.251205.006/A1560ZHSAEZG1`, kernel
  `5.15.189-android13-8-33641424`. 4K pages (`CONFIG_ARM64_4K_PAGES`,
  `CONFIG_ARM64_VA_BITS=39`), `CONFIG_SECURITY_DEFEX=y`, `CONFIG_KDP=y`,
  `CONFIG_KDP_CRED=y`, `CONFIG_SAMSUNG_GKI_KERNEL=y`, `CONFIG_SLUB`.
- **F2** factory `boot.img`
  `sha256 9800789fd2f7b169ba3f51de9613e5776850f8096e23570111496537b1e65a81`;
  `Image` `9dddd18f619c234c5a97e70b5fccdd11e43814b0b28dfa417392fa1dd2b8c6fb`;
  `vmlinux.elf` `7ce467e5a558de5391d405bf060362a024c502690533425ab8327fea51ac93df`;
  BTF `de165b42879670423c358958a3b879c55be048d5121aacf4054ba7b2826b0f30`.
  Booted in QEMU it reports exactly the three F2 slabinfo lines the profile
  predicts: `posix_timers_cache` object `264` (`0x108`) at `pagesperslab 2`
  (order 1), `task_struct` `4608` (`0x1200`), `cred_jar` `192` (`0xc0`).
- **F3** `init_posix_timers` is
  `__initstub__kmod_posix_timers__387_281_init_posix_timers6`, which calls
  `kmem_cache_create_usercopy("posix_timers_cache", 0x108, …)`.
  `do_timer_create` → `bl kmem_cache_alloc` at `0xffffffc0082048c0`
  → **`timer_site = 0xffffffc0082048c4`**. `copy_process` calls
  `dup_task_struct`, whose `bl kmem_cache_alloc` (5.15 has no `_node` variant
  here) at `0xffffffc0080c9ea4` returns to `0xffffffc0080c9ea8`
  → **`copy_process_low21 = 0xc9ea8`**.
- **F4** BTF: `cred` `0xb0` — **4-byte `usage`**, uid `0x4`, euid `0x14`, caps
  `0x28`, security `0x78`, user `0x80`, user_ns `0x88`, ucounts `0x90`, groups
  `0x98`; `task_struct` `0x1200`, cred `0x798`; `k_itimer` `0x108`, `it`
  `0x78`. `cred_init` requests `0xb0`, which SLUB rounds to `0xc0`
  (`cred_alloc`). `fork_init` passes `0x1200` and there is no
  `task_struct_vendor_size_setup`, so `task_alloc_bytes = 0x1200`.
  `pcp_free = 1` for the same reason as zephyr: 5.15 frees the order-1 slab
  through the PCP lists.
- **F5** `selinux_state 0xffffffc00abcded8`, `panic_on_warn 0xffffffc00a8dadd0`,
  `root_user 0xffffffc00a901410`, `init_user_ns 0xffffffc00aa6cda8`,
  `init_ucounts 0xffffffc00a902828`, `init_groups 0xffffffc00a9024b0`; all six
  re-verified equal to `nm`. `selinux_blob_off = 0x0` and
  `selinux_sid_kernel = 1` from `blobsim2.py` (effective LSM order
  `capability, integrity, selinux`; only selinux carries a 32-byte cred blob).
  DEFEX does not register a cred blob.
- **F5 Samsung** `defex_creds_hash = 0xffffffc00ac53740`:
  `get_task_creds` indexes it directly as an 8-byte array for `pid <= 0x8000`,
  and `creds_fast_hash_init` zeroes `0x40000` bytes there.
- **F1 vulnerability** `begin_new_exec` still calls `posix_cpu_timers_exit`
  (`0xffffffc0084c8e4c`) before `exit_itimers` (`0xffffffc0084c8e5c`).
- **F6** `validate_conf.py` 0 errors, `--selfcheck` 0 failures.
- **F7–F11** all pass in QEMU against the factory `Image`, first attempt:
  `target` prints `timer_site=0xffffffc0082048c4` and `samsung=1`; `ids`
  `page_alloc=263 page_free=261 pairs=1029`; `probe` votes
  `base=0xffffff7fc0000000` with `pair … agree=1`; `leak` 512/512 votes;
  verify reaches `resuid=0/0/0` + `ROOT_SHELL_OK`.
- **Samsung endgame** verified separately under `--samsung fake`: the
  `defex_hash` stage clears `creds_fast_hash[105]`, the `fake_cred` stage
  plants the fake cred and `selinux_state`, then `fake_uid`/`fake_euid` repair
  it; the worker reports `uid=0 euid=0` and reaches the KDP-safe init-domain
  step. `ksud` and an SELinux policy are not in the QEMU initramfs, so the
  late-load itself stops at `ksud missing` exactly as designed (F12/F13 stay
  pending on a device).
- **QEMU boot note** the factory `Image` cannot boot under `qemu-system-aarch64`
  unmodified: RKP/KDP/DEFEX call the phone's Knox hypervisor via `_uh_call`,
  which does not exist there, so the boot dies in
  `map_kernel_text_segment`, `kdp_init`/`prepare_ro_creds`, and the DEFEX
  signature gate. Verification therefore used a **throwaway, patched copy**
  (`/tmp/opencode/a15/Image.qemu`) with those vendor hooks neutralised. The
  derived constants were never taken from it, and the factory artifacts in
  `sam_a1560/` stay unmodified. This is the same class of QEMU-only shim the
  harness uses for every other profile; it is not a profile change.

### samsung s26fe — `6.6.127-android15-8-abogkiS741BXXS3AZK1-4k` (Samsung mode)

`conf/samsung/samsung-s26fe-6.6.127.conf`, for the Samsung Galaxy S26 FE
(SM-S741B, Exynos, EUX firmware `S741BXXS3AZK1`, Android 17). This is the first
6.6 Samsung profile and the third profile under `conf/samsung/`.

- **F1** banner `Linux version 6.6.127-android15-8-abogkiS741BXXS3AZK1-4k`
  (kleaf/clang 18, `#1 SMP PREEMPT Tue Nov  3 23:55:17 UTC 2026`), 4K pages
  (`file` reports the `Image` as 4K). The `release_prefix` in the conf is the
  full banner, so no other Samsung 6.6 build can match it: the S25 series
  ships `6.6.127-android15-8-p87b1ce1-…-4k`, whose text addresses differ, and
  `release_prefix_matches()` cuts at `-` boundaries.
- **F2** factory `boot.img`
  `sha256 373aa4c18fafbf6811d74e5d2b779a5c8846b0863ae8bd0d5e8cf1c09ad2481b`;
  `Image` `b936ad4eb99164de807b9027f356ca7f5b64b88bc2f07e6bbe79bf0607a2ad2f`;
  `.BTF` `2d5a2d3dc78ccc93ba1d49996bbd0dffbe5416e57d98ad024cfae170ffd51943`.
  `vmlinux-to-elf` reconstructs the kallsyms ELF at base `0xffffffc080000000`
  with **115 121 symbols**. Unlike the a15xzh 5.15 kernel, this Image boots
  unmodified in QEMU — no KDP/RKP shim needed.
- **F1 vulnerability** `begin_new_exec` calls `exec_mmap`
  (`0xffffffc0803d9564`), `exec_task_namespaces` (`…9594`),
  **`posix_cpu_timers_exit`** (`…95ac`), `exit_itimers` (`…95bc`) — the
  vulnerable order.
- **F3** `init_posix_timers` creates the cache with `mov w1, #0x108` and
  stores it at `posix_timers_cache` (`0xffffffc082580d60`); `do_timer_create`
  → `bl kmem_cache_alloc` (the non-`_noprof` name on 6.6) at
  `0xffffffc08019727c`, the register feeding `x0` being
  `ldr x0, [x20, #0xd60]` from that same global (dataflow-verified by
  `sitecheck.py`) → **`timer_site = 0xffffffc080197280`**. It is the only
  `kmem_cache_alloc` site in the function (`…71d8`–`…76e4`); 6.6 has no
  `alloc_tag` profiling path. `copy_process` calls `dup_task_struct`
  (`bl` at `0xffffffc0800ac898`), whose
  `bl kmem_cache_alloc_node(task_struct_cachep)` at `0xffffffc0800ad470`
  returns to `0xffffffc0800ad474`
  → **`copy_process_low21 = 0xad474`**.
- **F4** BTF: `cred` `0xb8` — **8-byte `atomic_long usage`**, uid `0x8`, euid
  `0x18`, securebits `0x28`, caps `0x30`, security `0x80`, user `0x88`,
  user_ns `0x90`, ucounts `0x98`, group_info `0xa0`; `task_struct` `0x12c0`,
  cred `0x820`; `k_itimer` `0x108`, `it` `0x78` → `timer_node_off = 0x78`.
  `cred_init: mov w1, #0xb8` → SLUB rounds to `0xc0` (`cred_alloc`).
  `task_struct_vendor_size_setup` exists (`mov w9, #0x12c0`, vendor cap
  `0x200`) but the image does not set `android_arch_task_struct_size`, so
  `task_alloc_bytes = 0x12c0`.
- **F5** `selinux_state 0xffffffc08259f7f8`, `panic_on_warn 0xffffffc08233ac0c`,
  `root_user 0xffffffc08235f0a0`, `init_user_ns 0xffffffc08235ee10`,
  `init_ucounts 0xffffffc082360c70`, `init_groups 0xffffffc082360600`; all six
  re-verified equal to `nm`. `selinux_state - 8` is
  `avc_latest_notif_update.notif_lock`, so the `-7` store lands on
  `enforcing`'s low byte as on every other profile. `selinux_blob_off = 0x0`
  (`blobsim2.py`: effective order `capability, safesetid, selinux, bpf,
  integrity`; only selinux has a 32-byte `lbs_cred`; no landlock cred blob on
  6.6) and `selinux_sid_kernel = 1`.
- **F5 Samsung** `defex_creds_hash = 0xffffffc082623e28`: this build names the
  fast table `creds_fast_hash` (its own symbol, `creds_hash + 0x40000`).
  `get_task_creds` indexes it directly as an 8-byte array for `pid <= 0x8000`
  (`cmp w23, #0x8, lsl #12` → `add x9, x9, x23, lsl #3`) and falls back to the
  bucket chain above it.
- **F6** `validate_conf.py` 0 errors (`timer_site` and `copy_process_low21`
  match the vmlinux, 6/6 symbols, `alloc_req_off 0x10` matches BTF);
  `--selfcheck` 0 failures on the host build; `target` mode prints
  `target=lynx`, `samsung=1`, exit 0; a foreign banner
  (`…abogkiS931BXXUDDZJB-4k`, the S25 Ultra kernel) is refused with
  `conf release prefix mismatch` and no kernel access.
- **F7–F11** all pass in QEMU against the **unmodified factory `Image`**
  (first attempt, `logs/mass-s26fe.json`; re-run after the spray-write fix and
  pool recycle, `logs/mass.json`, still 0 failing gates): slabinfo reports
  `posix_timers_cache` object `264` (`0x108`) at `pagesperslab 2` (order 1)
  and `task_struct` `4800` (`0x12c0`); `target` prints
  `timer_site=0xffffffc080197280` and `samsung=1`; `ids`
  `page_alloc=275 page_free=273 pairs=1029`; `probe` votes
  `base=0xffffff7fc0000000` with `pair pfn` `agree=1`, `recs=4096 kept=4096`;
  `leak` 512/512 votes; verify reaches `resuid=0/0/0` + `ROOT_SHELL_OK`.
- **Samsung endgame** under `--samsung fake`: `defex_hash` clears
  `creds_fast_hash[pid]`, the `fake_cred` stage plants the fake cred, then
  `selinux_state` and the uid/euid repair writes run, and the worker reaches
  `uid=0 euid=0` with `setuid(0)=0 errno=0 resuid=0/0/0`; the late-load then
  stops at `ksud missing` exactly as designed (F12/F13 stay pending on a
  device; the QEMU initramfs has no ksud or coreutils for the stage script).
  Completing the five-plant chain in QEMU needed the spray-write fix and the
  per-attempt pool recycle below — the plain race means per-plant bursts miss
  roughly half the time, so a miss must be recoverable, not fatal. See
  [the spray-write fix](#samsung--spray-write-fix) that this chain exposed.
- **QEMU note** the factory `Image` boots under `qemu-system-aarch64` as-is;
  Samsung's DEFEX logs `[DEFEX] Normal mode` and its Knox `uh_log` device
  initialises, unlike the a15xzh 5.15 kernel that needed the vendor-hook
  shim.
- **QEMU harness** (harness-only, outside this repo — `work/qemu/` in the
  port tree): `mass.py` now accepts Samsung profiles' full-banner
  `release_prefix` and scans `conf/samsung/` alongside `conf/dirty/`; the
  initramfs `init` raises `net.core.{wmem,rmem}_max` to `1048576` because
  `SO_SNDBUF 16 MB` is otherwise clamped to the default 212 992 (~416 KB per
  socket), which starves plant 2. 16 MB sysctls fail (RAM exhaustion in the
  8 GB guest), 4 MB regressed vs 1 MB. End-to-end chain command:
  `qemu-system-aarch64 -M virt -cpu max -m 8192 -smp 4 -kernel
  work/xi/s26fe-boot/Image -initrd initramfs.cpio.gz -append
  "... qconf=samsung-s26fe-6.6.127.conf qargs=--samsung qmode=fake"`.

### samsung s25edge — `6.6.127-android15-8-p87b1ce1-abogkiS937BXXUBDZJB-4k` (Samsung mode)

`conf/samsung/samsung-s25edge-6.6.127.conf`, for the Samsung Galaxy S25 Edge
(SM-S937B, Snapdragon, EUX firmware `S937BXXUBDZJB`, Android 17, patch
2026-10, 4K pages). This is the fourth profile under `conf/samsung/` and the
first S25-series one. The S25 family (Edge / S25 / S25+ / S25 Ultra) ships the
`p87b1ce1` 6.6.127 build, which is **not** the S741B S26 FE kernel: it shares
the 6.6 cred/task layout, but every text address differs, so all values below
were re-derived from the SM-S937B factory `boot.img`.

- **F1** banner `Linux version 6.6.127-android15-8-p87b1ce1-abogkiS937BXXUBDZJB-4k`
  (kleaf/clang 18, `#1 SMP PREEMPT Mon Oct 19 08:38:43 UTC 2026`), 4K pages.
  The vulnerable `begin_new_exec` order is intact — `exec_mmap`
  (`bl 0x…3d83dc` at `0x…3d8098`) and `exec_task_namespaces` (`bl
  0x…0e23fc` at `0x…3d80c8`) still run **before** `posix_cpu_timers_exit`
  (`bl 0x…197540` at `0x…3d80e0`) and `exit_itimers` (`bl 0x…195324` at
  `0x…3d80f0`).
- **F2** factory `boot.img`
  `sha256 92d60266452e1c5a55716e421da0e5f97c5d03eb80acac07043a7c5b94eff758`;
  extracted `Image`
  `6f84635078366d575e09c4ef0413327fecb0366147a90783c979153919cf67ec`;
  `.BTF` `f7e64d2abe8281e047cf04f108239f0d07c8629aa0c899584090feec0e3e9968`.
  `vmlinux-to-elf` reconstructs the kallsyms ELF at base `0xffffffc080000000`
  with **115 126 symbols**. The S25 Edge `.BTF` matches the other S25-series
  images; the kernel is the `p87b1ce1` build, not `abogkiS741BXXS3AZK1`.
- **F3** `timer_site = 0xffffffc0801962b0`: the `do_timer_create` →
  `kmem_cache_alloc(posix_timers_cache)` site, dataflow-verified with
  `sitecheck.py` (the call loads `x0` from `0xffffffc082581d60`, the
  `posix_timers_cache` pointer, and `init_posix_timers` sets `w1 = #0x108`,
  matching BTF `sizeof(struct k_itimer)`). `copy_process_low21 = 0xac474`:
  the return address of `bl kmem_cache_alloc_node(task_struct_cachep)` at
  `0xffffffc0800ac470` (called from `copy_process+0x11c`,
  `bl 0xffffffc0800ab898`).
- **F4** BTF: `struct cred` is `0xb8` with an 8-byte `usage` at `0x0`, `uid
  0x8`, `euid 0x18`, `securebits 0x28`, `cap_inheritable 0x30`, `security
  0x80`, `user 0x88`, `user_ns 0x90`, `ucounts 0x98`, `group 0xa0`; `cred_init`
  sets `w1 = #0xb8` and `cred_jar` rounds the object to `0xc0`. `task_struct`
  is `0x12c0` with `cred` at `+0x820`; `k_itimer` is `0x108` with the
  `cpu_timer` node at `+0x78`. `task_struct_vendor_size_setup` exists
  (memparse gate, min `0x200`) but the factory image never sets
  `android_arch_task_struct_size`, so no vendor extension:
  `task_alloc_bytes = 0x12c0`.
- **F5** `selinux_state 0xffffffc0825a0810` (its `-8` is
  `avc_latest_notif_update.notif_lock`, confirming the base),
  `panic_on_warn 0xffffffc08233ac0c`, `root_user 0xffffffc08235f220`,
  `init_user_ns 0xffffffc08235ef90`, `init_ucounts 0xffffffc082360d18`,
  `init_groups 0xffffffc082360780`. DEFEX `creds_fast_hash` is its own symbol
  at `0xffffffc082624f80` (`creds_hash 0xffffffc0825e4f80` + `0x40000`), which
  `get_task_creds` indexes directly for `pid <= 0x8000`. LSM order is
  `capability,safesetid,selinux,bpf,integrity`; only SELinux has a 32-byte
  `lbs_cred`, so `selinux_blob_off = 0x0`, `selinux_sid_kernel = 1`.
- **F6** `validate_conf.py`: 0 errors (call site and `copy_process` low21
  match the vmlinux, 6/6 symbols, `alloc_req_off 0x10` matches BTF; worst
  object node `0x1f68` / cred end `0x2038` spills, retry path).
  `--selfcheck` 0 failures on the throwaway host build; `target` prints
  `target=lynx`, `device=unknown`, the full banner, `pagesize=4096`,
  `timer_site=0xffffffc0801962b0`, `samsung=1`, exit 0. A foreign S25-series
  banner (`…abogkiS938BXXUDDZJB-4k`, S25 Ultra) is refused with
  `conf release prefix mismatch`. All 26 bundled confs still validate with
  0 errors.
- **F7–F11** all pass in QEMU on the **first attempt**
  (`logs/mass-s25edge.json`), against the factory kernel booted through the
  QEMU-only vendor-hook shim described below. Slabinfo reports
  `posix_timers_cache` object `264` (`0x108`), 31 objects at `pagesperslab 2`
  (order 1), `task_struct` `4800` (`0x12c0`) and `cred_jar` `192` (`0xc0`);
  `target` prints the banner, `pagesize=4096` and
  `timer_site=0xffffffc0801962b0`; `ids` `page_alloc=275 page_free=273
  pairs=1029`; `probe` `recs=4096 kept=4096` with
  `base=0xffffff7fc0000000` and `pair … agree=1`; `leak` 512/512 votes;
  verify reaches `child report uid=0 euid=0 setuid(0)=0 errno=0
  resuid=0/0/0` and `ROOT_SHELL_OK`.
- **Samsung endgame** under `--samsung fake` (same QEMU shim; harness log
  `logs/samsung-s25edge-fake.log`): `defex_hash`
  clears `creds_fast_hash[134]`, the `fake_cred` stage plants the fake cred
  and `selinux_state`, the SELinux plant landed on attempt 3
  (`[ksu] panic_on_warn=0`) — the other two bursts missed and were held, as
  designed — then the uid/euid repair writes run and the worker reports
  `uid=0 euid=0; preparing KDP-safe exec`, `setuid(0)=0 errno=0
  resuid=0/0/0`. The late-load stops at `ksud missing` / `KSU_MISSING`
  exactly as designed (the QEMU initramfs has no ksud or coreutils), then the
  process parks with the fake-cred page held. F12/F13 stay pending on a
  device.
- **QEMU note** the factory `Image` does **not** boot under
  `qemu-system-aarch64` unmodified (same class of failure as a15xzh): RKP
  issues `hvc #0` in `rkp_robuffer_init`'s `uh_call` trampoline and the
  hypervisor-backed page-table/RO-cred/DEFEX paths have no hypervisor to talk
  to. Verification used a **throwaway patched copy**
  (`/tmp/opencode/s25edge/Image.qemu`, built by `mkshim.py` next to it; both
  are also kept under `work/s25edge/qemu-shim/` in the port tree so the run
  can be reproduced); the factory artifacts in `work/s25edge/` stay unmodified
  and **no constant was derived from the shim**. Five one-word patches,
  static VA → file offset = VA − `0xffffffc080000000`:

  | VA | original | shim | why |
  |---|---|---|---|
  | `0xffffffc080037874` | `smc #0` (`d4000003`) | `mov x0,xzr` (`aa1f03e0`) | `uh_call` returns 0 (success) instead of trapping |
  | `0xffffffc08003a4dc` | `blr x8` (`d63f0100`) | `bl early_pgtable_alloc` (`947ac66d`) | PGD-level allocator fallback; RKP hands out hypervisor page tables |
  | `0xffffffc08003a7bc` | `blr x8` (`d63f0100`) | `bl early_pgtable_alloc` (`947ac5b5`) | lower-level allocator call site (same reason) |
  | `0xffffffc081ee0630` | `mov w8,#1` (`52800028`) | `mov w8,#0` (`52800008`) | leaves `kdp_enable = 0`; the stock `get_cred()`/`copy_creds()` path runs instead of `prepare_ro_creds()` |
  | `0xffffffc081f124f8` | `tbz w0,#0,…` (`36000080`) | `b` to the existing unlocked-boot return (`14000001`) | `defex_load_rules` skips the hypervisor-signed rules file |

  The failure ladder, for anyone re-deriving the shim: unmodified → `hvc #0`
  undefined instruction in `rkp_robuffer_init`; with only the `uh_call`
  patch → `BUG` in `__create_pgd_mapping+0x798` (RKP allocator returns 0, so
  the installed table descriptor has no valid address); patching one
  allocator site → prefetch abort on the EL1h vector (the unmapped
  `_stext.._text_end` range); patching both → `prepare_ro_creds` panics with
  `KDP Call failed` (the hypervisor is supposed to fill the RO-cred
  pointers); with `kdp_enable = 0` → `defex_load_rules` panics with
  `[DEFEX] Signature mismatch`; with both → userspace. `rkp_init` still runs
  and `[DEFEX] Normal mode` still logs.
- **QEMU harness** (harness-only, outside this repo — `work/qemu/` in the
  port tree): `mass.py` grew an explicit `--image <path>` override so the
  throwaway shim can be booted for one profile without touching the factory
  Image under `xi/<dev>-boot/`. The conf constants are still the factory
  ones; the boot banner is read from the image actually booted.

### samsung s23 — `5.15.197-android13-8-34343818-abS911BXXUAGZIF` (Samsung mode)

`conf/samsung/samsung-s23-5.15.197.conf`, for the Samsung Galaxy S23 (SM-S911B,
Snapdragon 8 Gen 2, EUX firmware `S911BXXUAGZIF`, Android 17, patch 2026-10, 4K
pages). This is the second 5.15 Samsung profile after `a15xzh` and the first
S23-series one. The S23+ / S23 Ultra share the `34343818` build number but ship
different `ab` firmware strings and different text layouts (their `Image`
hashes differ), so `release_prefix` pins the full banner including the
`abS911BXXUAGZIF` suffix.

- **F1** banner `Linux version 5.15.197-android13-8-34343818-abS911BXXUAGZIF`
  (clang 14.0.7, `#1 SMP PREEMPT Sun Sep 27 23:09:20 UTC 2026`), 4K pages,
  VA39. The embedded IKCONFIG confirms `ARM64_4K_PAGES=y`, `ARM64_VA_BITS=39`,
  `SECURITY_DEFEX=y`, `KDP=y`, `KDP_CRED=y`, `SLUB=y`. The vulnerable
  `begin_new_exec` order is intact — `bl exec_mmap` at
  `0xffffffc0084cb224`, then `bl posix_cpu_timers_exit` at
  `0xffffffc0084cb240`, then `bl exit_itimers` at
  `0xffffffc0084cb250`.
- **F2** factory `boot.img`
  `sha256 64213bb16804c1cf50d1808c5f9a7c50be45ad9f928925054c4add24c410c226`;
  extracted `Image`
  `21c6a686b8e73f9eb90b86126eb07a73d3706e751b7fda049d158cc86539db75`;
  `.BTF` `8596ca24a2316e4d52a30f206bba1adf733d3e61ecca5c760222e284caef1a2b`.
  `vmlinux-to-elf` reconstructs the kallsyms ELF at base
  `0xffffffc008000000` with **126 451 symbols** (note: the 5.15 base here is
  `0xffffffc008…`, not the 6.6 `0xffffffc080…`).
- **F3** `timer_site = 0xffffffc008206cb4`: `do_timer_create` loads
  `posix_timers_cache` (`0xffffffc00acde768`) into `x0` at
  `0xffffffc008206cac` and calls `kmem_cache_alloc` at
  `0xffffffc008206cb0`; dataflow-checked with `sitecheck.py`.
  `copy_process_low21 = 0xc9f74`: `dup_task_struct`'s
  `bl kmem_cache_alloc(task_struct_cachep)` is at `0xffffffc0080c9f70` and
  returns to `0xffffffc0080c9f74` (5.15 has no `kmem_cache_alloc_node` here).
- **F4** BTF: `struct cred` is `0xb0` with a 4-byte `usage` at `0x0`, `uid
  0x4`, `euid 0x14`, `cap_inheritable 0x28`, `security 0x78`, `user 0x80`,
  `user_ns 0x88`, `ucounts 0x90`, `group 0x98`; `cred_init` rounds `cred_jar` to
  `0xc0`. `task_struct` is `0x1200` with `cred` at `+0x798` (`real_cred
  +0x790`); `k_itimer` is `0x108` with the `cpu_timer` node at `+0x78`.
  `arch_task_struct_size` is absent, so `task_alloc_bytes = 0x1200`.
- **F5** `selinux_state 0xffffffc00ad8e600`,
  `panic_on_warn 0xffffffc00aa8add0`, `root_user 0xffffffc00aab16d0`,
  `init_user_ns 0xffffffc00ac294c0`, `init_ucounts 0xffffffc00aab2ae8`,
  `init_groups 0xffffffc00aab2770`. DEFEX `creds_fast_hash` is its own symbol
  at `0xffffffc00ae0f770` (`creds_hash 0xffffffc00adcf770` + `0x40000`),
  which `get_task_creds` indexes directly for `pid <= 0x8000` (the same
  shape as the 6.6 S26 FE / S25 Edge builds). LSM order is
  `capability,safesetid,integrity,selinux`; only SELinux has a 32-byte
  `lbs_cred`, so `selinux_blob_off = 0x0`, `selinux_sid_kernel = 1`.
- **F6** `validate_conf.py`: 0 errors (call site and `copy_process` low21
  match the vmlinux, 6/6 symbols; worst object node `0x1f68` / cred end
  `0x2030` spills, retry path). `target` prints `target=lynx`,
  `pagesize=4096`, the full banner and `timer_site=0xffffffc008206cb4`,
  exit 0. A foreign banner was exercised in QEMU by rewriting the shim copy's
  six `abS911BXXUAGZIF` strings to `abS916BXXUAGZIF` (the S23+ suffix): the
  binary refuses with `conf release prefix mismatch: conf=…abS911BXXUAGZIF
  running=…abS916BXXUAGZIF`, exit 1, before any kernel access. All 29 bundled
  confs still validate with 0 errors.
- **F7–F11** all pass in QEMU on the first attempt (`logs/mass.json`), against
  the factory kernel booted through the QEMU-only vendor-hook shim below.
  Slabinfo reports `posix_timers_cache` object `264` (`0x108`), 31 objects at
  `pagesperslab 2` (order 1), `task_struct` `4608` (`0x1200`) and `cred_jar`
  `192` (`0xc0`); `target` prints the banner, `pagesize=4096` and the profile
  `timer_site`; `ids` `page_alloc=263 page_free=261 pairs=1029`; `probe`
  `recs=4096 kept=4096`; `leak` 512/512 votes; verify reaches
  `uid=0 euid=0 … resuid=0/0/0`. F12/F13 stay pending on a device.
- **QEMU note** the factory `Image` does **not** boot under
  `qemu-system-aarch64` unmodified (same class of failure as a15xzh and
  s25edge): RKP calls into the Knox secure monitor (`smc #0` in the `uh_call`
  trampoline) and the hypervisor-backed page-table/RO-cred/DEFEX paths have no
  hypervisor to talk to. Verification used a **throwaway patched copy**
  (`/tmp/opencode/s23/Image.qemu`, built by `mkshim.py`; both are kept under
  `work/s23/qemu-shim/` in the port tree so the run can be reproduced). The
  factory artifacts in `work/s23/` stay unmodified and **no constant was
  derived from the shim**. Six patches, all static VA → file offset = VA −
  `0xffffffc008000000`:

  | VA | original | shim | why |
  |---|---|---|---|
  | `0xffffffc0080152f8` | `smc #0` (`d4000003`) | `mov x0,xzr` (`aa1f03e0`) | `uh_call` returns 0 (success) instead of trapping |
  | `0xffffffc0080563bc` | `blr x8` (`d63f0100`) | `bl early_pgtable_alloc` (`949e2c2e`) | PGD-level allocator fallback; RKP hands out hypervisor page tables |
  | `0xffffffc0080567d0` | `blr x8` (`d63f0100`) | `bl early_pgtable_alloc` (`949e2b29`) | lower-level allocator call site (same reason) |
  | `0xffffffc00a7d8c0c` | `mov w8,#1` (`52800028`) | `mov w8,#0` (`52800008`) | leaves `kdp_enable = 0`; the stock `get_cred()`/`copy_creds()` path runs instead of `prepare_ro_creds()` |
  | `0xffffffc00a803968` | `tbz w8,#0,…` (`36000088`) | `b` to the existing unlocked-boot return (`14000001`) | `defex_load_rules` skips the hypervisor-signed rules file |
  | `0xffffffc008506504` | `mov w0,#0xc002` … `bl uh_call` (8 words) | fill `V`: `V[0]=fc->root`, `V[8]=root->d_sb`, `V[0x10]=0`, `V[0x40]=mnt` | KDP's separate `vfsmnt_cache` object (`mount+0x160`) is normally filled by the hypervisor |

  The failure ladder: unmodified → RKP traps in `rkp_robuffer_init` on the
  secure-monitor call; with only the `uh_call` patch → `BUG` in
  `__create_pgd_mapping+0x798`; one allocator site → prefetch abort on the
  EL1h vector; both → `prepare_ro_creds` panics with `KDP Call failed`; with
  `kdp_enable = 0` → `defex_load_rules` panics with
  `[DEFEX] Signature mismatch`; skipping the rules load → userspace. Two
  further faults are specific to this 5.15 build: `vfs_create_mount+0x180`
  (`ldr [x9,#0x4e0]` off the unfilled `vfsmnt_cache`) and `shmem_init+0x8c`
  (`str` through the `V+0x40` `real_mount` back-pointer). Filling the object in
  the second (now no-op) `uh_call` block fixes both; the unchanged `0x6524`
  setup code then runs against a valid mount.
- **QEMU harness** (harness-only, outside this repo — `work/qemu/` in the port
  tree): the same `mass.py --only samsung-s23 --image
  /tmp/opencode/s23/Image.qemu` path as s25edge, so the factory `Image` under
  `xi/s23-boot/` stays untouched. The conf constants are the factory ones; the
  boot banner is read from the image actually booted.

### samsung s23fe — `5.10.240-android12-9-33420454-abS711BXXSJGZI6` (Samsung mode)

`conf/samsung/samsung-s23fe-5.10.240.conf`, for the Samsung Galaxy S23 FE
(SM-S711B, Exynos 2200, EUX firmware `S711BXXSJGZI6`, Android 16, patch
2026-10, 4K pages). This is the **first 5.10 profile** in the tree: every
other profile is 5.15/6.x, and 5.10 has no `struct cred::ucounts`, so the
cred chain needed a different shape (see F4/F6 below). It is also the first
Exynos profile. The sibling `s23fe_sm-s711u1_snapdragon` image in the port
workspace is a different build (different `Image` hash and text layout) and
is not usable for this profile.

- **F1** banner `Linux version 5.10.240-android12-9-33420454-abS711BXXSJGZI6`
  (`dpi@SWDK3801`, clang 12.0.4, `#1 SMP PREEMPT Fri Sep 18 13:53:09 KST
  2026`), 4K pages, VA39. The embedded IKCONFIG confirms
  `ARM64_4K_PAGES=y`, `ARM64_VA_BITS=39`, `SECURITY_DEFEX=y`, `KDP=y`,
  `KDP_CRED=y`, `SLUB=y`, `SLUB_DEBUG=y`, `CFI_CLANG=y`,
  `SHADOW_CALL_STACK=y`, `MEMCG_KMEM=y`. There is **no BTF**. The vulnerable
  `begin_new_exec` order is intact: `bl exec_mmap` at
  `0xffffffc008387c78`, then `bl posix_cpu_timers_exit` at
  `0xffffffc0081a3db0`, then `bl exit_itimers` at `0xffffffc0081a1f14`
  (`begin_new_exec` itself is at `0xffffffc0083872f4`). `_uh_call` is
  `hvc #2` on this build (not `smc`), unlike the 5.15/6.6 Samsung images.
- **F2** factory `boot.img`
  `sha256 9fe5dd7050673563812f54aa030d4ace8e49fae102d6c90bfbd52d1eb58aca42`
  (64 MiB, `boot.img.lz4` inside the AP tar); extracted `Image`
  `dd9838fae388faccdaeb3048f4d4486b0949bd91548b9a4c186493b07bd7cbc0`
  (33 412 928 bytes), `kernel_format raw-arm64`, `os_version_hdr 12.0.0`,
  `os_patch_level 2026-10`. `vmlinux-to-elf` reconstructs the kallsyms ELF
  at base `0xffffffc008000000` with **117 263 symbols**; the KMI is
  `android12-5.10`.
- **F3** `timer_site = 0xffffffc0081a2db0`: `do_timer_create` loads
  `posix_timers_cache` (`0xffffffc00a1b6a50`) into `x0` at
  `0xffffffc0081a2dac` and calls `kmem_cache_alloc` there; `sitecheck.py`
  confirms this is the only `posix_timers_cache` allocation site.
  `copy_process_low21 = 0xd2c4c`: `dup_task_struct`'s
  `bl kmem_cache_alloc(task_struct_cachep 0xffffffc00a16e188)` is at
  `0xffffffc0080d2c48` and returns to `0xffffffc0080d2c4c` (5.10 has no
  `kmem_cache_alloc_node` in this path). The validator initially reported
  `0xd0a6c`; disassembly showed that is `copy_signal`'s `sig_cachep`
  allocation, i.e. a false match — the `dup_task_struct` site wins.
- **F4** no BTF, so the layout comes from `fork_init`/`cred_init` literals,
  `init_cred` static data and `prepare_creds`/`commit_creds`:
  `k_itimer` is `0x108` with the `cpu_timer` node at `+0x78`. `struct cred`
  is `0xa8` (`cred_jar` object `0xc0`) with a 4-byte `usage` at `0x0`,
  `uid 0x4`, `euid 0x14`, caps `0x28..0x48` (5 words), `security 0x78`,
  `user 0x80`, `user_ns 0x88`, `group 0x90`, non_rcu/rcu union `0x98`.
  **5.10 has no `cred->ucounts`** (and no `init_ucounts` symbol): the profile
  pins `cred_ucounts_off = cred_group_off = 0x90`, so the later groups write
  overwrites the ucounts write, and `init_ucounts` points at
  `ucounts_hashtable 0xffffffc00a16efc8`, which is only ever written and
  never dereferenced. `task_struct` is `0x1280` (`fork_init` literal, no
  vendor extension) with `cred` at `+0x780`; the trace `alloc_req_off` is
  `0x10`.
- **F5** `selinux_state 0xffffffc00a2c4e50`,
  `panic_on_warn 0xffffffc009ed9dc0`, `root_user 0xffffffc009f03960`,
  `init_user_ns 0xffffffc009f03710`, `init_groups 0xffffffc009f04b90`.
  DEFEX `creds_fast_hash` is its own symbol at `0xffffffc00a3493b0`
  (`creds_hash 0xffffffc00a3093b0` + `0x40000`); `get_task_creds` indexes it
  directly as an 8-byte pointer array for `pid <= 0x8000`
  (`cmp w25, #0x8, lsl #12`). The LSM list is
  `capability,safesetid,integrity,selinux`: only SELinux has a 32-byte cred
  blob, so `selinux_blob_off = 0x0`, `selinux_sid_kernel = 1` (the same
  shape as the 6.6 S26 FE / S25 Edge builds). `fullcap = 0x1ffffffffff`.
- **F6** `validate_conf.py`: 0 errors across all 30 confs (call site and
  `copy_process` low21 match, 6/6 symbols; the validator needed a fallback
  that accepts the `dup_task_struct` site when `copy_process` itself no
  longer contains the allocation). Host build `--selfcheck`: 0 failures
  (`libc` shim + `FAKE_REL`); `target` prints the full banner,
  `pagesize=4096`, `timer_site=0xffffffc0081a2db0` and `samsung=1`. A
  foreign 5.15 Samsung banner is refused with
  `conf release prefix mismatch` before any kernel access, and the 16K
  profile still refuses a 4K host page size.
- **F7–F11** all pass in QEMU on the first shim boot (`logs/mass-s23fe.json`),
  against the factory kernel booted through the QEMU-only vendor-hook shim
  below. Slabinfo reports `posix_timers_cache` object `264` (`0x108`), 31
  objects at `pagesperslab 2` (order 1), `task_struct` `4736` (`0x1280`) and
  `cred_jar` `192` (`0xc0`); `target` prints the banner, `pagesize=4096` and
  `timer_site=0xffffffc0081a2db0`; `ids` `page_alloc=260 page_free=258
  pairs=1029`; `probe` `recs=4096 kept=4096` with a `pair … agree=1`; `leak`
  512/512 votes; verify reaches `child report uid=0 euid=0 setuid(0)=0
  errno=0 resuid=0/0/0` and `ROOT_SHELL_OK` (a standalone verify transcript
  is kept in `logs/samsung-s23fe-f11.log`). F12/F13 stay pending on a
  device.
- **Samsung endgame** under `--samsung fake` (same shim; harness log
  `logs/samsung-s23fe-fake.log`): `defex_hash` clears
  `creds_fast_hash[197]`, then the `fake_cred`, `selinux_state`, `fake_uid`
  and `fake_euid` plants each land on the first attempt (`free_seen=1` /
  `burst hit=1`, `[ksu] panic_on_warn=0`), the worker reports `uid=0 euid=0`
  and `setuid(0)=0 errno=0 resuid=0/0/0`. The KDP-safe setup then
  `unshare(CLONE_NEWNS)`es, remounts `/` private and fails the ksud bind
  mount with `errno=2` (the QEMU initramfs has no ksud source), runs the
  stage script and stops at `[ksu] ksud missing` / `KSU_MISSING`, worker
  `exit=0x100`, child `exit status=0`, then parks with the fake-cred page
  held exactly as designed. F12/F13 stay pending on a device.
- **QEMU note** the factory `Image` does **not** boot under
  `qemu-system-aarch64` unmodified (same class of failure as a15xzh, s23
  and s25edge): RKP/KDP call the Exynos secure monitor over `hvc` and the
  hypervisor-backed page-table/RO-cred/DEFEX paths have no EL2 behind them.
  Verification used a **throwaway patched copy**
  (`work/xi/s23fe-boot/qemu-shim/Image.qemu`, built by the `mkshim.py` next
  to it so the run can be reproduced); the factory artifacts in
  `work/xi/s23fe-boot/` stay unmodified and **no constant was derived from
  the shim**. Nine logical changes, all static VA → file offset =
  VA − `0xffffffc008000000`:

  | VA | original | shim | why |
  |---|---|---|---|
  | `0xffffffc008016128` | `hvc #2` (`d4000002`) | `mov x0,xzr` (`aa1f03e0`) | `_uh_call` returns 0 (success) instead of trapping; covers all 66 call sites |
  | `0xffffffc00807b718` | `blr x8` (`d63f0100`) | `bl early_pgtable_alloc` (`947398c9`) | PGD-level allocator fallback; RKP hands out hypervisor page tables |
  | `0xffffffc00807bae0` | `blr x8` (`d63f0100`) | `bl early_pgtable_alloc` (`947397d7`) | lower-level allocator call site (same reason) |
  | `0xffffffc009d58930` | `mov w8,#1` (`52800028`) | `mov w8,#0` (`52800008`) | leaves `kdp_enable = 0`; the stock `get_cred()`/`copy_creds()` path runs instead of `prepare_ro_creds()` |
  | `0xffffffc009d819f4` | `bl do_load_rules` (`97ffff97`) | `mov w0,wzr` (`2a1f03e0`) | `defex_load_rules` skips the hypervisor-signed rules file |
  | `0xffffffc0083ac2f0` | `_uh_call(0x83000213)` block (7 words) | fill `V`: `V[0]=fc->root`, `V[8]=root->d_sb`, `V[0x38]=mount` | `vfs_create_mount` normally lets the hyp fill the 0x40-byte `vfsmnt_cache` object; `kern_mount` consumes `V[0x38]` |
  | `0xffffffc008d1b548` | `bl _uh_call` (0x83000211) | `str x19,[x20,#0x38]` (`f9001e93`) | `kdp_mnt_alloc_vfsmount`: owner back-pointer for **every** `alloc_vfsmnt` (cloned mounts in `clone_mnt`) |
  | `0xffffffc008d1b40c` / `0xffffffc0083ace8c` | `mov x4,xzr; mov x5,xzr; bl _uh_call` (0x83000213) | `str x2,[x1]; str x3,[x1,#8]; nop` | `kdp_set_mnt_root_sb` helper and `clone_mnt`'s inlined copy: fill `mnt_root`/`mnt_sb` |
  | `0xffffffc008d1b450` / `0xffffffc008d1b494` / `0xffffffc008d1b4d8`, `0xffffffc0083ace54` / `0xffffffc0083ad018` | `bl _uh_call` (0x83000215) | `str w2,[x1,#0x10]` (`b9001022`) | the three `mnt_flags` helpers and `clone_mnt`'s two inlined copies: flags at `V+0x10` |

  The failure ladder, for anyone re-deriving the shim: unmodified →
  `hvc #2` undefined instruction in `_uh_call` (first caller
  `rkp_robuffer_init`); with only the `_uh_call` patch → `BUG` in
  `__create_pgd_mapping+0x798` (`rkp_ro_alloc_phys` returns 0, so the
  installed table descriptor has no valid address); patching one allocator
  site → prefetch abort on the EL1h vector; patching both →
  `prepare_ro_creds` panics with `KDP Call failed`; with `kdp_enable = 0` →
  `defex_load_rules` panics with `[DEFEX] Signature mismatch`; with the
  rules load skipped → userspace, but the first mount faults at
  `vfs_create_mount+0x100` (`ldr [x8,#0x8]`, `mnt_sb`) until that call's
  vfsmount object is filled (the hyp normally fills it; the object is 0x40
  bytes, and `kern_mount` consumes the owner at `+0x38`, not `+0x40`).
  With that fill F7–F11 pass, but the Samsung `unshare(CLONE_NEWNS)` path
  then dies in `copy_mnt_ns+0x280` (`ldr x10,[x10,#0x68]`, `x10 = 0`):
  `clone_mnt` allocates fresh vfsmounts through the three `_uh_call`
  mount ops (`0x83000211` owner, `0x83000213` root/sb, `0x83000215` flags)
  and their inlined copies, so the cloned mount has no owner/root/sb.
  Emulating those five call sites fixes `unshare` and the chain runs to
  `ksud missing`. `rkp_init` still runs and `[DEFEX] Normal mode` still
  logs.
- **QEMU harness** (harness-only, outside this repo — `work/qemu/` in the
  port tree): `mass.py --only samsung-s23fe --image
  work/xi/s23fe-boot/qemu-shim/Image.qemu`, the same path as s23/s25edge,
  so the factory `Image` stays untouched. The conf constants are the
  factory ones; the boot banner is read from the image actually booted.

### Samsung — spray-write fix (found while porting s26fe)

`--samsung fake` hung after `plant1 target=… zombie` on every attempt (3/3),
with no `free_seen`/`burst` line ever printed. Cause: `spray_thread()` wrote
its 8 KB payloads with a blocking `write()` to a socket whose peer is never
drained (that is what keeps the pages pinned). The Samsung chain plants
**twice** on the same pool — `defex_hash` (zero) then `fake_cred` (fake) — and
plant 1 leaves each queue ~full, so plant 2's first write parks inside
`write()`, `pthread_join()` never returns, and the chain stops right after the
zombie is observed. Single-plant paths (`verify`, plain `fake`, `permissive`)
never fill the pool that far, which is why this was never seen before.

Fix: the spray writes use `send(…, MSG_DONTWAIT)`. A write that would block
queues no new skbuff anyway — the peer never frees space — so every byte that
used to land still lands and the reclaim geometry is unchanged; the only
difference is that a full queue can no longer park a spray thread past a
`pthread_join()`.

Reproduced against the pre-fix binary on `s26fe` (3/3 hangs at the same point,
`logs/s26fe-samsungfake{,-2,-3}.log`); with the fix the chain no longer hangs,
but it exposed a second problem: the pool is shared across stages, and every
plant leaves ~768 MB of payloads queued forever, so each burst starts with
less free sndbuf than the one before it and late stages starve — a burst whose
victim page is never reclaimed by our spray (`burst hit=0`) kills the stage,
and a miss was treated as fatal. Best pre-recycle run reached the fourth stage
(`logs/s26fe-samsungfake-fixed5.log`, misses at plant 4); runs with larger
sysctls or more CPUs still lost at plant 2, so the residue is the binding
constraint, not capacity or CPU count.

Two further changes in `run_plant()`/`stage_write()` fix that:

- **Per-attempt pool recycle (`pool_reset`)**: at each `stage_write()` attempt
  the spray pool from the previous attempt is closed (both ends of every
  socketpair — closing purges the queued skbuffs and returns their pages
  immediately) and a fresh one is created, so every burst starts with full
  sndbuf. The fake cred makes one pool permanently special: from the moment
  `fake_cred` lands, the queued payloads *are* the page `task->cred` points
  into, so that pool (`pool_a`) is pinned for the life of the process and
  every later stage runs on a second pool (`pool_b`). A plain
  drain-after-each-zero-stage would have been wrong here — with the shared
  pool it would have freed the fake cred's page. Releasing a completed zero
  stage's pool is safe because its rb node was erased from its tree when the
  child was reaped and nothing else references payload content; a missed
  plant's pool is safe to release too because the zombie is held and never
  reaped, so its stale nodes are never dereferenced.
- **Burst miss is retryable** (`res->retry = 1` on `burst hit=0`): the
  single-stage paths already looped on `!ok`, but `stage_write()` treated a
  miss as stage-fatal. A miss writes nothing and pins nothing, so a fresh
  plant with a fresh pool is a clean retry.

Re-run on `s26fe` with both changes (`logs/s26fe-samsungfake-recycle.log`):
the chain completes all five writes — `defex_hash` hit on attempt 1, `fake_cred`
miss then hit on attempt 2, `selinux` attempt 1, `fake_uid` miss then attempt 2,
`fake_euid` miss then attempt 2 — and the worker reports `uid=0 euid=0
setuid(0)=0 resuid=0/0/0`; the run then stops at `ksud missing` by design.
F7–F11 were re-run after the fix and still pass, so the zero-write and
single-plant paths are unaffected.

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

### Samsung — `g_slide` fix (found while porting a15xzh)

`--samsung fake` (and plain `fake`) parked on `no KASLR slide` before its
first write, so the endgame could never run. Cause: commit `227597d` moved an
`if (!g_slide) park_forever("no KASLR slide")` check to the top of the `fake`
branch, but `g_slide` was only ever assigned inside `run_plant()`, which runs
*after* that check. `calibrate_base()` had the slide in `site0` and threw it
away.

Fix: `calibrate_base()` now stores `g_slide = site0 - STATIC_TIMER_SITE` when
the vote succeeds. `run_plant()` still recomputes it from the site it captures,
so each write keeps its own authoritative slide.

Reproduced against HEAD (`git show HEAD:p7a/timer_p7a.c`, built with the same
NDK command) on both zephyr 5.15 and spinel 6.12:

| build | `timer fake` | `timer --samsung fake` |
|---|---|---|
| HEAD `timer_p7a.c` | `[!] no KASLR slide` → park | parked before `defex_hash` |
| fixed | writes `fake_cred` + `selinux_state`, child `resuid=0/0/0` | full chain, see the a15xzh section |

The zero-write `verify` path was unaffected either way (it never reads
`g_slide`) and was re-run after the fix on a15xzh and zephyr: still
`resuid=0/0/0` + `ROOT_SHELL_OK`. `app/src/main/assets/timer` was rebuilt from
the fixed source.

`validate_conf.py` needed two fixes for this port, both in the tool and not the
profiles: it resolved a profile to a vmlinux by the `release` field, which
Samsung profiles do not have (they set `release_prefix`), so the empty string
matched the first vmlinux alphabetically and reported 10 bogus symbol/BTF
mismatches; and its `copy_process_low21` cross-check only looked for
`kmem_cache_alloc_node`, which 5.15 does not emit here. With both corrected it
reports 0 errors for all 24 bundled profiles.

### samsung s24fe — `6.1.162-android14-11` (Samsung mode)

`conf/samsung/samsung-s24fe-6.1.162.conf`, for the Samsung Galaxy S24 FE
(SM-S721B, Exynos 2400e, EUX firmware `S721BXXUFEZJ6`, Android 17, patch
2026-10, 4K pages). The factory artifacts are predownloaded in
`timerroot-port/samsung/s24fe_sm-s721b_exynos/` (`boot.img`, `boot.img.lz4`,
`Image`, `btf.bin`, `metadata.json`); the kallsyms ELF rebuilt from them lives
in `work/xi/s24fe-boot/`.

The Samsung release string on this Exynos family carries no model suffix, so
`uname -r` is exactly `6.1.162-android14-11` on the S24, S24+, S24 FE and the
reference S26 Ultra build. The profile therefore pins `device_model =
"SM-S721B"` and `android_release = "17"`, and `UserService` now prefers an
identity-pinned Samsung conf over a release-only one (see *Profile selection*
below).

- **F1** banner `Linux version 6.1.162-android14-11 (build-user@build-host)`
  (Android clang 17.0.2, `#1 SMP PREEMPT Mon Oct 19 11:41:26 UTC 2026`),
  4K pages. The vulnerable `begin_new_exec` order is intact: `bl
  posix_cpu_timers_exit` at `0xffffffc0083ae5a4`, then `bl exit_itimers` at
  `0xffffffc0083ae5b4` (`begin_new_exec` itself at
  `0xffffffc0083ae1bc`) — VULNERABLE.
- **F2** factory `boot.img`
  `sha256 f5f4109953959d8f09e3b3142d0ee1dfcce4cf069dae8b77cc2373146b6fe899`
  (64 MiB, Android boot header v4 with an **empty** `cmdline` field); the
  extracted `Image` is
  `2a9e9aa3be718dc51fd7e6c389d243c50a97ed9c13914fba2160304181850ebd`
  (38 832 640 bytes), `.BTF` is
  `d6991a6975155571d8ec653db9f00ec971af657fce0c5ac2b7453dbd7cb982e0`
  (5 997 046 bytes). `vmlinux-to-elf` rebuilds the kallsyms ELF at base
  `0xffffffc008000000` with **115 697 symbols**; KMI `android14-6.1`.
- **F3** `timer_site = 0xffffffc008194fe0`: `do_timer_create` loads
  `posix_timers_cache` (`0xffffffc00a53b3e0`, `adrp`/`ldr` off
  `0xffffffc00a53b000+0x3e0`) into `x0` at `0xffffffc008194fd8` and calls
  `kmem_cache_alloc` at `0xffffffc008194fdc`; `sitecheck.py` confirms this is
  the only `posix_timers_cache` allocation site. `copy_process_low21 =
  0xacb7c`: `dup_task_struct`'s `bl kmem_cache_alloc_node(task_struct_cachep)`
  at `0xffffffc0080acb78` returns to `0xffffffc0080acb7c` (6.1 does not
  inline `copy_process` into it, so the trace scan has a single candidate).
- **F4** BTF plus `init_posix_timers`/`cred_init`/`fork_init` literals:
  `k_itimer` is `0x108` with the `cpu_timer` node at `+0x78`; `struct cred`
  is `0xb0` (`cred_jar` object `0xc0`) with a 4-byte `atomic_t usage` at
  `0x0`, `uid 0x4`, `euid 0x14`, `cap_inheritable 0x28` (5 words),
  `security 0x78`, `user 0x80`, `user_ns 0x88`, `ucounts 0x90`,
  `group_info 0x98`; `task_struct` is `0x12c0` (BTF; there is no
  `arch_task_struct_size` bump on this build) with `cred` at `+0x838`; the
  trace `alloc_req_off` is `0x10`, matching the BTF
  `trace_event_raw_kmem_cache_alloc` shape.
- **F5** `selinux_state 0xffffffc00a5ea4a8`,
  `panic_on_warn 0xffffffc00a2eac00`, `root_user 0xffffffc00a310a00`,
  `init_user_ns 0xffffffc00a310770`, `init_ucounts 0xffffffc00a3121d8`,
  `init_groups 0xffffffc00a311d20`. DEFEX `creds_fast_hash` is its own
  kallsyms symbol at `0xffffffc00a66e9f8` (`creds_hash 0xffffffc00a62e9f8` +
  `0x40000`); `get_task_creds` indexes it directly as an 8-byte pointer array
  for `pid <= 0x8000`. `selinux_state - 8` is
  `avc_latest_notif_update.notif_lock` and BTF puts `enforcing` at bit 0, so
  the `-7` store lands on `enforcing`. `blobsim2.py` LSM order is
  `capability, safesetid, integrity, selinux`: only SELinux carries a 32-byte
  cred blob, so `selinux_blob_off = 0x0` and `selinux_sid_kernel = 1`.
  `fullcap = 0x1ffffffffff`.
- **F6** `validate_conf.py`: 0 errors over all 35 bundled confs; for this
  profile 6/6 symbols match the factory vmlinux, the `do_timer_create` call
  site and `copy_process_low21` match, and the worst case node `0x1f68` /
  cred end `0x2030` spills past the `0x2000` slab into the retry path
  (documented, designed). `--selfcheck` booted in QEMU: **0 failures** across
  the eleven invariants (`slab_size 0x2000`, `timer_site_low21 0x194fe0`,
  `copy_process_low21` in 21 bits, `cred_uid_off 0x4`, `fake_cred_off 0x18`,
  `cred_req 0xb0 < cred_alloc 0xc0`, `alloc_req_off 0x10`, linear window
  `0xffffff0000000000..0xffffffc000000000` below the image).
- **F7–F11** all pass in QEMU on the **first** shim boot
  (`work/qemu/logs/mass-s24fe.json`): slabinfo reports `posix_timers_cache`
  object `264` (`0x108`), 31 objects / 2 pages (order 1), `task_struct` `4800`
  (`0x12c0`, 6 objects / 8 pages, order 3) and `cred_jar` `192` (`0xc0`);
  `target` prints the banner, `pagesize=4096` and
  `timer_site=0xffffffc008194fe0`; `ids` `page_alloc=264 page_free=262
  pairs=1029`; `probe` `recs=4096 kept=4096`; `leak` 512/512 votes; verify
  reaches `child report uid=0 euid=0 setuid(0)=0 errno=0 resuid=0/0/0` plus
  `ROOT_SHELL_OK`. F12/F13 stay pending on a device.
- **Profile selection** the four 6.1.162 Exynos models share one `uname -r`,
  so `confMatches()` alone cannot tell their profiles apart. `UserService`
  now keeps a `device_model`-pinned Samsung conf only when
  `ro.product.model` (and `ro.build.version.release`) match, and falls back
  to the unpinned conf otherwise — the old single-profile Samsung behaviour.
  The same rule already applied to `maybe-dirty` confs.
- **QEMU note** as with the other Exynos/Knox builds the factory `Image` does
  **not** boot under `qemu-system-aarch64` unmodified: `_uh_call` traps in the
  missing secure monitor and `defex_load_rules` panics with
  `[DEFEX] Signature mismatch`. Verification used a **throwaway patched
  copy** (`work/xi/s24fe-boot/qemu-shim/Image.qemu`, built by the `mkshim.py`
  next to it; `--no-pgd` stops the patch ladder at two words). The factory
  artifacts stay unmodified and **no constant was derived from the shim**:

  | VA | original | shim | why |
  |---|---|---|---|
  | `0xffffffc00803bbf0` | `hvc #0` (`d4000002`) | `mov x0,xzr` (`aa1f03e0`) | `_uh_call` returns 0 instead of trapping; covers every call site |
  | `0xffffffc009e8dd68` | `bl do_load_rules` (`97ffff8e`) | `mov w0,wzr` (`2a1f03e0`) | `defex_load_rules` skips the hypervisor-signed rules file and takes its own success path |

  The failure ladder: unmodified → `_uh_call` traps; with only that patch →
  `[DEFEX] Signature mismatch` panic from `defex_load_rules`; with both →
  userspace, and F7–F11 pass on the first attempt. Unlike s23/s23fe this
  build needs **no** RKP page-table, KDP or vfsmount patch — the two sites in
  `PGD_PATCHES` are unused here. Rebuild with
  `python3 mkshim.py <factory Image> Image.qemu --no-pgd`
  (result sha256 `1cec3804a1ed4446e848a0d98efe7169a95a9fcbb348687ad7d29d1915b99bf9`).
- **Kernel boot parameters** the profile adds nothing to the kernel command
  line, and the factory `boot.img` v4 header `cmdline` field is empty — on a
  real S24 FE `/proc/cmdline` is whatever the bootloader and the built-in
  bootconfig supply. The app records it verbatim as `kernel_boot_params`
  (`cat /proc/cmdline`, `DeviceProbe`), and for this port the reference
  values are:
  - QEMU `-append` used for every gate here:
    `console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init panic=-1
    slub_min_order=1 qconf=samsung-s24fe-6.1.162.conf` (`qargs=`/`qmode=`
    only steer the initramfs harness).
  - Observed in-VM `/proc/cmdline`:
    `console=ttynull stack_depot_disable=on cgroup_disable=pressure
    kasan.page_alloc.sample=10 kasan.stacktrace=off kvm-arm.mode=protected
    bootconfig ioremap_guard console=ttyAMA0 earlycon=pl011,0x9000000
    rdinit=/init panic=-1 slub_min_order=1 qconf=…`

  `slub_min_order=1` is a QEMU-only knob: it reproduces the phone's order-1
  `posix_timers_cache` slab independently of the VM's CPU count, and is not
  needed on a device. No profile constant depends on any boot parameter —
  there is no `android_arch_task_struct_size` bump on this build (the
  `task_struct` object is the plain `0x12c0`).
- **Foreign banner** booting the same conf against a 5.15.194 `zephyr` Image
  is refused before any kernel access:
  `conf release prefix mismatch: conf=6.1.162-android14-11
  running=5.15.194-android13-8-00015-gf5526d1116e5-ab15004895`.
- **Siblings** the same constants cover SM-S921B (S24) and SM-S926B (S24+):
  their 6.1.162 `Image`s are different binaries (sha256 `073eaf03…` /
  `844ad759…`) but expose identical values for all six pinned symbols and the
  same `do_timer_create` / `dup_task_struct` sites
  (`work/xi/s24-probe/`, `work/xi/s24plus-probe/`). The S25 FE (SM-S731B) build is **not** compatible:
  its `root_user`, `init_user_ns`, `init_ucounts` and `init_groups` sit at
  +0x40 and its `creds_hash` / `creds_fast_hash` at +0x90 (only
  `selinux_state` and `panic_on_warn` land on the same addresses) — that
  model needs its own profile.

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
| F7 `timer target` | pass (QEMU) | every generic profile with a workspace `Image`, plus the s23fe, s24fe, s25edge and s23 shim runs, prints its own `timer_site`, exit 0 |
| F8 `timer ids` | pass (QEMU) | page event ids resolved in every profile |
| F9 `timer probe` | pass (QEMU) | base vote + `pair pfn` agreement on every profile |
| F10 `timer leak` | pass (QEMU) | 512/512 base votes, cred leaked on the first attempt |
| F11 verify | pass (QEMU) | zero-write child reaches `resuid=0/0/0`, `ROOT_SHELL_OK` |
| F12 permissive | pending | needs SELinux policy, not just the LSM being compiled in |
| F13 `timer fake` | pending | needs KernelSU present |
| F14 QEMU | pass | every generic profile with a workspace `Image` passes every gate (table below); s23fe, s24fe, s25edge and s23 pass in their own shim runs; s26u is the only provenance exception, not a binary result |
| F15 hardware | pending | no device |
| F16 app | defer | tables added as `verified in QEMU`; flip to `tested` only after F15 |

### F14 — QEMU mass run

Every conf whose factory Image is in the workspace was booted in
`qemu-system-aarch64 -M virt` at the profile's page size and driven through
the shipped aarch64 binary. **18 of 22 generic profiles ran and all 18 passed
every gate**, and the Samsung `a15xzh` profile passed the same gates as a
separate run (its factory `Image` needs the vendor-hook shim described in its
section above). The other four are the imported OPPO/realme profiles
(`6.12.58-…-ab15213644-4k`, `6.12.69-…-g242e1a07f878-ab15865446-4k`,
`6.6.118-…-g9bc34d5b0c79-abogki537459655-4k`,
`6.6.66-…-abogki428889875-4k`), which have no factory artifact in the
workspace — one of them was derived from a device dump, so there is no image
to boot. `logs/mass-final.json` holds the per-profile detail.

Re-run after the spray-write fix and pool recycle (`logs/mass-recl.json`,
27 profiles: the 22 above plus `samsung-s26fe`, `samsung-s26u` and the two
`maybe-dirty` confs): **19 of the 21 profiles with a workspace Image passed
every gate**, including the first full-suite run of `samsung-s26fe`. The two
exceptions are provenance/environment limits, not binary behaviour, and both
reproduce deterministically:

- `samsung-s26u` — the profile's constants come from the SamTimer reference
  6.1.162 build, whose factory `boot.img` is not in the workspace. Its
  generic `release_prefix = "6.1.162-android14-11"` prefix-matches the
  workspace `g9dd05ae3a1de-ab16261587` Image (a different binary: the
  reference layout is KASLR-disabled, text at `0xffffffc008…` vs this
  kernel's `0xffffffc080…`), so the harness boots a lookalike banner and the
  run fails at `base` calibration (`made=512 site=0 count=0`, identical
  twice). The profile row stays *untested* until the S24/S26 Ultra factory
  image is fetched and the constants re-derived; the s26fe profile pins the
  full banner for exactly this reason.
- `samsung-a15xzh` — the factory Image cannot boot unmodified in QEMU (Knox
  `_uh_call`); the throwaway vendor-hook shim copy from its port was cleaned
  from `/tmp`, so the boot dies before slabinfo. Its gates all passed in the
  dedicated runs recorded in its section above.
- `samsung-s25edge` — the factory Image needs the same class of vendor-hook
  shim (RKP `uh_call`, RKP page-table allocator, KDP, DEFEX rules signature;
  the exact five words are in its section). Run separately with the harness
  `--image` override: **all gates passed on the first attempt**
  (`logs/mass-s25edge.json`), and the `--samsung fake` endgame completed in a
  second run, stopping only at the designed `ksud missing`.
- `samsung-s23` — the 5.15 factory Image needs the vendor-hook shim too (RKP
  `uh_call`, RKP page-table allocator, KDP, DEFEX rules signature, plus the
  KDP `vfsmnt_cache` fill; the exact six words are in its section). Run
  separately with the harness `--image` override: **all gates passed on the
  first attempt** (`logs/mass.json`).
- `samsung-s23fe` — the first 5.10 (and first Exynos) image; it needs its own
  vendor-hook shim (`hvc #2` `_uh_call`, the two RKP page-table allocator
  sites, KDP, DEFEX rules signature, plus the KDP vfsmount fills in
  `vfs_create_mount`, `kdp_mnt_alloc_vfsmount`, `kdp_set_mnt_root_sb` and the
  three `mnt_flags` helpers; the exact words are in its section). Run
  separately with `--image`: **all gates passed** (`logs/mass-s23fe.json`),
  and the `--samsung fake` endgame completed to the designed `ksud missing`.

`samsung-s23` was ported after that sweep. It has its own factory `Image` and
passed every gate in a separate shim run (`logs/mass.json`), which brings the
count to **20 of the 22 profiles with a workspace `Image`**. `samsung-s23fe`
followed as the first 5.10 profile and also passed every gate in its own shim
run.

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
| 6.12.81-…-ab16388316-4k | blazer (Pixel 10 Pro) | pass | pass | pass | pass | pass | pass |
| 6.12.81-…-ab16388316-16k | blazer 16K | pass | pass | pass | pass | pass | pass |
| 6.12.81-…-gf5369e7496cb-4k | cubs/grizzly/kodiak/yogi (Pixel 11) | pass | pass | pass | pass | pass | pass |
| 6.12.81-…-gf5369e7496cb-16k | Pixel 11 16K | pass | pass | pass | pass | pass | pass |
| 6.18.21-…-abogki555938958-4k | hongkong/madrid | pass | pass | pass | pass | pass | pass |
| 6.18.21-…-abogki565292102-4k | lhasa/yingtian | pass | pass | pass | pass | pass | pass |
| 6.6.118-…-ab15657065-4k | mist | pass | pass | pass | pass | pass | pass |
| 6.6.118-…-abogki536571621-4k | iolite | pass | pass | pass | pass | pass | pass |
| 6.6.118-…-abogki519650608-4k | dada | pass | pass | pass | pass | pass | pass |
| 6.6.118-…-ab16143355-4k | dada (OS4) | pass | pass | pass | pass | pass | pass |
| 6.6.118-…-ab15511674-4k | kunzite | pass | pass | pass | pass | pass | pass |
| 6.6.118-…-gc4127a25dcf3-ab15863337-4k | OnePlus 13 (CPH2653) | pass | pass | pass | pass | pass | pass |
| 6.6.127-…-ab16252310-4k | frankel (Pixel 10) | pass | pass | pass | pass | pass | pass |
| samsung-a15xzh-5.15.189 | a15xzh (Galaxy A15 5G) | pass | pass | pass | pass | pass | pass |
| samsung-s26fe-6.6.127 | s26fe (Galaxy S26 FE) | pass | pass | pass | pass | pass | pass |
| samsung-s25edge-6.6.127 | s25edge (Galaxy S25 Edge) | pass | pass | pass | pass | pass | pass |
| samsung-s23-5.15.197 | s23 (Galaxy S23) | pass | pass | pass | pass | pass | pass |
| samsung-s23fe-5.10.240 | s23fe (Galaxy S23 FE) | pass | pass | pass | pass | pass | pass |
| samsung-s26u-6.1.162 | s26u (Galaxy S24/S26 Ultra) | pass | pass | pass | n/a | n/a | n/a |
| samsung-s24fe-6.1.162 | s24fe (Galaxy S24 FE) | pass | pass | pass | pass | pass | pass |

(the two `n/a` rows for s26u are the provenance mismatch above; the
`maybe-dirty` confs report `kernel not in workspace` like the four OPPO/realme
imports.)

`samsung-s24fe` was ported after that sweep. It has its own factory `Image`
and passed every gate in a separate shim run (`logs/mass-s24fe.json`), which
brings the count to **21 of the 23 profiles with a workspace `Image`** — the
S24 FE section above records the run. The 6.12.81 Pixel 11 pair (4K + 16K)
was ported after that and also passed every gate
(`logs/mass-6.12.81-p11.json`), bringing it to **23 of the 25**.

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

The OnePlus 13 profile was added after that sweep and passed every gate in
its own run (`logs/mass-oneplus13.json`). It is also the first profile whose
slab geometry was re-checked on a boot **without** `slub_min_order` (order
still 1 at `smp=4` and `smp=8`) and with a full no-hint F9/F11 replay.

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

## 6.1.172 — Pixels 6a-10a, November 2026 (CP4A.261105.040)

### `6.1.172-android14-11-g8d0115b07367-ab16385437` (4K and 16K)

The November 2026 monthly ships one identical 6.1 kernel binary on all
fifteen 6.1 GKI Pixels (bluejay, panther, cheetah, lynx, shiba, husky,
akita, tokay, caiman, komodo, tegu, comet, felix, tangorpro, stallion) —
decompressed Image sha256 `5c1b01c87980ea45a3a03d6bdc85e442d6fec8a087a0dfba6d0618b7f1cc13bb`,
35,772,928 bytes. The kernel moved 6.1.162 -> 6.1.172 in this release, so
the old `6.1.162` profiles no longer match the running banner on an updated
device. Factory kernels were range-fetched straight out of the factory zips
(`timerroot-port/pixel/<codename>/`, `fetch_boot.py` there; the inner
`image-*.zip` is stored uncompressed, so `boot.img`/`kernel_16k` come out of
HTTP ranges without pulling the ~4-15 GB images). Artifacts and derivation
logs: `work/xi/tegu172-boot/` (4K from the tegu factory image, boot.img
sha256 `9c9a99fe3204b56e…`; 16K from the same zip's `kernel_16k`,
sha256 `184a9ba1dd675a46…`).

- **F1** `begin_new_exec` order (4K @ `0xffffffc0083a76c0`, 16K @
  `0xffffc000083a7470`): `exec_mmap` -> **`posix_cpu_timers_exit`** ->
  `exit_itimers` on both — VULNERABLE.
- **F3** `timer_site = 0xffffffc008192f9c` (16K `0xffffc000081930a8`),
  `bl kmem_cache_alloc` inside `do_timer_create`, `x0` fed by
  `posix_timers_cache` (`sitecheck.py`); `copy_process_low21 = 0xaba1c`
  (16K `0xab98c`) from the `dup_task_struct` `bl kmem_cache_alloc_node`
  return address.
- **F4** geometry unchanged from 6.1.162: `timer_alloc = 0x108` (BTF
  `k_itimer`), `cred_req = 0xb0` / `cred_alloc = 0xc0`, `task_alloc_bytes =
  0x12c0` (BTF `task_struct`), `task_cred_off = 0x838`. **Device correction
  (2026-11-16, lynx hardware):** the factory Image has no vendor extension,
  but the shipped firmware adds one — the Pixel cmdline carries
  `android_arch_task_struct_size=784`, so `dup_task_struct` asks for
  `0x12c0 + 0x310 = 0x15d0` (`bytes_req=5584` on the live
  `kmem:kmem_cache_alloc` trace, slabinfo `task_struct` object 5632, 5 objs /
  8-page slab). QEMU boots the Image without the parameter and still matches
  `0x12c0`, which is why F7-F11 passed here while the first device runs
  failed. The conf keeps the factory value; `scan_task_allocs` accepts both
  (`p7a/timer_p7a.c`, commit `711bf29`).
- **F5** symbols: `selinux_state = 0xffffffc00a27c848` (16K
  `0xffffc0000a366858`), `panic_on_warn = 0xffffffc00a02ac0c`, `root_user`,
  `init_user_ns`, `init_ucounts`, `init_groups` per the conf comments.
  `enforcing` at bit 0 of `selinux_state`, `avc_latest_notif_update.notif_lock`
  at `selinux_state - 8` on both builds. `blobsim2.py`: same registration
  order (`capability`, `selinux(0)`, `safesetid(0)`, `integrity`), only
  selinux carries a 24-byte cred blob -> `selinux_blob_off = 0x0` (the 16K
  kallsyms ELF drops the local `selinux_blob_sizes` symbol, so the 16K
  `blobsim2` run reports MISSING; the registration order and `CONFIG_LSM`
  string are identical to the 4K build that resolved it).
- **F6** `validate_conf.py`: 0 errors on both confs; the worst-case node
  spills into the retry path (documented, designed). `target` mode prints
  `target=lynx` with the right `timer_site`; a VM booted with the old
  `6.1.162` conf refuses before any kernel access
  (`conf release mismatch: conf=6.1.162… running=6.1.172…`).
- **F7-F11** all PASS on the first attempt for both page sizes
  (`work/qemu/logs/mass-6.1.172.json`, `mass-6.1.172-16k.json`): slabinfo
  cross-check (`posix_timers_cache` object 0x108 at order 1 4K / order 0
  16K, `task_struct` 0x12c0), F7 target, F8 ids (a=263 f=261), F9 probe
  (4096/4096), F10 leak (made=512 votes=512), F11 verify
  (`child report uid=0 euid=0 setuid(0)=0 resuid=0/0/0`).
- **F12-F13** need a device, as always. The `tested` hardware rows in
  `docs/supported-devices.md` still refer to the 6.1.162 build.

#### Device gate — lynx, CP4A.261105.040.A1 (2026-11-16)

The first device runs all failed at `[-] cred leak failed` with
`task_recs=0` (`recs=3`) on every attempt — shell mode still got uid 0, but
fake mode (and therefore the KSU plant) never found the child's
task_struct. Root cause: the firmware vendor extension above; the scan
demanded exactly `0x12c0` while the device records `0x15d0`.

After the fix (scanner accepts `+0x310`, rebuilt binary md5
`5ab631cd20b33991c8ae18e111d709a7`, bundled as the app asset):

- Boot shell stage: `root shell ready` ~3 min after
  `LOCKED_BOOT_COMPLETED` (BFU, before unlock — the boot channel path).
- KSU plant: first post-reboot attempt missed the burst twice
  (`fake_cred exhausted retries`), attempt 2 hit (`burst hit=1 after
  81ms`, `fake cred page pinned`), selinux zero planted on attempt 2, then
  the chain completed: `[fake] worker setuid(0)=0 resuid=0/0/0` ->
  `worker exit=0`.
- Result: `auto: KernelSU active: selinux=Permissive (after 1s)`;
  `su -c id` -> `uid=0(root) context=u:r:ksu:s0` (SukiSU Ultra manager);
  auto-root pref `enabled=true`. KSU was late-loaded (ksud), not
  userspace-installed, so `/data/adb/ksu` stays empty.
- Plant reliability on this boot remains marginal (1 hit of 3 fake_cred
  bursts plus 1 selinux miss) — the pcp-reclaim burst timing is the
  limiting factor, not the geometry; parked zombies from misses require a
  reboot before another run (SKILL hard rule).

#### Reclaim-burst timing fix (husky hardware report, 2026-11-22)

A husky run with the same kernel/profile showed the shell stage winning on
its first plant (`free at 85ms`, `burst hit=1 after 105ms`) while all three
`fake_cred` plants missed.  The two useful signatures in that log were
`free_seen=0 burst hit=0 after 15078ms` on two attempts (one of them after a
3843ms PCP slabinfo wait) and `free_seen=1 burst hit=0` with the full
162048-send budget spent on the third.

Both come from the same place in `run_plant()`: the parent did not read
`trace_pipe_raw` until `wait_zombie()` and the PCP slabinfo wait were over.
During those waits the rings wrap, so either the victim's `mm_page_free` is
lost (phase 2 waits its whole window and bursts after the page is gone) or
the reclaim `page_alloc` is lost (a successful reclaim is scored as a miss
and the zombie is never reaped).  The PCP slab drop was also only a
confirmation: phase 2 still waited for a traced `mm_page_free` that these
kernels need not emit.

`p7a/timer_p7a.c` now starts a `reclaim_watcher` thread at `trace_start()`
that drains all eight per-CPU rings continuously and keeps one ordered
`free_seen -> hit` state for the whole plant.  For `pcp_free=1` profiles the
slabinfo drop publishes `g_free_seen` itself, so the burst starts at the
confirmed free rather than 14s later; the poll interval went 200ms -> 20ms.
The final after-stop pass and the `free at` line are preserved.  Syntax
checked with `gcc -fsyntax-only`; hardware F15 re-run is still pending.

Two follow-ups from the same sweep, recorded in
`timerroot-port/pixel/KERNELS.md`:

- `mustang`/`rango` kernels are byte-identical to the already-ported
  `6.12.81-…-ab16388316` blazer kernel, so those rows move to
  `verified in QEMU`.
- The Pixel 11 series ships `6.12.81-…-gf5369e7496cb-ab16467452-4k` in this
  release (all four, byte-identical); ported below with its 16K sibling.

## 6.12.81 — Pixel 11 series, November 2026 (CP4A.261105.040.D1)

### `6.12.81-android16-6-gf5369e7496cb-ab16467452` (4K and 16K)

All four factory images (`cubs`, `grizzly`, `kodiak`, `yogi`) carry
byte-identical payloads for both page sizes. The 4K image is
`1b9514dd3e43a4a2d86f07787dc6334cea41d3918467316a62ab5e3596f4e4c3`
(42,441,216 bytes); the standalone `kernel_16k` decompresses to
`5687a0ba8af2b632a97f315d113a8cd62f2674567d2f5c8b07d0337f03cca1a5`
(42,355,200 bytes). Artifacts kept in `timerroot-port/pixel/<codename>/`
(`Image`, `kernel_16k`) and derived under
`timerroot-port/work/xi/cubs-nov-boot/` and `cubs16k-nov-boot/`.

- **F1** `begin_new_exec` still runs the vulnerable order:
  - 4K (`0xffffffc080324f58`): `exec_task_namespaces` (`+0x248`) ->
    `posix_cpu_timers_exit` (`0xffffffc0803251b4`) -> `exit_itimers`
    (`0xffffffc0803251c4`) — VULNERABLE.
  - 16K (`0xffffc00080472238`): `exec_mmap` (`+0x3d0`) ->
    `exec_task_namespaces` (`+0x3fc`) -> `posix_cpu_timers_exit`
    (`0xffffc00080472648`) -> `exit_itimers` (`0xffffc00080472658`) —
    VULNERABLE.
- **F2** factory artifacts:
  - `boot.img` sha256 `85e7580d5c5004b43eefd85917635972f18d1f0b6d5f1b7d20a577ba4feb6d0b`
  - 4K kernel member (LZ4) sha256 `0a26d7b816449c4eccd604a6c3a5c4da9dcffcbcea96118b21252205e1f9520d`
  - `kernel_16k` member (LZ4) sha256 `54c06983918b630f128a554f3dd01a3d6f8a81c9705601b0161c499ad1549ab8`
  - `vendor_boot.img` sha256 `57b561f4416742ef820399de167e65bc0270517210d079c043e281c5cc584444`;
    its vendor command line carries `android_arch_task_struct_size=784`.
  - Recovered `vmlinux.elf` + `BTF`: 4K
    `dffc4deca82d06eb3c3c11603dce25a0aa107bdd78e61ad21d753aad34c620c1` /
    `994bc27d0fe2a347a8f150b72b84e60f52f3066453842ed761387603d650208b`
    (132,813 kallsyms symbols); 16K
    `cfae5448a1193e5454fc6466c27968f61fc7da570c62c9ce73ef27a33ab3debb` /
    `1d1ee8b80a805b31f960a43fde5d7c2f1a4ff5503080eb6a529c905180147c56`.
- **F3** call sites, confirmed by dataflow (`sitecheck.py`) and disassembly:
  - 4K `timer_site = 0xffffffc0802c85d8`: `alloc_posix_timer+0x24`
    `bl kmem_cache_alloc_noprof` with `x0` from
    `[adrp 0xffffffc0828b2000, #0x4f0]` (`posix_timers_cache`). The
    second `bl` at `+0x98` (site `0xffffffc0802c864c`) is the alloc-tag
    profiling path.
  - 4K `copy_process_low21 = 0xc9d4c`: inlined `dup_task_struct`, first
    `bl kmem_cache_alloc_node_noprof` at `0xffffffc0800c9d48` with `x0`
    from `task_struct_cachep`; the later `bl` at `+0xe2c`
    (`site ...caa34`) is the alloc-tag path.
  - 16K `timer_site = 0xffffc000801f86d4`: `do_timer_create+0xa8` `bl`
    with `x0` from `posix_timers_cache`; the second `bl` at `+0x588`
    (`site ...8bb4`) is the alloc-tag path.
  - 16K `copy_process_low21 = 0xdfb48`: standalone `dup_task_struct`,
    `bl kmem_cache_alloc_node_noprof` at `+0x50` with `x0` from
    `task_struct_cachep`; the `+0x474` `bl` is the alloc-tag path.
- **F4** geometry from BTF: `k_itimer` `0x100` (`timer_node_off` stays
  `0x78`), `cred` `0xb8` (`cred_req 0xb8` -> `cred_alloc 0xc0`),
  `task_struct` `0x1440`, `task_cred_off 0x900`. The vendor extension
  `784` is set by the firmware, so `task_alloc_bytes = 0x1440 + 0x310 =
  0x1750` on both page sizes. Cred offsets are the 6.12 layout:
  uid `0x8`, euid `0x18`, caps `0x30`, security `0x80`, user `0x88`,
  user_ns `0x90`, ucounts `0x98`, group `0xa0`.
- **F5** six kallsyms symbols (4K / 16K):
  `selinux_state` `0xffffffc0828db9a8` / `0xffffc000828d99b8`;
  `panic_on_warn` `0xffffffc08262ade0` / `0xffffc00082610de0`;
  `root_user` `0xffffffc082652348` / `0xffffc0008263b348`;
  `init_user_ns` `0xffffffc0826520d0` / `0xffffc0008263b0d0`;
  `init_ucounts` `0xffffffc082653ce0` / `0xffffc0008263cce0`;
  `init_groups` `0xffffffc082653810` / `0xffffc0008263c810`.
  `selinux_state - 8` is `avc_latest_notif_update.notif_lock` on both, and
  BTF puts `enforcing` at bit 0. `blobsim2.py` gives the runtime order
  `capability, landlock, safesetid, selinux, bpf` with `lbs_cred`
  landlock 8 / selinux 24, so `selinux_blob_off = 0x8`. The 16K numeric
  layout happens to equal the blazer 16K one, but every value here was
  independently derived from the `cubs` 16K payload.
- **F6** `validate_conf.py`: `0 error(s)` for both. `--selfcheck`:
  `ok (0 failures)` for both; the worst-case node spills into the designed
  retry path on both (`slab 0x2000` 4K, `slab 0x4000` 16K). A 4K image
  booted with the old `6.12.69` conf refuses before kernel access:
  `[-] conf release mismatch: conf=6.12.69-…-ab16108597-4k
  running=6.12.81-…-ab16467452-4k`.
- **F7-F11** all PASS on the first attempt for both profiles
  (`timerroot-port/work/qemu/logs/mass-6.12.81-p11.json`):
  - 4K: slabinfo cross-check pass (`posix_timers_cache` object `0x100`
    at order 1, `task_struct` `0x1750` rounded to `0x1780` for align 64);
    F8 ids `a=334 f=332 n=1029`; F9 probe `recs=4096 kept=4096`,
    `pair agree=1`; F10 leak `made=512 votes=512`; F11 verify
    `resuid=0/0/0`, `ROOT_SHELL_OK`.
  - 16K: slabinfo pass (order 0); F8 ids `a=334 f=332 n=1027`; F9 probe
    `recs=4096 kept=4096`; F10 leak `made=512 votes=512`; F11 verify
    `resuid=0/0/0`, `ROOT_SHELL_OK`.
- **F12-F13** need a device, as always (no SELinux policy / KernelSU in
  the QEMU initramfs). **F15** hardware pending; **F16** rows added to
  `docs/supported-devices.md` as `verified in QEMU`.

## Xiaomi 15 (dada / 24129PN74C), HyperOS 4.0 global — `OS4.0.0.11.XOCMIXM`, 6.6.118-android15-8-g0908354dac1b-ab16143355-4k

Ported from the shipped incremental OTA
`dada_global-ota_full-OS4.0.0.11.XOCMIXM-user-17.0-19e034272e.zip`
(metadata: `post-build=OS4.0.0.11.XOCMIXM`, `pre-device=dada`,
Android 17 / `CP2A.260605.016`, security patch 2026-09-01, payload
`8766355211` bytes, SHA-256 from `payload_properties.txt`). Artifacts
extracted locally into `timerroot-port/work/xi/` (boot, vendor_boot,
dtbo, unpacked kernel/ramdisk/bootconfig, reconstructed vmlinux+BTF):
boot image SHA-256 `3e8f0134cb685336a4a9b84916036beb48cbee9b2310776c0406278bce83c9e8`,
kernel raw SHA-256 `1073400e04a4cf94871b40a230b42af0078ff3f07aa6a52bff0469f0c127195b`.
Different kernel binary from the existing OS3.0.307.0.WOCCNXM port
(`6.6.118-...-abogki519650608-4k`), so a separate conf is required.

- **F1** same vulnerable ordering as other 6.6 builds:
  `exec_mmap -> exec_task_namespaces -> posix_cpu_timers_exit -> exit_itimers`;
  `CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y`; `CLOCK_PROCESS_CPUTIME_ID`
  returns `2,3,0`. Confirmed empirically by the F11 zero-write endgame
  reaching uid 0 against the real factory kernel in QEMU.
- **F2** `init_posix_timers` creates `posix_timers_cache` with size `0x108`,
  flags `0x4040000` (SLAB_PANIC|SLAB_ACCOUNT). `do_timer_create` allocates
  from it (`0xffffffc08234c760`) at `0xffffffc080195d4c` ->
  `timer_site 0xffffffc080195d50`. `copy_process` allocates `task_struct`
  from `task_struct_cachep` (`0xffffffc082325990`) via
  `kmem_cache_alloc_node` at `0xffffffc0800ab938` ->
  `copy_process_low21 0xab93c`.
- **F3** BTF layout: `cred` `0xb8` (`uid 0x8`, `euid 0x18`,
  `cap_inheritable 0x30`, `security 0x80`, `user 0x88`, `user_ns 0x90`,
  `ucounts 0x98`, `group_info 0xa0`); `task_struct` `0x12c0`
  (`cred 0x820`, `real_cred 0x818`); `k_itimer` `0x108` (`it 0x78`,
  `rcu 0xf8`).
- **F4** `cred_req 0xb8`, `cred_alloc 0xc0` (SLAB_HWCACHE_ALIGN rounds
  the `0xb8` cred object up to `0xc0`), `cred_cap_off 0x30`,
  `cred_cap_count 5`, `fake_cred_off 0x18`. `task_struct` base `0x12c0`
  plus `0x200` (cmdline `android_arch_task_struct_size=512`, capped at
  `0x400` by `task_struct_vendor_size_setup`) -> `task_alloc_bytes 0x14c0`.
  BTF cross-check: `task_cred_off 0x820`. `timer_alloc 0x108`,
  `timer_node_off 0x78`, `alloc_req_off 0x10` (bytes_req - call_site in
  `trace_event_raw_kmem_cache_alloc`).
- **F5** `selinux_state 0xffffffc08236a2e0` (`enforcing` @ +0),
  `panic_on_warn 0xffffffc08211ae0c`, `root_user 0xffffffc08213f1e0`,
  `init_user_ns 0xffffffc08213ef50`, `init_ucounts 0xffffffc082140cb0`,
  `init_groups 0xffffffc082140740`, `task_struct_cachep 0xffffffc082325990`,
  `posix_timers_cache 0xffffffc08234c760`. All 6 conf symbols match the
  reconstructed vmlinux exactly.
- **F6** `selinux_blob_sizes{cred=24,...}` is the only cred-blob contributor
  in ordered LSM init for this build (`capability, selinux, bpf, integrity`;
  bpf lbs_cred 0, landlock absent) -> `selinux_blob_off 0x0`. Conf
  `conf/6.6.118-android15-8-g0908354dac1b-ab16143355-4k.conf` passes
  `validate_conf.py` (slab `0x2000` obj `0x108`: worst node `0x1f68`
  cred_end `0x2038` spills/retry path, same class as OS3; `alloc_req_off
  0x10` matches BTF).
- **F7–F11 / F14 (QEMU)** booted the real arm64 `Image` from this boot.img
  in `qemu-system-aarch64` at 4K pages with
  `android_arch_task_struct_size=512` and `slub_min_order=1`, using the
  shipped aarch64 `timer` binary through `mass.py`. All gates PASS:
  `slabinfo` (`posix_timers_cache` obj `0x108`/order 1, `task_struct` obj
  `0x14c0` confirming the vendor extension),
  `F7_target` (release/site `0xffffffc080195d50`),
  `F8_ids` (`a=275 f=273 n=1029`), `F9_probe` (`recs=4096 kept=4096`,
  base/page-pair agree), `F10_leak` (`made=512 votes=512`). The original
  F11 transcript reported `uid=0 euid=0 resuid=0/0/0`, but that run was
  still PID 1/root: the child is root before the plant, so the check
  proved nothing about the cred write. After the harness started dropping
  to uid 2000, 1/4 eight-CPU replays reproduced the device failure
  exactly — `free_seen=1 burst hit=1`, `plant1 reaped status=0x9`,
  `cred writes landed`, then `[child] woke uid=2000 euid=2000` and
  `cred writes did not land`. The reclaim/reap success flags do not prove
  the stale `rb_erase` ran on the payload; when the free lands after the
  phase-1 burst the page can be recycled after the erase has already
  passed. `p7a/timer_p7a.c` now reads the child's real uid from
  `/proc/<pid>/status` after each plant and retries the whole plant (fresh
  pool, fresh target) up to six times until it is actually 0. With that
  fix the uid-2000 harness passes: 8/8 eight-CPU runs reached
  `ROOT_SHELL_OK` (one needed a second plant), and `mass.py` reports
  `F11_verify=PASS(resuid=0/0/2000)` because an unprivileged `setuid(0)`
  from a zeroed real uid cannot clear the saved uid. Transcripts:
  `timerroot-port/work/qemu/logs/mass-dada-os4.json` (old root run),
  `mass-dada-fixed2.json` (uid-2000 run). Rebuilt binary
  `p7a/timer_p7a` sha256 `6cf47fb8…`.

Runtime gates still pending for this build: **F12–F13** KernelSU manager
smoke, **F15** hardware verification (needs a physical dada device). Port
status: static re-derivation (F1–F6) and QEMU runtime (F7–F11, F14) complete;
hardware/manager gates remain.

**First hardware attempt (2026-11-21, uid 2000):** failed with the pre-fix
binary staged (`sha256 1da4329d…`, 2,144,472 bytes). `timer-shell-dada-OS4-1.log`
shows `plant attempt 1/3`, `free_seen=1 burst hit=1`, `plant1 reaped status=0x9`,
`cred writes landed`, then `[child] woke uid=2000` / `cred writes did not
land` — the exact signature reproduced in QEMU before commit `97f1d71`.
`timer_last-dada-OS4-1.log` stops after the profile line (dirty device; reboot
required between attempts). The beta workflow now force-refreshes the rolling
beta asset (`plant attempt %d/6`) on every app run and every auto-root boot,
because the shell service keeps a stale protocol-3 binary across APK updates.
F15 re-run with the refreshed binary is still pending.

**Second hardware attempt (2026-11-23, kernel root then KernelSU load fails):**
the zero-write endgame succeeded (`[child] woke uid=0`, `resuid=0/0/2000`,
`root shell ready`), then every `fake` stage failed with
`[+] plant1 free_seen=1 burst hit=1` / `plant1 reaped status=0x9` followed by
`[child] woke uid=2000 euid=2000 mode=fake` and
`[fake] worker setuid(0)=-1 errno=1`. The app reported
`the exploit parked before loading ksud`, which blames ksud for a failure that
happened before it ran.

Root cause is **slab geometry, not the fake-cred trail**. `[base]` in the same
log tells it:

```
13:42:18  [base] ... count=483 order=1 size=0x2000   <- zero stage, works
13:42:20  [base] ... count=31  order=0 size=0x1000   <- every fake stage
```

`posix_timers_cache` on this device is `248 248 264 31 2` in `/proc/slabinfo`:
object 264, **31 objects, 2 pages** — order 1, 8K, which is what the conf says.
The order-0 vote is an artefact of the vote itself: it pairs a slab with the
`mm_page_alloc` that created it, so it only sees slabs allocated inside the
capture window. Once an earlier run has warmed the cache, `timer_create()`
serves free objects from existing slabs, almost nothing is allocated, and the
vote collapses. Cross-checking every victim pointer in the log against both
geometries:

| run | victim | offset in used slab | `% timer_alloc` | offset in 8K slab |
|---|---|---|---|---|
| 13:42:18 zero | `…27c8ef78` | `0x0f78` | 0 | `0x0f78` |
| 13:42:20 fake | `…6d8ab9c8` | `0x09c8` | **128** | `0x19c8` |
| 13:43:16 fake | `…18a29080` | `0x0080` | **128** | `0x1080` |

So with `slab_size = 0x1000` the payload is built at `V & 0x0fff`, half a slab
away from the object the kernel erases at `0x19c8`, and the 4K skbuffs only
ever cover the half without the node. The stale node is never overwritten, the
erase finds zeroes, and the child keeps uid 2000 while every
`hit=1`/`reaped status=0x9` line still looks healthy.

Fixes:
- `slabinfo_geometry()` reads `posix_timers_cache`'s `pagesperslab` and makes
  it authoritative (`[+] slab geometry confirmed by slabinfo: order=1
  size=0x2000 obj=264 per=31`), overriding a disagreeing conf. The vote is now
  only used for the linear-map base.
- `calibrate_base()` drains the free objects slabinfo reports before
  measuring, so the vote sees a cold cache again.
- `vote_base()` no longer silently drops votes past the 64th distinct key.
- `run_plant()` rejects a victim whose in-slab offset is not a multiple of
  `timer_alloc` and retries, with a base fallback so calibration cannot hard-fail.
- The app now reports `the fake credential did not take effect, so ksud never
  ran` instead of blaming ksud.

QEMU re-run on the identical OS3 6.6.118 dada Image (2026-11-24) passed as
`uid=2000`: `runhigh: uid=2000 euid=2000 gid=2000`, slabinfo geometry
`order=1 size=0x2000 obj=264 per=31`, `[base] count=512 order=1`, and
`child report uid=0 euid=2000 setuid(0)=0 resuid=0/0/2000` + `ROOT_SHELL_OK`.
The fake stage reached `[child] woke uid=0 euid=0 mode=fake` and
`[fake] worker setuid(0)=0`; `KSU_MISSING` is expected because the initramfs has
no manager. The stock initramfs leaves kernel-created slabinfo `0400`, so it
also exercised the address-periodicity fallback. A second, audit-only
initramfs exposed slabinfo to uid 2000 and exercised the authoritative read and
both endgames. Evidence: `logs/mass-dada-os3-uid2000-20261124.json` and
`logs/dada-os3-uid2000-{zero,fake}{,-slabinfo}-20261124.log`.

The beta workflow for fix commit `5adcee3` also completed successfully
(run `45316418891`). Its `timer` asset is 2,164,208 bytes, sha256
`1ece3a4c7d9853128d6727dafbfc2a6170df8dcca0e35f2af938c36d19142dc2`, and its
`.text` is byte-identical to the locally rebuilt binary used for these QEMU
replays. The later source edits only correct comments; the rebuilt tracked
`p7a/timer_p7a` is an NDK r29 build of the current source,
2,153,512 bytes, sha256
`c9706844bfd0a4567123fd3652512a1eabe7b0833c04f689d13280e6697571f0`, with
the same `.text`. Hardware re-test on the affected Android 15 device is still
pending.

**Why `/proc/slabinfo` can be a usable oracle without root:** the Linux
kernels inspected here create it `root:root 0400`; Android userspace may then
apply `chown root log /proc/slabinfo` and `chmod 0440 /proc/slabinfo`. The Xiaomi
`dada` OS4 field probe proves effective access for that exact build: it ran as
`uid=2000` with supplementary `gid=1007(log)` under enforcing SELinux and printed
`posix_timers_cache 248 248 264 31 2`. The probe did not record the inode mode,
label or init rule. A separate live Pixel 7a (`lynx`, Android 17) reference
recorded all four links: `root:log 0440`, label
`u:object_r:proc_slabinfo:s0`, supplementary gid 1007, and a loaded policy
allowing `shell proc_slabinfo:file read`; its matching system `init.rc` contains
the DAC pair. That Pixel evidence is a reference, not proof of the Xiaomi init
configuration. All four links — kernel mode, later userspace DAC change, shell
group, and SELinux label/rule — matter. The contrast in the Xiaomi probe is
`/sys/kernel/tracing/events/timer/...` returning `Permission denied`, which is
exactly why geometry must come from slabinfo rather than tracing metadata.
The exploit already depended on this (`slab_usage()`, `slab_active()`), and the
log's `[slab] pre-exec active=…` lines are those calls succeeding as uid 2000.
If any link is absent, `derive_order_from_ptrs()` recovers the order from
address periodicity alone: on the 11 victim addresses above it scores order 1 at
11/11 aligned (31 objects/slab) against 5/11 for order 0, so the fallback
reaches the same answer with no slabinfo and no root. See
[the factory-image audit](docs/slabinfo-access-audit.md) for which images prove
each link and which remain inconclusive. That audit confirms the exact Pixel 9a
`tegu` CP3A.261005.005 factory set statically, including its product
`system.img`; the remaining offline-only sets are inconclusive, and none is
unsupported.

**Same release string, different text (the `moon` failure class).** A field log
from a device reporting `moon` with
`6.6.118-android15-8-ge56cf6b09cca-ab15511674-4k` — the `kunzite`/`goya`
release, and the only profile that release selects — died at
`[base] made=512 site=0 slide=0 best=0 count=0` with slabinfo confirming
`order=1 size=0x2000 obj=264 per=31`. Geometry, page-event ids
(`page_alloc=275 page_free=273 pairs=1029`) and the PID filter were all fine,
so the trace held no `kmem_cache_alloc` record whose `call_site` matched
`timer_site`. `TIMER_SITE_LOW21` is KASLR-invariant (the arm64 slide is 2 MB
aligned), so that is a text-layout difference, not a slide: a vendor build on
the same GKI tag with a different defconfig moves `do_timer_create`'s call
site. The 6.6.118 family alone already has `0x195d48` (kunzite/goya),
`0x195d50` (dada), `0x195d94` (iolite) and `0x1a4dfc` (Samsung).

Two real defects were found while chasing it, neither sufficient to explain
this log on its own:

- `enable_events()` wrote the three `enable_event:kmem:…` commands to
  `events/kmem/rss_stat/trigger` and ignored every result. A rejected write
  left a run with the page events on — so `ids` passed and looked healthy —
  and `kmem_cache_alloc` off, which is exactly `site=0 count=0`. Verified in
  QEMU with the trigger `chmod 444` as uid 2000: the old binary exits 1 right
  after the banner, the fixed one reads every event back, retries through
  `events/kmem/<event>/enable`, and completes the run.
- `pin()` ignored `sched_setaffinity()` failure. Every capture reads one CPU's
  `trace_pipe_raw`, so a denied pin (vendor cpuset for the shell domain)
  traces a buffer the allocations never touched and again produces
  `site=0 count=0`. The binary now falls back to an allowed CPU and logs
  `[!] cannot pin to cpu …`.

Calibration now names the three empty-scan cases instead of only printing
`site=0 count=0`: no `kmem_cache_alloc` records at all (event off), none with
`bytes_req == bytes_alloc == timer_alloc` (object size differs), or the size
matches but no `call_site` has the profile's low21 — in which case it prints
the captured sites (`observed call_site=… low21=… count=…`) so the device can
be ported. The `bestc < 4` floor stays: the base is the physical-page anchor
used when `pair_slab_pfn()` misses, so a 1-3 vote base is a wrong-address
write, and a slabinfo-confirmed *geometry* does not confirm the *pairing*.
QEMU 6.6.118 gates re-run after the change: `slabinfo`, `F7_target`,
`F8_ids`, `F9_probe`, `F10_leak` and `F11_verify`
(`resuid=0/0/2000`, `ROOT_SHELL_OK`) all pass on the factory Image.

## OnePlus 13 (CPH2653), OxygenOS/ColorOS 17.0.0.102 (EX01) — `6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k`

Factory artifacts supplied in `timerroot-port/oneplus/Oneplus13/CPH2653_17.0.0.102(EX01)/`
(`boot.img`, `init_boot.img`, `vendor_boot.img`; 4K pages, no
`android_arch_task_struct_size=` on the vendor command line or in
`vendor_boot`'s bootconfig/`dtb`). Work tree:
`timerroot-port/work/oneplus13/` (`boot/kernel`, `vmlinux`, `btf.bin`,
`vb/`); the `mass.py` workspace entry is `work/xi/oneplus13-boot/`.

`mass.py` actually resolves this conf to the **pre-existing** `work/xi/dg4-boot/`
entry (an OTA payload unpacked on 20 Nov, before this port) whose `kernel` is
byte-identical to the supplied `boot.img`'s Image
(`3ccbdb1b…607bad24`, verified with `sha256sum` on both paths). The
`oneplus13-boot/` symlink dir exists so the validator can find
`vmlinux`/`btf.bin`/`pagesize`; the QEMU runs boot `dg4-boot/kernel`. The
two `boot.img`s are not identical as files (1 908 differing bytes, AVB/
signature area) but their kernels are.

- boot.img sha256 `b83602958c464a6a344589cd41b1fceec49f8e1d2513e215afcd003f93493bd4`
- Image sha256 `3ccbdb1b4bd1c8610b4d6fd987ea9247ca95b43c0ddd21d3e51de771607bad24`
  (36 801 024 bytes, `ARM\x64` at +56, BTF blob at file offset `0x1717d64`,
  6 118 877 bytes, sha256 `369f09626d9e546d6d140abc388f1cd6f7a022d8d26798d73e7a291d43bfb2c2`)
- vmlinux (reconstructed, 110 141 symbols) sha256 `2e22f82c71e6d84100e6499b2953ed5f9581c5ac217f41cc11c7e0bb70ca084b`
- vendor_boot.img sha256 `ba81b50a633cfc4b7a720110d32e5db8735d5b48fefbaddda2790aee67d86b8b`;
  `init_boot.img` sha256 `10241baad4a0d535d13ec7e9e81601a32a1e49a4fb9b15b2f3fb80e257361f8f`

This is a **new kernel binary**, not a sibling of any Xiaomi 6.6.118 payload,
even though every derived constant happens to coincide with the kunzite/mist
pair (only the release string differs in the conf). The image is the same
36 801 024-byte size as kunzite/mist but 8 737 of its 8 984 4K pages differ,
and its banner `-gc4127a25dcf3-ab15863337` matches no existing profile. Every
constant below was nevertheless derived independently from this `Image`
(disassembly + BTF + embedded `ikconfig`), not copied from the Xiaomi confs.

- **F1** VULNERABLE, same ordering as the other 6.6 builds:
  `exec_mmap` (`0xffffffc0803d51cc`) -> `exec_task_namespaces`
  (`0xffffffc0803d51fc`) -> **`posix_cpu_timers_exit`**
  (`0xffffffc0803d5214`) -> `exit_itimers` (`0xffffffc0803d5224`).
  Embedded `ikconfig` confirms `CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y`,
  `CONFIG_ARM64_4K_PAGES=y` (16K not set), `CONFIG_SLUB=y`.
- **F2** `init_posix_timers` (`0xffffffc081d18c20`) creates
  `posix_timers_cache` with `mov w1, #0x108` and flags `0x4040000`
  (`SLAB_PANIC|SLAB_ACCOUNT`), storing the cache at
  `0xffffffc08234c760`. `do_timer_create` (`0xffffffc080195ca0`) loads it
  with `adrp x20, 0xffffffc08234c000` + `ldr x0, [x20, #0x760]` and calls
  `bl kmem_cache_alloc` at `0xffffffc080195d44` ->
  **`timer_site = 0xffffffc080195d48`** (`low21 0x195d48`).
  (`mov w1, #0xdc0` there is `GFP_KERNEL|__GFP_ZERO`, not a size — the size
  comes from the cache). `copy_process` (`0xffffffc0800ab7fc`) allocates
  `task_struct_cachep` (`0xffffffc082325990`) through
  `kmem_cache_alloc_node` at `0xffffffc0800ab938` (`mov w1, #0xcc0` is
  `GFP_KERNEL`) ->
  **`copy_process_low21 = 0xab93c`** (identical to the four Xiaomi 6.6.118
  builds, as expected — that call site does not move with the vendor
  defconfig here). `dup_task_struct` is inlined.
- **F3** BTF layout (same as the 6.6 family): `cred` `0xb8` with
  `usage 0x0` (8 bytes), `uid 0x8`, `gid 0xc`, `suid 0x10`, `sgid 0x14`,
  `euid 0x18`, `egid 0x1c`, `fsuid 0x20`, `fsgid 0x24`, `securebits 0x28`,
  `cap_inheritable 0x30`, `cap_permitted 0x38`, `cap_effective 0x40`,
  `cap_bset 0x48`, `cap_ambient 0x50`, `security 0x80`, `user 0x88`,
  `user_ns 0x90`, `ucounts 0x98`, `group_info 0xa0`;
  `task_struct` `0x12c0` with `real_cred 0x818`, `cred 0x820`;
  `k_itimer` `0x108` with `it 0x78` (`rcu 0xf8`).
- **F4** `cred_init` (`0xffffffc081d12358`) `mov w1, #0xb8` with flags
  `0x2000` (`SLAB_HWCACHE_ALIGN`) plus `movk w3, #0x404, lsl #16`
  (`SLAB_PANIC|SLAB_ACCOUNT`) -> `0x4042000` -> `cred_req 0xb8`,
  `cred_alloc 0xc0`.
  `task_struct_vendor_size_setup` (`0xffffffc081d0041c`) is present and adds
  the parsed value to `mov w9, #0x12c0`, capped at `0x400`; this image's
  vendor_boot bootconfig and `dtb` carry **no**
  `android_arch_task_struct_size=` parameter, so `task_alloc_bytes = 0x12c0`
  (confirmed at runtime: `task_struct` slabinfo object is 4800 = `0x12c0`).
  `alloc_req_off = 0x10` (`trace_event_raw_kmem_cache_alloc`:
  `bytes_req` at bit 192, `call_site` at bit 64) — 6.6, no `name` field.
  `timer_node_off = 0x78`.
- **F5** `selinux_state 0xffffffc08236a2e0` (preceded immediately by
  `avc_latest_notif_update.notif_lock` at `0xffffffc08236a2d8`, and BTF puts
  `enforcing` at bit 0, so the `-7` store lands on `enforcing`);
  `panic_on_warn 0xffffffc08211ae0c`, `root_user 0xffffffc08213f1e0`,
  `init_user_ns 0xffffffc08213ef50`, `init_ucounts 0xffffffc082140cb0`,
  `init_groups 0xffffffc082140740`. All 6/6 match the vmlinux
  (`validate_conf.py`).
- **F6** `__start_lsm_info` registers `capability` (order -1),
  `selinux` (order 0, `selinux_blob_sizes.lbs_cred = 24`),
  `bpf` (order 0, `lbs_cred = 0`), `integrity` (order 1). `CONFIG_LSM`
  names `landlock,lockdown,yama,loadpin,safesetid,selinux,smack,tomoyo,apparmor,bpf`
  but the embedded config sets `# CONFIG_SECURITY_LANDLOCK is not set`,
  `# CONFIG_SECURITY_YAMA is not set`, `# CONFIG_SECURITY_LOCKDOWN_LSM is
  not set`, `# CONFIG_SECURITY_SAFESETID is not set`,
  `# CONFIG_SECURITY_SMACK is not set`, `# CONFIG_SECURITY_TOMOYO is not set`
  and `# CONFIG_SECURITY_APPARMOR is not set`, so **selinux is the first
  cred-blob contributor** -> `selinux_blob_off = 0x0`.
  `conf/6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k.conf` passes
  `validate_conf.py` with 0 errors (`do_timer_create` bl ->
  `0xffffffc080195d48`, `copy_process` low21 `0xab93c`, 6/6 symbols,
  `alloc_req_off 0x10`). The worst-case node spills into the designed retry
  path (`slab 0x2000 obj 0x108: worst node=0x1f68 cred_end=0x2038`), the
  same class as the other 6.6 profiles. `--selfcheck` against the real
  factory Image reports `ok (0 failures)` for all ten invariants plus the
  informational spill line (`logs/oneplus13-selfcheck-20261127.log`), and the
  conf gate refuses a foreign banner before any kernel access: booting the
  kunzite/mist Image and handing it this conf prints
  `[-] conf release mismatch: conf=6.6.118-…-gc4127a25dcf3-ab15863337-4k
  running=6.6.118-…-g666ad52b8230-ab15657065-4k`, exit 1
  (`logs/oneplus13-wrongbanner-20261127.log`).
- **F7-F11 / F14 (QEMU)** booted the factory Image in `qemu-system-aarch64
  -M virt` at 4K pages with `slub_min_order=1`, driving the shipped NDK r29
  aarch64 `timer` binary through `mass.py` as uid 2000
  (`runhigh: uid=2000 euid=2000 gid=2000`). **All gates PASS**
  (`logs/mass-oneplus13.json`):
  - `slabinfo`: `posix_timers_cache` obj `0x108` order 1 (31 objects,
    pagesperslab 2), `task_struct` obj `0x12c0` — the profile's
    `timer_alloc` / `slab_order` / `task_alloc_bytes` are the kernel's own.
    Booted a second time without `slub_min_order` and at `smp=8`: the order
    still came out 1, so the geometry is not a harness artifact. A full
    no-hint pass (no `slub_min_order`, no `android_arch_task_struct_size`)
    also reproduces `F9_probe=PASS(recs=4096 kept=4096)` and `F11=PASS`
    (`logs/oneplus13-nohint-{probe,verify}-20261127.log`).
  - F7 `target` mode reports `kernel=6.6.118-…-gc4127a25dcf3-ab15863337-4k`,
    `pagesize=4096`, `timer_site=0xffffffc080195d48`, `protocol=3`; exit 0
    (`logs/oneplus13-f7-target-20261127.log`). The `target=lynx` line in that
    output is a hard-coded legacy marker the binary prints for every profile,
    so the gate was tightened to check `kernel=` / `pagesize=` /
    `timer_site=` instead of it.
  - F8 `page_alloc=275 page_free=273 pairs=1029`.
  - F9 `recs=4096 kept=4096`, `pair agree=1`.
  - F10 `made=512 votes=512` (`[base] … order=1 size=0x2000`).
  - F11 `child report uid=0 euid=2000 setuid(0)=0 errno=0 resuid=0/0/2000`
    + `ROOT_SHELL_OK`, `cred writes landed`. `mass.py` runs F11 twice; both
    gate runs landed the plant on the **first** attempt (`plant attempt 1/6`,
    `logs/…f11-1.log` and `…f11-2.log`). A separate manual verify boot took
    a retry (`[!] plant 1 left child uid=2000; retrying` -> `attempt 2/6`) and
    still reached `resuid=0/0/2000` + `ROOT_SHELL_OK`
    (`logs/oneplus13-f11-verify-20261127.log`); the no-hint boot landed on
    attempt 1 again (`logs/oneplus13-nohint-verify-20261127.log`).
    Transcripts: `logs/mass-oneplus13.json`, plus the four logs above.

  Note on the harness: `runhigh` in the port tree still had only the
  `RLIMIT_NOFILE` raise (no uid drop), and `gate_verify()` still required
  `euid=0` on the report line, which the uid-only plant never prints. Both
  were corrected in `work/qemu/runhigh.c` and `work/qemu/mass.py` for this
  port: `runhigh` now `setresgid`/`setresuid`s to 2000 after raising the fd
  limit (and `init` makes tracefs world-writable so uid 2000 can drive it),
  and `gate_verify()` accepts the `uid=0 euid=2000` wake line, rejects a
  `runhigh: uid=0` root harness outright, and requires `resuid=0/0/…` after
  the child's own `setuid(0)`. `gate_target()` likewise stopped gating on the
  hard-coded `target=lynx` marker and now compares `kernel=`, `pagesize=`
  and `timer_site=` against the conf, so one profile's boot can no longer
  satisfy another profile's F7.

**Runtime gates still pending**: **F12** (`timer permissive`),
**F13** (`timer fake` + KernelSU) and **F15** need a physical CPH2653.
The **F16** row is in `docs/supported-devices.md` as `verified in QEMU`.
Port status: static re-derivation (F1-F6) and QEMU runtime (F7-F11, F14)
complete for this build.
