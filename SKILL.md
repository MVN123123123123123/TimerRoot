---
name: timerroot-kernel-port
description: Port the TimerRoot exploit (CVE-2026-98260, POSIX CPU timer UAF) to a new arm64 Android/GKI kernel. Re-derive the per-build constants from the factory vmlinux (kallsyms + BTF), write a conf/ profile, validate it statically, then prove it in QEMU and on the device. Use when asked to port, retarget, add a profile for, or re-derive TimerRoot for another kernel build.
version: 4.2
applies_to: [arm64]
reference_impl: MVN123123123123123/TimerRoot, p7a/timer_p7a.c
---

# TimerRoot Port

> For the short, human-readable version of this procedure — the six steps, the
> numbers you need and why — see [Porting a kernel](docs/porting.md). This file
> is the full, agent-grade reference.

## 0. What porting actually is

The exploit is build-specific in a small, enumerable way. Most of the geometry
is **predictable from the kernel family** (see the cheat sheet in §2); per
build you only have to derive four things:

1. `timer_site` and `copy_process_low21` — two code addresses,
2. six kallsyms symbols,
3. the cred/task/slab sizes (mostly family-predictable, confirm from BTF),
4. `selinux_blob_off` (LSM order, the one that is *not* a lookup).

Everything lands in a **conf file** (`conf/<release>.conf`, HOCON syntax).
No source edits are needed for a new profile: the binary loads the conf,
asserts the invariants in `--selfcheck`, and refuses a foreign banner before
touching the kernel.

### The primitive (read once, then forget it)

1. A child `execve`s `/proc/self/exe` with `argv[0]=""`; `exec_thread` creates
   `NTIMERS` `CLOCK_THREAD_CPUTIME_ID` timers, `VICTIM_IDX` armed with a
   3600 s `SIGEV_SIGNAL` expiry.
2. `execve` tears down the thread group; `posix_cpu_timers_exit` leaves a
   **stale `timerqueue_node` in the freed `posix_timers_cache` slab**.
3. Spray threads reclaim that slab page with `SOCKBUF`-sized socket writes
   carrying a forged node.
4. On reap, `rb_erase` takes the left-child-only path:
   `*target = node[0]`, `*(node[0]+8) = dest`, then `node[0x20]` is cleared.
5. `node[0]` is the payload → **write a controlled 64-bit value to a
   controlled address**, plus two fixed side-writes.

Everything else is bookkeeping. A wrong constant corrupts kernel state with
no error return — every gate below exists to catch that before the write.

---

## 1. The flow

| Step | What | Gate |
|---|---|---|
| 0 | Identify banner, confirm the bug is still present | F1 |
| 1 | Pull factory `boot.img` + vmlinux + BTF from the OTA | F2 |
| 2 | Derive the per-build constants | F3–F5 |
| 3 | Write `conf/<release>.conf` | F6 |
| 4 | Static validation: `validate_conf.py`, `--selfcheck`, wrong banner | F6 |
| 5 | QEMU against the factory Image: `target`/`ids`/`probe`/`leak`/verify | F7–F11 (F14) |
| 6 | Device: re-run F10/F11, then `permissive` → `fake` → 200 runs | F12–F16 |

Commit one gate per commit, as `port: Fn <banner>`. Log every gate in
`PORT_LOG.md` — that file is the record that the procedure was followed.

---

## 2. Family cheat sheet — look here before deriving anything

Almost every geometry constant is a function of the kernel family. Derive the
per-build items in §5 and take the rest from this table (still confirm against
BTF — the table is a prior, not a substitute).

| | **5.15** | **6.1** | **6.6** | **6.12** | **6.18** |
|---|---|---|---|---|---|
| text base | `0xffffffc008000000` (`__pi_`) | `0xffffffc008000000` (`__pi_`) | `0xffffffc080000000` | `0xffffffc080000000` | `0xffffffc080000000` |
| timer alloc fn | `do_timer_create` → `kmem_cache_alloc` | same | same (non-`_noprof` name) | `alloc_posix_timer` → `kmem_cache_alloc_noprof` | `alloc_posix_timer` → `kmem_cache_alloc_noprof` |
| `timer_alloc` (sizeof k_itimer) | `0x108` | `0x108` | `0x108` | `0x100` | `0x180` |
| `timer_node_off` | `0x78` | `0x78` | `0x78` | `0x78` | **`0xe0`** (k_itimer grew `rcuref`) |
| task alloc fn | `dup_task_struct` → `kmem_cache_alloc` (no `_node` here) | `dup_task_struct` → `kmem_cache_alloc_node` | inlined in `copy_process` → `kmem_cache_alloc_node_noprof` | inlined → `_noprof` | `dup_task_struct` → `_noprof` |
| `sizeof(task_struct)` | `0x1200` | `0x12c0` | `0x12c0` | `0x1440` | `0x1280` |
| vendor ext present | no (`arch_task_struct_size` absent) | factory Image: no; **firmware can set it** — Nov 2026 Pixel monthly (`CP4A.261105.040`) boots `android_arch_task_struct_size=784` on the cmdline (verified on lynx: `dup_task_struct` records `bytes_req=5584` = `0x12c0+0x310`, slabinfo object 5632) | setup exists, factory images don't set it | yes (`=512`/`784`/`1024`) | yes (`=1024`) |
| `sizeof(cred)` / `usage` width | `0xb0` / 4B | `0xb0` / 4B | `0xb8` / 8B | `0xb8` / 8B | `0xb8` / 8B |
| `cred` uid / euid | `0x4` / `0x14` | `0x4` / `0x14` | `0x8` / `0x18` | `0x8` / `0x18` | `0x8` / `0x18` |
| `cred` securebits / caps | `0x24` / `0x28` | `0x24` / `0x28` | `0x28` / `0x30` | `0x28` / `0x30` | `0x28` / `0x30` |
| `cred` security / user / user_ns / ucounts / group | `0x78`/`0x80`/`0x88`/`0x90`/`0x98` | same | `0x80`/`0x88`/`0x90`/`0x98`/`0xa0` | same | same |
| `cred_req` → `cred_alloc` | `0xb0` → `0xc0` | `0xb0` → `0xc0` | `0xb8` → `0xc0` | `0xb8` → `0xc0` | `0xb8` → `0xc0` |
| `task_cred_off` | `0x798` | `0x838` | `0x820` | `0x900` | `0x908` |
| `selinux_blob_off` | `0x0` | `0x0` | `0x0` (no landlock cred blob) | `0x8` **if** landlock registers one, else `0x0` | `0x10` (landlock 11 → `ALIGN(11,8)=16`) |
| `pcp_free` | `1` | `1` | derive (§6) | derive (§6) | derive (§6) |

Family-invariant: `cred_alloc = ALIGN(cred_req, 64)`; `fake_cred_off = 0x18`
(it is a property of the `rb_erase` geometry, not of the cred layout);
`alloc_req_off = 0x10` (6.18 adds `name`, so it becomes `0x18` — both are
accepted by `--selfcheck`); `slab_order = 1`, `slab_size = 8192` at 4K;
`fullcap = 0x1ffffffffff` unless `CAP_LAST_CAP` changed;
`selinux_sid_kernel = 1`.

Runtime correction: `slab_order`/`slab_size` in the conf are a **hint**, and
`/proc/slabinfo` is the **authority when the shell can read it**. SLUB derives
the real order from the device's possible-CPU count, so a phone can differ from
the QEMU boot used to validate the profile. `posix_timers_cache`'s
`pagesperslab` column states the order outright (`2` pages → order 1 → 8K).

Do **not** assume slabinfo is world-readable. The Linux kernels inspected here
create it as `root:root 0400`; Android userspace commonly relaxes it later to
`root:log 0440`. A normal `adb shell` can then read it only if `adbd` grants the
shell supplementary group `log` (gid 1007) **and** the enforcing SELinux policy
labels `/slabinfo` as `proc_slabinfo` and allows `shell` to read that type.
These are independent requirements; neither a `ueventd.rc` rule nor a matching
`init.rc` rule proves the complete access chain. Audit `boot`, `init_boot`
(Android 13+), `vendor_boot`, and the matching system image; call incomplete
sets **inconclusive**. See
[the factory-image audit](docs/slabinfo-access-audit.md).

When slabinfo is readable, `calibrate_base()` reads it first and logs either
`[+] slab geometry confirmed by slabinfo: order=… size=… obj=… per=…` or
`[!] slab geometry mismatch: conf order=… slabinfo order=… (…); using slabinfo
geometry`. Record that line. When DAC, groups, or SELinux deny access, the
binary falls back to deriving the order from the periodicity of captured timer
addresses (`derive_order_from_ptrs`), which needs neither slabinfo nor root.

Do **not** rely on the page-event vote alone. It pairs a slab with the
`mm_page_alloc` that created it, so it only sees slabs allocated inside the
capture window — and a warm cache (any second run in one boot) serves
`timer_create()` from free objects in existing slabs and allocates almost
nothing. The observed signature is a working cold run voting
`count=483 order=1` and every later run voting `count=31 order=0`, which
halves `SLAB_SIZE` and breaks the attack in two independent ways:

- the fake cred is built at `V & 0x0fff`, half a slab away from the node the
  kernel will actually erase (the object sits at `0x19c8`, not `0x09c8`), so
  the stale node is never overwritten and the child keeps its old uid even
  though the plant reports `hit=1`/`reaped`;
- the spray sends 4K skbuffs, so a 4K page alloc at the head of the freed 8K
  block only ever covers the first half — the half without the node.

`calibrate_base()` therefore drains the free objects reported by slabinfo
before measuring, restoring the cold profile. `run_plant()` additionally
rejects a victim whose in-slab offset is not a multiple of `timer_alloc` and
retries, so a wrong geometry fails loudly instead of writing elsewhere.

16K-page builds keep the same family values but override `page_size = 16384`,
`page_shift = 14`, `slab_order = 0`, `slab_size = 16384`, and a different
`linear_min`/`linear_max` — and they are a **separate profile**, selected by
page size because the release string is identical (see F6).

---

## 3. Step 0 — Identify and qualify (F1)

```sh
adb shell uname -r
adb shell getprop ro.build.fingerprint ro.product.device ro.build.id
adb shell getconf PAGESIZE
```

- Near-miss banners are **different ports**: `-11-` ≠ `-8-`, a different `ab`
  suffix is a different kernel, and `-4k` suffix presence varies by vendor.
  Sibling devices shipping the *same* release string may still carry different
  text layouts (the two 6.1 Redmis differ only in `timer_site`; the S25 family
  vs S26 FE differ everywhere). Verify per build, never per family. This
  includes two devices on one GKI tag with different vendor defconfigs: the
  `do_timer_create` call site moves, so the 6.6.118 family alone has four
  different `timer_site` values. `uname -r` matching is necessary, not
  sufficient — a run that dies at `base calibration failed` with
  `site=0 count=0` prints the captured call sites, and those decide.
- 16K devices print a page size of 16384 — that is a second profile.

**Vulnerability check — do not skip this.** Disassemble `begin_new_exec` in
the new vmlinux and check the call order. The fix moves
`posix_cpu_timers_exit()` past `de_thread()`; the vulnerable order still has
`exit_itimers()` after it:

```
vulnerable:   … exec_mmap → [exec_task_namespaces] → posix_cpu_timers_exit → exit_itimers
fixed:        posix_cpu_timers_exit comes after de_thread/exit_itimers
```

The order *is* the exploit: the stale node is queued, the mm/nsproxy are
replaced, `posix_cpu_timers_exit` is the last user of the pids, and the
reclaimed slab is still reachable. If the order is fixed, stop — no port.

Gate: banner + fingerprint + page size + the disassembled call sequence in
`PORT_LOG.md`.

---

## 4. Step 1 — Factory artifacts (F2)

From the **factory image of that exact build** — never the running device,
never a custom ROM, never a "same SoC" kernel. OTA zips are ~10 GB; read them
with HTTP range requests and never download whole. The tooling lives outside
the repo in the separate, gitignored port tree (`timerroot-port/`; on this
machine `/mnt/integral/timerroot-port/`, tooling in `work/xi/` and the QEMU
harness in `work/qemu/` — PORT_LOG.md uses the absolute paths). Keep extracted
`boot.img`/`vmlinux` there too.

| tool | purpose |
|---|---|
| `get_hdr.py` / `fetch_part.py` | `payload.bin` header + one partition via range workers |
| `fetchvb.sh`, `fetchdtbo_all.sh` | same for `vendor_boot` / `dtbo` (needed in step 2) |
| `timerroot-port/xiaomi/fetch_xi.py` | Xiaomi/Redmi/POCO: all three partitions in one pass from a HyperOS **full** OTA, plus a per-device `manifest.json` with hashes |
| `timerroot-port/xiaomi/{summarize,verify_payloads}.py` | index the fetched banners and prove which devices share a byte-identical `Image` |

Xiaomi ships one GKI payload across a generation, so a new device often lands
on a profile that already exists: of the 32 Xiaomi/Redmi/POCO images in
`timerroot-port/xiaomi/`, 14 are byte-identical to an already-ported payload
(the Xiaomi 14 `houji` kernel equals the Redmi Note 15 Pro+ `flourite` one).
Hash the *decompressed* `Image` before treating a release-string match as the
same port — `verify_payloads.py` does exactly that. Only the **full** OTA
(`*-ota_full-*.zip`) carries a `payload.bin`; recovery incrementals do not.
| `unpack_bootimg`, `extract-vmlinux` / LZ4 unwrap | `boot.img` → kernel → raw `Image`/vmlinux |
| `vmlinux-to-elf` | kallsyms ELF when `nm` on the bare vmlinux comes up short |
| `derive.py`, `sitecheck.py`, `blobsim2.py`, `evidence.py` | step 2 |
| `validate_conf.py` | step 4 |

Keep `init_boot.img` too on Android 13+; init moved there. For an access audit,
decode the policy in `vendor_boot`, inspect `adbd`'s compiled groups, disassemble
the factory kernel's `slab_proc_init`, and read the **matching** system
`init.rc`. Never infer the final DAC mode from `ueventd.rc` alone. If any
artifact is missing, record the access chain as inconclusive rather than
assuming the common `0440 root:log` configuration.

```sh
nm vmlinux | wc -l                       # symbols must exist; else vmlinux-to-elf
objcopy --dump-section .BTF=btf.bin vmlinux
sha256sum boot.img vmlinux btf.bin
```

Also grab, from the running device (these are runtime facts, allowed):

```sh
adb shell cat /proc/slabinfo | grep -E 'posix_timers_cache|cred_jar|task_struct'
```

`posix_timers_cache` gives `object_size` (= `timer_alloc`), `cred_jar` gives
`cred_req`/`cred_alloc`, `task_struct` gives `task_alloc_bytes`. If the device
isn't bootable yet, QEMU reproduces these lines from the factory Image (F14).

Gate: vmlinux with symbols, `btf.bin`, slabinfo lines, hashes recorded.

---

## 5. Step 2 — Derive the per-build constants (F3–F5)

Five numbers per build; use `derive.py` / `sitecheck.py` and verify by
disassembly, **by surrounding instruction sequence, never by symbol name
alone**.

### `timer_site` (F3)

The `posix_timers_cache` object is allocated in `do_timer_create()` (5.15–6.6)
or `alloc_posix_timer()` (6.12+). Find the `bl kmem_cache_alloc[_noprof]`
whose `x0` is fed by `adrp`+`ldr` from the global that the init function
(`init_posix_timers`, sometimes emitted as `__initstub__kmod_posix_timers__…`)
stores the `kmem_cache_create` return value into. `sitecheck.py` does that
dataflow and separates the real site from the `current->alloc_tag` profiling
path (6.12/6.18 have a second `bl` bracketed by alloc-tag swaps — not it).

`timer_site` is the **return address** (`bl` + 4): the caller reloads `x0`
there, and that reload is what the planted fake node sees.

Only the low 21 bits are used to scan the trace, and that is sound because the
arm64 KASLR slide is `MIN_KIMG_ALIGN` (2 MB) aligned: `static_site & 0x1fffff`
is the same at runtime, and the full captured address gives the slide
(`site0 - timer_site`). So a low21 that never matches is **not** a KASLR
problem — it means the device is running a different *image* than the one the
profile was derived from, even when `uname -r` is identical. Vendor builds
share a GKI release string but not the vendor defconfig, and the
`do_timer_create` call site moves with it (the 6.6.118 family already has
`0x195d48`, `0x195d50`, `0x195d94` and `0x1a4dfc`). The binary now prints the
call sites it actually captured (`observed call_site=… low21=… count=…`) when
the profile's site matches nothing; port that device, do not relax the filter.

### `copy_process_low21` (F3)

The `task_struct` allocation is
`kmem_cache_alloc[_node][_noprof](task_struct_cachep, …)`, reached from
`copy_process()` directly (inlined `dup_task_struct`, 6.6/6.12) or through a
standalone `dup_task_struct` (5.15/6.1/6.18 — read the return address from the
`dup_task_struct` body, that is where the call lives). Take the low 21 bits
of the return address (`bl` + 4) — the exploit scans trace records for that
21-bit match.

### Six symbols (F5)

`selinux_state`, `panic_on_warn`, `root_user`, `init_user_ns`,
`init_ucounts`, `init_groups` — from `nm vmlinux`, re-verified by hand once.
For `selinux_state` you need the **struct base**, such that the `-7` store
lands on `enforcing`: BTF must put `enforcing` at bit 0 of the struct, and
`selinux_state - 8` should be `avc_latest_notif_update.notif_lock` (if the
nearest preceding symbol is far away, the store lands in padding — record
that, as zephyr does).

### `selinux_blob_off` (F5)

Not a lookup: it is the offset of `task_security_struct` inside the aggregate
LSM cred blob, assigned by `lsm_set_blob_sizes()` in **runtime
`CONFIG_LSM=` registration order**, not link order:

```
for each lsm in registration order:
    ALIGN(total, 8) -> blob offset
    total += lsm_blob_sizes.lbs_cred
```

`blobsim2.py` reconstructs the order from `__start_lsm_info`/`__end_lsm_info`
plus the built-in `CONFIG_LSM` string and each LSM's `lbs_cred`. Landlock's
cred blob (8 bytes on 6.12, 11 → 16 on 6.18) is the usual surprise; deriving
from the `landlock,lockdown,…` string alone corrupts the child's SID.

### `task_alloc_bytes` (F4)

Start from BTF `sizeof(task_struct)`, then check
`task_struct_vendor_size_setup()` (6.6+): it parses
`android_arch_task_struct_size` from the command line, capped at `0x400`
(6.12/6.6) or `0x500` (6.18). Whether the parameter is **set** is a
firmware fact — grep the vendor `dtb`/bootconfig in `vendor_boot.img`/
`dtbo.img`. Known outcomes: 6.6/6.1 images don't set it; 6.12 sets 512–1024;
Pixel 11 sets 784; 6.18 sets 1024.

### Sanity cross-checks

- `timer_site_low21 == static_timer_site & 0x1fffff` and
  `copy_process_low21 == <ret> & 0x1fffff` must agree.
- `timer_alloc` is the `mov w1, #…` size at the cache creation; BTF
  `sizeof(k_itimer)` must match it.
- `cred_req` is the `mov w1, #…` at `cred_init`; `cred_alloc = ALIGN(,64)`.
- `alloc_req_off` = `bytes_req − call_site` in the trace event; on 5.15 the
  event is `trace_event_raw_kmem_alloc`, not `…_kmem_cache_alloc`.

Gate: address + disassembly snippet + 6/6 symbols + blob order logged; run
`evidence.py` to regenerate the tables straight from vmlinux + BTF.

---

## 6. Step 3 — Write the conf (F6)

Create `conf/<release>.conf` (copy the closest existing profile and diff).
Samsung goes in `conf/samsung/` (§9). Format is HOCON (`key = value`,
`#`/`//` comments); the loader `conf_defaults()` pre-fills every field with
the 6.6/6.12-layout defaults, so **you only write what differs**. A conf that
omits a key is not a draft — it inherits the default. Required to set on
every profile:

- identity: `release` (exact banner, `-4k` suffix insensitive) or
  `release_prefix` (prefix match, cut at `-` boundaries — use the full banner
  when sibling builds share a release string, §9), `ksu_kmi`,
  `page_size`/`page_shift` (non-4K),
- slab: `slab_order`, `slab_size` (must satisfy
  `slab_size == page_size << slab_order`), `linear_min`, `linear_max`,
- sites: `timer_site`, `timer_alloc`, `copy_process_low21`,
- cred/task: `cred_req`/`cred_alloc`/`cred_size`, `cred_uid_off`,
  `cred_euid_off`, `cred_cap_off`, `cred_security_off` (+ the other
  `cred_*_off` on a 4-byte-`usage` layout), `task_cred_off`,
  `task_alloc_bytes`,
- symbols: `selinux_state`, `panic_on_warn`, `root_user`, `init_user_ns`,
  `init_ucounts`, `init_groups`,
- selinux: `selinux_blob_off`, `selinux_sid_kernel`,
- conditional: `pcp_free = 1`, `timer_node_off` (≠ `0x78`), `timer_alloc`
  (≠ `0x108`), `alloc_req_off` (≠ `0x10`), `fullcap` (≠ default),
  `fake_cred_off` (never unless you re-derived §10 and it is not `0x18`).

`pcp_free`: set `1` when the kernel frees the order-1 slab through the PCP
lists (no `mm_page_free` events); the reclaim then gates on `/proc/slabinfo`
instead. Known `1` on 5.15 and 6.1; for 6.6+ let the QEMU run tell you — if
`leak` never fires while slabinfo free counts rise, it's `pcp_free`.

**Invariants** (asserted by `--selfcheck`; F6 gate = 0 failures):

- `slab_size == page_size << slab_order`.
- `timer_site_low21` and `copy_process_low21` agree with the static forms.
- `cred_uid_off == usage width` (4 or 8); `fake_cred_off == 0x18`.
- `fake_caps_off >= 0x28` (the `c[]` overlay clears `c[5]` only when
  `FAKE_CAPS_OFF/8 > 5`, else it collides with securebits).
- `fake_cred_off + cred_size <= slab_size - timer_node_off`, and the
  worst-case object offset `(V & SLAB_OFF_MASK) + node + cred_end <=
  slab_size`. Spilling is allowed — `run_plant()` retries — but it must be
  the designed retry, not an accident; record it either way.
- `cred_req < cred_alloc`; `alloc_req_off` is `0x10` (pre-6.18) or `0x18`
  (`name` field on 6.18).
- `linear_min < linear_max` bounds the **direct map**: the runtime
  `calibrate_base()` vote must land in `[linear_min, linear_max]`, and the
  kernel image is mapped *above* it — so `--selfcheck` asserts
  `linear_min < linear_max <= timer_site`. `timer_site` inside the window is
  a bad profile, not a good vote; the slide (`site0 - timer_site`) converts
  the direct-map vote back to the image before any write.
- Samsung: `defex_creds_hash` present (§9).

Then run `validate_conf.py` — it re-derives every constant from the factory
vmlinux + BTF and diffs against the conf. **Gate: 0 errors, `--selfcheck`
0 failures, `target` prints the profile, and a deliberately wrong banner is
refused before any kernel access.**

---

## 7. Step 4 — QEMU (F7–F11, F14)

Boot the factory Image (never a rebuilt one) in `qemu-system-aarch64` at the
same page size and run the gates in order. Harness: `work/qemu/` in the port
tree — `initramfs/` (busybox + shipped aarch64 `timer` + every `conf/`),
`mkinitramfs.sh`, `mass.py` (boots each conf, checks F7–F11 and writes
`logs/mass-*.json`), `runhigh` (raises `RLIMIT_NOFILE` to 65536 — the spray
opens 2048 socketpairs = 4096 fds — then **drops to uid/gid 2000** before
exec'ing `timer`). The uid drop is mandatory: a root run starts with an
already-uid-0 child, so F11 would pass without the exploit firing. `init` also
makes tracefs writable by shell; it is not a substitute for the uid drop.

Boot parameters are derived, not guessed:

- `android_arch_task_struct_size=<vendor ext>` — without it `task_struct`
  stays stock and the conf's `task_alloc_bytes` cannot match slabinfo.
- `slub_min_order=<slab_order>` — SLUB picks the order from online CPU count;
  a 4-vCPU VM would get order 0. This pins the phone's geometry.
- 4K/16K Pixel pairs share a release string; `mass.py` selects by page size.
- initramfs `init` sets `net.core.{wmem,rmem}_max = 1048576` — `SO_SNDBUF`
  16 MB is otherwise clamped to ~416 KB per socket and starves plant 2.
  16 MB sysctls fail (RAM exhaustion), 4 MB regresses.

Gates (each prints its evidence in the log):

- **F7** `timer target` → `target=lynx`, correct `kernel=`/`profile=`/`timer_site=`, exit 0.
- **F8** `timer ids` → page event ids, no `dmesg` noise; safe without reboot.
- **F9** `timer probe` → `[probe] pair pfn` agrees with `base`, `mod264`
  dominance consistent with `timer_alloc`, no `victim index missing`; safe to
  re-run (no victim armed).
- **F10** `timer leak` → `[cred] … hello=52445931`, `[+] child=… cred=…` on
  ≥8/10.
- **F11** `timer` (verify) and `timer shell` → `child report uid=0`,
  `setuid(0)=0`, `resuid=0/0/2000`, `ROOT_SHELL_OK`. A shell-uid run keeps the
  **saved** uid at 2000 — an unprivileged `setuid(0)` cannot clear it — so
  `0/0/2000` is a pass and `0/0/0` is the signature of a root harness. The
  gate checks real uid 0, post-setuid effective uid 0 and the root shell;
  old transcripts showing `0/0/0` are not evidence for the current binary.

Known harness artefacts (not profile faults): run `mass.py` at `-j 2` on a
12-core host — oversubscription makes bursts miss their 15 s window
(`burst hit=0 after 15004ms`) and reproduces the pre-existing race panic
(`posix_cpu_timers_exit` → `rb_next`) at ~10%; 0/40 when not oversubscribed.
F11 is the only gate that arms the spray — retry it once and record both
attempts. The plant now verifies its own result: after each `run_plant()` the
parent reads the child's real uid from `/proc/<pid>/status` and retries the
whole plant with a fresh pool (up to six attempts, `plant attempt n/6`) until
it is actually 0. `r.ok` alone only proves the slab was reclaimed and the
zombie reaped — the free can land after the phase-1 burst, i.e. after the
stale `rb_erase` has already passed, and the page gets recycled without the
payload write landing. `plant n left child uid=…; retrying` is expected; six
failures are not.

`calibrate_base()` runs on every mode before the gates: it votes the linear
base for slab orders 0–3 and can override the conf geometry (see §2). Record
the `[base] … order=… size=…` line; a mismatch against the conf is a finding
even when all gates pass. F14 is the mass run: `mass.py` boots every profile
with a workspace Image, at its own page size, and drives all gates with the
shipped binary; reference results (including the two provenance/environment
exceptions) live in `PORT_LOG.md` §F14 and the JSON logs. Profiles with no
factory artifact cannot be covered and stay `untested`.

Samsung kernels that call the Knox hypervisor (`smc #0`/`hvc #0` in
`uh_call`, RKP page-table/RO-cred paths, DEFEX signature gate) do not boot
unmodified. Build a **throwaway patched copy** with `mkshim.py` (see §9),
boot it via `mass.py --image`, and keep the factory artifacts unmodified.
**No constant is ever derived from the shim.**

The 16K layout needs its own QEMU pass. Gate: all green in QEMU.

---

## 8. Step 5 — Device (F10–F16)

Runtime contract:

- Runs in **`shell`** (uid 2000, `u:r:shell:s0`) because it needs
  `/sys/kernel/tracing`. Test over `adb shell` only — never `su`, never a
  terminal app.
- 2–3 min uptime before the first run; a run at 20 s is not a data point.
- `dmesg -C` before every run; pull `/data/local/tmp/timer_last.log` after
  any panic (every line is `fsync`ed there for that reason).
- **One variable per run.** Never retry on a dirty device — reboot between
  attempts.

Build: `aarch64-linux-gnu-gcc -static -O2 -pthread p7a/timer_p7a.c -o timer`
(host smoke build), push, `chmod 755`. For a byte-identical match with the
GitHub CI asset use the NDK command in `AGENTS.md` (NDK 29,
`aarch64-linux-android21-clang`, `-O2 -ffunction-sections -fdata-sections
-Wl,--gc-sections -g -static -pthread` plus the two required
`-fdebug-*-dir`/`-fdebug-prefix-map` flags). The shipped binary must contain
the literal markers `TIMER_PROTOCOL=3` (and `TIMER_SAMSUNG=1` for a
Samsung-capable build): the app scans for them before picking a profile and
starts the binary as `timer --conf <path> --protocol 3 [--samsung] <mode>`.
Without `--conf`, or with a lower protocol, it refuses with
`OLD_APP_DETECTED` / `TIMER_PROTOCOL=3` instead of planting. A stale binary
with a current marker can survive an APK update in the shell service; the
beta channel force-refreshes the rolling asset for that reason — when a fix
"does not appear" on device, compare the staged binary's SHA-256 with the
built asset before debugging the profile. The app also writes a shell-uid
device spec to `/data/local/tmp/timer-debug.log` before each run (see
`DeviceProbe.java`); attach it with `timer_last.log` for a failed port.

- **F10/F11** re-run `leak`/verify on the device, then **F11** `timer shell`
  → root shell. From `adb shell` (uid 2000) the verify child reports
  `resuid=0/0/2000`, not `0/0/0`; the `shell` mode is the real root shell.
- **F12** `timer permissive` → `getenforce` → `Permissive`,
  `[+] permissive done`.
- **F13** `timer fake` → `woke uid=0`, worker `setresgid(0)=0`,
  `KSU_LOADED`, `su -c id` → `u:r:ksu:s0`, `getenforce` stays `Permissive`.
- **F15** hardware: cold boot, settle, 10/10; then measure over **200 runs**
  and record the rate.
- **F16** app: add the device to the supported table as `verified in QEMU`
  (or `untested`) until F15 passes, then `tested`. `target=` stays `lynx`.

F12–F13 are out of reach in the QEMU initramfs (no SELinux policy, no
KernelSU/ksud) — they need a device. `KSU_MISSING` there is the designed
stop, not a failure.

---

## 9. Samsung mode

Samsung kernels (DEFEX, KDP, Knox RKP) need extra fields and a different
endgame; profiles live in `conf/samsung/samsung-<device>-<release>.conf`.

- **`release_prefix` = the full banner.** Sibling builds share the numeric
  release but differ in the `ab<model>` firmware suffix and every text
  address (`p87b1ce1` S25 vs `abogkiS741BXXS3AZK1` S26 FE).
  `release_prefix_matches()` cuts at `-` boundaries, so a partial prefix can
  cross-match — pin the whole thing.
- **`defex_creds_hash`** (required; the loader refuses a Samsung conf without
  it): Samsung keeps per-pid creds in a fast table indexed for
  `pid <= 0x8000`. Derive it from kallsyms: `creds_hash + 0x40000` where
  `creds_fast_hash` has no symbol of its own, or its own symbol where it
  does. `get_task_creds` disassembly shows the indexing shape.
- **`samsung_package`** pins the manager (`me.weishu.kernelsu`,
  `versionName samsung-v*`); the loader refuses Samsung mode with any other
  package.
- **Endgame**: `--samsung fake` runs the five-plant chain — `defex_hash`
  (clear `creds_fast_hash[pid]`) → `fake_cred` → `selinux_state` → uid/euid
  repair → init-domain switch. Per-plant bursts miss roughly half the time, so
  a miss must be **recoverable, not fatal** (`res->retry = 1`; hold and retry
  with a fresh pool). Spray writes use `send(..., MSG_DONTWAIT)`: the peer is
  never drained, so a blocking `write()` parks the spray thread and
  `pthread_join()` hangs once the queue is full — the chain plants twice on
  the same pool, which is why single-plant paths never exposed this.
  `pool_reset()` closes both ends of the previous attempt's socketpairs and
  builds a fresh pool; the one holding the landed fake cred (`pool_a`) is
  pinned, so all later stages run on `pool_b`. Releasing a zero-stage pool is
  safe; releasing the fake-cred pool would free `task->cred`.
- **QEMU shims**: KDP/RKP/DEFEX call the phone's hypervisor. The shim (one
  file, `mkshim.py`) patches `smc #0` → `mov x0,xzr` (uh_call success), the
  two `blr x8` early-allocator sites → `bl early_pgtable_alloc`,
  `kdp_enable = 0`, and skips the DEFEX signed-rules gate. The failure
  ladder is documented in `PORT_LOG.md` — patch in that order. `rkp_init`
  still runs and `[DEFEX] Normal mode` still logs; some Samsung Images boot
  unmodified, so try that first.

---

## 10. Endgame layout rules

The fake cred must satisfy all of these, or the erase damages it:

- `node[0x00]` = fake cred address → published as `task->cred`.
- `node[0x08]` = 0 (`rb_right`) → forces the left-only path.
- `node[0x10]` = `dest` → must fall **outside** the cred (`rb_erase` writes
  `dest` there).
- `node[0x20]` is zeroed by `posix_cpu_timers_exit` → must land on a uid/gid
  word that should be 0.
- `cred.euid` must **not** be at the offset the erase writes.

That is why `fake_cred_off = 0x18`: on 6.1 `cred.euid` sits at `+0x10` and
would be clobbered with `high32(dest) = 0xffffff88`. On a new cred layout,
re-check all five rules; the safe answer is almost always
`node[0x10] + 8` with `uid` repaired afterwards.

`usage` is set to 1 so `rb_next` stops at the fake cred's NULL parent. Do not
"fix" it to the low 32 bits of the address.

**Never call `setuid()` in the `fake` child.** `task->cred` is the fake while
`task->real_cred` is original; `commit_creds()` `BUG_ON`s on the mismatch.
`fork()` first — `copy_creds()` gives the worker `cred == real_cred` and a
real SELinux blob.

The plant is not proven by a reaped zombie (`r.ok`): if the free lands after
the phase-1 burst, the slab can be recycled again *after* the stale
`rb_erase` passed, so nothing wrote the payload. The parent reads the child's
real uid from `/proc/<pid>/status` after each plant and retries the whole
plant with a fresh pool, up to six attempts, until it is actually 0. A
`plant n left child uid=…; retrying` line is a recoverable miss; six failures
point at spray/timing, not at the cred offsets.

Still hardcoded in the source (re-check per family, do not blindly trust):
`NTIMERS`/`VICTIM_IDX` (4096/2048), `PREFILL_TIMERS`, the `-7` on
`selinux_state` (`enforcing` has been a bool at bit 0 on every build so far;
re-derive as `8 - sizeof(enforcing)` from BTF), and the 32-byte SELinux blob
fill. Everything else that used to be a literal is now a conf key.

---

## 11. Diagnostics

Grep the log; each line maps to one cause.

| Log | Cause | Fix |
|---|---|---|
| `victim not captured` | `timer_alloc` / `timer_site` wrong | re-derive F3 |
| `no call_site has low21 … (conf timer_site=…)` followed by `observed call_site=… low21=…` | the profile's `timer_site` belongs to another image; same `uname -r` is not enough (the low21 is KASLR-invariant, so this is a text-layout difference, not a bad slide) | port that device's boot.img (F3) — the observed `low21` narrows it to a known build; never relax the filter, the same value anchors the slide |
| `N kmem_cache_alloc records …, none with bytes_req == bytes_alloc == …` | the trace works but `posix_timers_cache` has another object size | re-derive `timer_alloc` from `sizeof(struct k_itimer)`; compare `obj=` in the slabinfo line |
| `the trace holds no kmem_cache_alloc record for pid …` | the `kmem:kmem_cache_alloc` event is not recording (tracefs instance without the event, or the enable write was rejected) | the binary now retries through `events/kmem/<event>/enable`; if it persists, check the tracefs instance |
| `[!] kmem:… is not enabled (…)` | both the `rss_stat` trigger and the event's own `enable` file were rejected | check that `TR` is the instance the exploit reads and that the event exists |
| `[!] cannot pin to cpu N (…)` | the shell cpuset does not contain the trigger CPU; tracing it would read an empty buffer and look like a bad profile | the binary traces an allowed CPU instead; record which one |
| `victim index missing` | `NTIMERS` too low, slab order changed | re-derive geometry |
| `bad base` | `linear_min/max` wrong for the VA layout | fix from the new layout |
| `pair missing` | slab↔page ordering broken | check `slab_order`; try `pcp_free` |
| `fake cred spills` | node offset or cred size wrong | re-derive `timer_node_off` / `cred_size` |
| `burst missed` | spray too slow, device loaded | more `SPRAY_POST`, settle longer |
| `no zombie` | killer race lost | check the `CLOCK_THREAD_CPUTIME_ID` path |
| `cred writes did not land` | wrong `cred_uid_off` | re-derive |
| `setuid(0) failed` | caps missing → `fake_caps_off` wrong | re-derive |
| `KSU_STALE` | module uapi ≠ manager uapi | reboot, matching manager |
| `KSU_MISSING` | no manager / `ksu_kmi` wrong | fix `ksu_kmi` |
| `conf release prefix mismatch` | banner ≠ profile | correct port or new conf — never bypass |
| `plant n left child uid=…; retrying` | reaped but the stale erase missed the payload (free landed late) | expected; fresh-pool retry handles it — check spray/timing if all 6 fail |
| `[!] slab geometry mismatch: conf order=… slabinfo order=…` | SLUB chose a different order than the conf | calibration used the slabinfo geometry; record the finding and, if it is stable, write the real `slab_order`/`slab_size` into the conf |
| `victim offset … is not a multiple of timer_alloc` | `slab_size` is not the kernel's real slab size, so the object sits in the other half of the block | trust `[+] slab geometry confirmed by slabinfo`; if the conf and slabinfo disagree, fix the conf |
| `slabinfo unreadable; address periodicity says order=…` | shell lacks DAC permission/supplementary `log`, or SELinux denies `proc_slabinfo` (the kernel normally creates the file `0400`) | the order was derived from timer addresses; audit the complete access chain and confirm the derived order matches the conf |
| `OLD_APP_DETECTED` / `TIMER_PROTOCOL=3` | app/binary protocol mismatch, or binary started without `--conf` | update app / refresh binary; pass `--conf … --protocol 3` |
| `resuid=0/0/0` in QEMU | harness ran as root, so F11 proved nothing | drop to uid 2000 with `runhigh` and re-run |
| `no KASLR slide` on `fake` | slide missing before the first endgame write | `calibrate_base()` must store `g_slide` from `site0`; re-run probe |
| panic on first touch | any wrong constant | the log names the stage |

---

## 12. Hard rules

1. **Never run a non-matching banner.** `kernel=` must match the profile; the
   conf gate is the safety net, not a formality.
2. **Never kill a parked process.** The fake cred page is pinned in its
   socket buffers; reaping it panics. Reboot is the only clean stop.
3. **Never derive from the running device** — factory `boot.img` only, and
   never from a QEMU shim.
4. **Never copy fake-cred offsets between 4-byte and 8-byte `usage`
   families**; the whole fake cred shifts by the usage width.
5. **Never arm the victim timer in a probe.**
6. **Never edit a constant without a source comment.**
7. **QEMU before hardware. Always.** 16K gets its own pass.
8. **One gate per commit.**
9. **Don't break `target=lynx`** or the `argv[0]==""` re-exec branch.
10. **Report the measured rate**, not the hoped-for one.
11. **Never qualify F11 from a root QEMU run** — drop to uid 2000 first; a
    child that starts as root proves nothing.
12. **Never trust a stale binary** — check `TIMER_PROTOCOL=3` and the built
    asset's hash before blaming a profile for a missing fix.

---

## 13. Definition of done

- [ ] F1–F16 logged in `PORT_LOG.md` (F12+ may be pending with a device plan).
- [ ] Conf registered in `conf/`; `validate_conf.py` 0 errors;
      `--selfcheck` 0 failures; wrong banner refused.
- [ ] QEMU F7–F11 green against the factory Image (both page sizes if both
      exist), run as uid 2000, with `resuid=0/0/2000` + `ROOT_SHELL_OK`.
- [ ] Binary carries `TIMER_PROTOCOL=3` and is started with `--conf … --protocol 3`.
- [ ] Device: `woke uid=0` + `getenforce=Permissive` + `u:r:ksu:s0`, 10/10
      cold boots, measured rate over 200 runs recorded.
- [ ] Stable 10 min, `dmesg` clean, no reboot.
- [ ] App table updated: `verified in QEMU` → `tested` only after F15.
