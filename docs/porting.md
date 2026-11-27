# Porting TimerRoot to a new kernel

> **Research use only.** Use this only on hardware you own or are explicitly
> allowed to modify.

This is the short, human-readable version of the porting procedure. It explains
*what* you have to find and *why*, without the disassembly recipes, scripts and
failure ladders. For the full agent-grade procedure use
[SKILL.md](../SKILL.md); for the evidence of every port already in the tree see
[PORT_LOG.md](../PORT_LOG.md). For how a finished profile gets into the app see
[Building](building.md#adding-a-kernel-profile).

---

## The idea in one minute

The exploit binary is the same for every device. Everything that depends on a
particular kernel build lives in one small text file under `conf/`, called a
**profile**:

```
conf/6.6.118-android15-8-g0908354dac1b-ab16143355-4k.conf
```

The app picks the profile at runtime by comparing `uname -r` (and the page size
when the release string is shared). If nothing matches, it refuses to run — it
never guesses. That refusal is a safety feature: a profile built for a
different kernel corrupts memory instead of failing cleanly.

**Porting = producing one new profile file.** No C or Java changes are needed,
and you never "adapt" the exploit source for a new device.

To write that file you only have to derive a handful of things from the
**factory kernel of that exact build**:

1. two code addresses (where two specific memory allocations happen),
2. six symbol addresses (from the kernel's symbol table),
3. a set of structure sizes and field offsets (from BTF),
4. one SELinux offset that is *calculated*, not looked up.

Most of the rest are predictable from the kernel family (5.15, 6.1, 6.6, 6.12,
6.18) and are just copied from the closest existing profile — but still checked.

### Words you will meet

| Term | Plain meaning |
|---|---|
| banner / release | The `uname -r` string, e.g. `6.6.118-android15-8-g...-ab...-4k`. It identifies one kernel build. |
| vmlinux | The uncompressed kernel with its symbol table. This is where addresses come from. |
| kallsyms | The kernel's own symbol list; `nm vmlinux` is how you read it. |
| BTF | Debug type information embedded in the kernel. It tells you `sizeof(struct cred)` and where each field sits. |
| slab / cache | The kernel's fixed-size object allocator. The exploit reuses one freed slab page, so object sizes and page order matter. |
| profile / conf | The HOCON file in `conf/` holding all the numbers for one build. |
| gate | One check in the porting procedure (F1–F16). A gate is only "pass" when it was actually run and logged. |

---

## What you need before you start

- **The factory image of the exact build** (`boot.img`, often `vendor_boot.img`
  and `dtbo.img`). Never derive constants from the running device, a custom
  ROM, a "same SoC" phone, or a QEMU-patched kernel.
- **A `vmlinux` with symbols and a BTF section.** Android boot images carry a
  compressed `Image`; unpack it, decompress it, and use `vmlinux-to-elf` if
  `nm` on the bare file comes up empty.
- **Basic tools:** `unpack_bootimg`, `extract-vmlinux` (or an LZ4 unwrap),
  `vmlinux-to-elf`, `nm`, `llvm-objdump`, `bpftool`, `sha256sum`.
- **A way to test:** `qemu-system-aarch64` with the factory `Image`, plus a real
  device for the final steps. QEMU uses a small initramfs with the exploit
  binary and all profiles. The tooling is kept in the separate port tree, not
  in this repository.
- **A place to record evidence:** add a section to
  [PORT_LOG.md](../PORT_LOG.md) for every gate you pass.

OTA zips are around 10 GB. Read them with HTTP range requests instead of
downloading them whole, and keep the extracted images outside the repository.

---

## The six steps at a glance

| Step | What you do | Gate |
|---|---|---|
| 0 | Identify the build, page size and vulnerability | F1 |
| 1 | Extract the factory `vmlinux`, BTF and slabinfo | F2 |
| 2 | Derive the addresses and sizes | F3–F5 |
| 3 | Write `conf/<release>.conf` | F6 |
| 4 | Validate it without touching a kernel | F6 |
| 5 | Prove it in QEMU against the factory Image | F7–F11 |
| 6 | Prove it on the device | F12–F16 |

Commit one gate at a time (`port: F1 <banner>`, `port: F2 <banner>`, …) and log
every gate in `PORT_LOG.md`. That log is the record that the procedure was
followed.

---

## Step 0 — Identify the build and confirm the bug

Read the identity off the device:

```sh
adb shell uname -r
adb shell getprop ro.build.fingerprint ro.product.device ro.build.id
adb shell getconf PAGESIZE
```

Two traps:

- **Near-miss banners are different ports.** A different `ab` suffix, `-11-`
  versus `-8-`, or a different vendor build means different addresses even on
  the same family and the same release number. Sibling devices of the same
  model can also differ in a single address. Always derive per build.
- **A 16K page size is a second profile.** Some builds ship both a 4K and a
  16K kernel under the same release string; those are selected by page size.

**Check that the bug is still there.** Disassemble `begin_new_exec()` in the
new `vmlinux` and look at the call order:

```
vulnerable:  ... -> posix_cpu_timers_exit() -> exit_itimers()
fixed:       posix_cpu_timers_exit() moved after de_thread()/exit_itimers()
```

That order *is* the exploit: the stale timer node is left in a freed slab page,
and the freed page is still reachable when the exploit reclaims it. If the
order is fixed, **stop — there is no port**.

Log the banner, fingerprint, page size and the call sequence.

---

## Step 1 — Collect the factory artifacts

From the factory image of that exact build:

1. Get `payload.bin` / `boot.img` (and `init_boot.img` on Android 13+,
   `vendor_boot.img`, `dtbo.img` when you need the vendor command line). To audit
   unprivileged slabinfo access, also keep the matching system image: Pixel
   factory boot ramdisks contain recovery-style init files, not the platform
   `system/etc/init/hw/init.rc` that changes slabinfo's DAC mode.
2. Unpack `boot.img` and extract the raw kernel `Image` and the `vmlinux` with
   symbols.
3. Extract the `.BTF` section:

   ```sh
   nm vmlinux | wc -l                         # must be non-zero; else vmlinux-to-elf
   objcopy --dump-section .BTF=btf.bin vmlinux
   sha256sum boot.img vmlinux btf.bin
   ```

   `objcopy --dump-section` only works when the ELF actually has section
   headers. A `vmlinux-to-elf` reconstruction has just `.kernel`/`.bss`/
   `.symtab`, so it fails with `Unable to recognise the architecture of the
   input file`. The BTF section is still in the raw `Image`: find the header
   magic `9f eb 01 00 18 00 00 00` at a 4-byte-aligned offset, read
   `hdr_len`/`type_len`/`str_len` from that `<HBBIIIII` struct, and write out
   the next `hdr_len + type_len + str_len` bytes as `btf.bin`.

   The `Image` also embeds its own kernel config: search for `IKCFG_ST`, take
   the gzip stream up to `IKCFG_ED`, and decompress. That file answers the
   questions kallsyms cannot: `CONFIG_POSIX_CPU_TIMERS_TASK_WORK`,
   `CONFIG_ARM64_4K_PAGES` vs 16K, the real `CONFIG_LSM`, and which
   `CONFIG_SECURITY_*` options are actually enabled.

   Read `CONFIG_POSIX_CPU_TIMERS_TASK_WORK` **now**, before deriving
   anything. It decides whether F11 can ever land. `POSIX_CPU_TIMERS_TASK_WORK`
   is `default y if POSIX_TIMERS && HAVE_POSIX_CPU_TIMERS_TASK_WORK`, and
   arm64 selects `HAVE_POSIX_CPU_TIMERS_TASK_WORK` only from 6.1 onward
   (`arch/arm64/Kconfig`: no hit in 5.10.236/5.15.194, one in
   6.1.157/6.6.118). A 6.1+ arm64 kernel therefore always has it; a
   5.10/5.15 one has it only if the vendor opted in. If both
   `CONFIG_HAVE_POSIX_CPU_TIMERS_TASK_WORK` and
   `CONFIG_POSIX_CPU_TIMERS_TASK_WORK` are absent, **stop**: the profile can
   pass F7–F10 and will never pass F11, because the fired timer is expired
   inline in tick/irq context and the exit path never dequeues the stale node.
   Four factory kernels are known like this — the 5.15.194 `vermeer` and
   `zircon` (Redmi Note 13 Pro/Pro+), the 5.15.194 `zephyr` (Redmi Note 17 4G)
   and the 5.10.236 `garnet` (Redmi Note 13 Pro 5G). Their profiles are kept
   as *unsupported by configuration*; do not retry the plant or bisect.
   Details and the diagnostic signature are in `SKILL.md` §11.

   When you re-verify such a kernel, re-run it with the current canonical
   `timer` and the slabinfo-readable harness rather than citing an older
   transcript. A pre-fix log shows `slabinfo unreadable` and the
   `slab -1 -> -1` reclaim fallback, which weakens the evidence even though
   the conclusion is a build fact. With the fix the log reads
   `slab geometry confirmed by slabinfo` and a real `slab N -> M` delta, and
   F11 still fails on all six plants — record that run.

   Some `boot.img`s store an **LZ4-legacy compressed** `kernel` instead of a
   raw `Image` (`chagall`, `klimt`, `duchamp`, `degas`, `zircon` in the
   November-2026 Xiaomi batch). `file` says `LZ4 compressed data, legacy`;
   decompress it to `kernel.raw` before the `IKCFG` scan, the BTF scan or any
   disassembly. The `IKCFG_ST` blob sits near the end of the decompressed
   image (around 24-25 MB), so a "no IKCFG" result on the compressed file is
   expected — do not conclude the config is absent from the compressed bytes.

   **Pass `derive_conf.py` the `vendor_boot.img`, not an extracted directory.**
   `android_arch_task_struct_size` (which sets the `task_struct` vendor
   extension) is only in the vendor image; the key lives in the vendor
   `dtb`/bootconfig trailer. An extracted `work/xi2/<dev>-vb/` directory made
   `unpack_bootimg` fail and the old code returned `0` without a word, which
   is *exactly* the value a kernel with no vendor extension legitimately
   produces — so athens and haotian quietly lost `0x400`/`0x200` of
   `task_alloc_bytes` with no error. The script now reads the key out of the
   directory too, and warns when it cannot find it; a `[!]
   android_arch_task_struct_size not in …` line means the derivation is
   incomplete, not that the kernel lacks the extension. Verify
   `task_alloc_bytes` against the `vendor_boot` cmdline before trusting it.

   A kernel with **no BTF at all** still ports, but every geometry constant
   must then come from disassembly and static data. The 5.10.236 `garnet`
   build is the worked example: `cred` `0xa8` with a 4-byte `usage`, no
   `cred->ucounts` (that field arrived after 5.10, so `cred_ucounts_off` is
   pinned onto the `group_info` slot at `0x90` and `init_ucounts` points at
   `ucounts_hashtable`, which is written but never dereferenced), `task_struct`
   `0x1280` from the `fork_init` literal, and `cred_req = cred_size = 0xa8`
   from `cred_init`. Confirm each against `prepare_creds`, `put_cred_rcu`,
   `getuid`/`geteuid` and `dup_task_struct`.

   BTF has a trap when the banner is derived from it: some builds' strings
   table only carries the literal `Linux version %s (%s)`, so a naive banner
   read returns that format string, not a release. `scripts/derive_conf.py`
   now rejects it; read the banner from `/proc/version`/the `Image` header or
   the OTA manifest instead.

4. Record a few **runtime facts** from the device (these are allowed because
   they are observations, not constants to derive from):

   ```sh
   adb shell cat /proc/slabinfo | grep -E 'posix_timers_cache|cred_jar|task_struct'
   ```

   These show the object sizes and slab order the kernel actually uses. If the
   device cannot boot yet, QEMU reproduces the same lines from the factory
   Image.

Log the hashes, symbol count and the three slabinfo lines.

### Where the factory artifacts come from

- **Pixel** — the factory zip on `developers.google.com/android/images`. The
  inner `image-*.zip` is stored uncompressed, so `boot.img` and friends are
  readable with HTTP ranges (`timerroot-port/pixel/fetch_boot.py`).
- **Xiaomi / Redmi / POCO** — the HyperOS **full** OTA
  (`<codename>-ota_full-<build>-*.zip` on `bigota.d.miui.com`). Only the full
  OTA carries a `payload.bin`; recovery incrementals do not.
  `timerroot-port/xiaomi/fetch_xi.py` reads the payload manifest with range
  requests and reassembles `boot`, `vendor_boot` and `dtbo` without pulling the
  7-10 GB zip. Take the build the device actually runs — the CN build for
  CN-first models, otherwise the newest global/EEA one — because the banner,
  not the model name, is the identity.
- **Samsung** — the full firmware zip from SamMobile/Frija; the per-model
  folders are listed in `timerroot-port/samsung/MANIFEST.md`.

Two checks before deriving anything from a Xiaomi payload:

- **The banner may already be in the tree.** Xiaomi ships one GKI payload
  across a generation, so e.g. the Xiaomi 14 (`houji`) kernel `Image` is
  byte-identical to the Redmi Note 15 Pro+ (`flourite`) one. A byte-identical
  `Image` under the same release means an existing `conf/` is a candidate — but
  its addresses still have to be verified against *this* vmlinux.
- **`vendor_boot`/`dtbo` carry the vendor command line.** An
  `android_arch_task_struct_size=` parameter there changes `task_alloc_bytes`;
  read it before copying that value from a sibling device.

---

## Step 2 — Derive the numbers

This is the real work. Verify every value by **the surrounding instruction
sequence**, never by symbol name alone.

### 2.1 The two code addresses

- **`timer_site`** — the *return address* of the `bl kmem_cache_alloc[_noprof]`
  that allocates a `posix_timers_cache` object. Newer kernels have a second,
  similar call bracketed by `current->alloc_tag` swaps; that is the profiling
  path, not the one you want. The return address (`bl` + 4) matters because the
  planted fake node is what the reload at that address sees.
- **`copy_process_low21`** — the low 21 bits of the return address of the
  `task_struct` allocation from `copy_process()` (or from `dup_task_struct()`
  on kernels where it is a separate function). The exploit searches trace
  records for that 21-bit match.

### 2.2 The six symbols

Read these from `nm vmlinux` and re-check them by hand:

```
selinux_state   panic_on_warn   root_user
init_user_ns    init_ucounts    init_groups
```

`selinux_state` must be the **base of the struct**, so that the exploit's
`-7` store lands on the `enforcing` byte (BTF should put `enforcing` at bit 0).

### 2.3 Sizes and offsets from BTF

BTF gives you the structure layouts; slabinfo confirms how the allocator rounds
them:

- `sizeof(k_itimer)` → `timer_alloc`; `offsetof(k_itimer, it)` →
  `timer_node_off`,
- `sizeof(struct cred)` → `cred_req` / `cred_size`, its rounded slab object →
  `cred_alloc`, and the offsets of `uid`, `euid`, capabilities, `security`,
  `user`, `user_ns`, `ucounts`, `group_info`,
- `sizeof(struct task_struct)` and the offset of its `cred` field →
  `task_cred_off`.

The `cred.usage` field is either 4 bytes (5.15, 6.1) or 8 bytes (6.6+); the
whole fake credential shifts with that width, so **never copy `fake_*` offsets
between the two families**.

### 2.4 `task_alloc_bytes`

Start with `sizeof(task_struct)` from BTF. On 6.6+ a firmware parameter
`android_arch_task_struct_size` can add an extension, but only **if it is set**
— look in the vendor `dtb` / bootconfig of `vendor_boot.img` / `dtbo.img`.
Known settings range from none to 512, 784 and 1024 bytes. Store the final
value in `task_alloc_bytes`.

### 2.5 `selinux_blob_off` — the one that is not a lookup

This is the offset of the SELinux security blob inside the combined LSM cred
blob. It is assigned at boot in **LSM registration order** (the runtime
`CONFIG_LSM=` order), with each contributor aligned to 8 bytes:

```
for each LSM in registration order:
    offset = ALIGN(total, 8)
    total += that LSM's cred blob size
```

Landlock is the usual surprise: on some 6.12 builds it registers an 8-byte cred
blob and on 6.18 an 11-byte one (rounded to 16), pushing SELinux to `0x8` or
`0x10`. Deriving this from the `CONFIG_LSM` string alone gets the wrong answer —
that string lists every LSM the kernel *supports*, including ones whose
`CONFIG_SECURITY_<X>` is off and which therefore appear nowhere in
`__start_lsm_info`. Reconstruct the order from the kernel's LSM info section,
and cross-check against the Image's embedded config (`IKCFG_ST`): a
`# CONFIG_SECURITY_LANDLOCK is not set` means landlock's blob does not exist
even though `landlock` is the first name in `CONFIG_LSM`. Getting this wrong
corrupts the child process's SELinux SID.

### 2.6 Family shortcuts

These are starting points, not substitutes for the checks above. Always confirm
against BTF and disassembly.

| Family | Text base | Timer allocation | `timer_alloc` | `timer_node_off` | `cred` | `task_cred_off` | `selinux_blob_off` |
|---|---|---|---|---|---|---|---|
| 5.15 | `0xffffffc008000000` | `do_timer_create` → `kmem_cache_alloc` | `0x108` | `0x78` | `0xb0` (4B usage) | `0x798` | `0x0` |
| 6.1 | `0xffffffc008000000` | `do_timer_create` → `kmem_cache_alloc` | `0x108` | `0x78` | `0xb0` (4B usage) | `0x838` | `0x0` |
| 6.6 | `0xffffffc080000000` | `do_timer_create` → `kmem_cache_alloc` | `0x108` | `0x78` | `0xb8` (8B usage) | `0x820` | `0x0` |
| 6.12 | `0xffffffc080000000` | `alloc_posix_timer` → `kmem_cache_alloc_noprof` | `0x100` | `0x78` | `0xb8` (8B usage) | `0x900` | `0x0` or `0x8` (landlock) |
| 6.18 | `0xffffffc080000000` | `alloc_posix_timer` → `kmem_cache_alloc_noprof` | `0x180` | `0xe0` | `0xb8` (8B usage) | `0x908` | `0x10` |

Family-invariant defaults: `slab_order = 1` at 4K, `fake_cred_off = 0x18`,
`alloc_req_off = 0x10` (`0x18` on 6.18, which adds a `name` field),
`selinux_sid_kernel = 1`, full capabilities `0x1ffffffffff`. A 16K build keeps
the family values but overrides `page_size`, `page_shift`, `slab_order = 0` and
`slab_size = 16384`.

On 6.12+ the allocation can live in `alloc_posix_timer()` **or** in
`do_timer_create()`, depending on the build. Find the actual call; the function
name in this table is only a hint.

Log the address plus a disassembly snippet, the 6/6 symbols and the LSM order.
The helper scripts (`derive.py`, `sitecheck.py`, `blobsim2.py`, `evidence.py`)
regenerate those tables straight from `vmlinux` + BTF.

### 2.7 `scripts/derive_conf.py` — the mechanical part

`scripts/derive_conf.py` automates steps 2.1–2.5 and refuses to write a profile
when a critical constant could not be established. It is a starting point for
a port, **not** a substitute for the gates: F1 (is the bug present) and F6–F16
still have to be run and logged.

```sh
vmlinux-to-elf Image vmlinux.elf
scripts/derive_conf.py \
  --vmlinux vmlinux.elf --image Image \
  --vendor-boot vendor_boot.img \
  --slab-order 1 \
  --device "OPPO Reno 16F" \
  --output conf/<banner>.conf
```

What it derives, and from where:

| Value | Source |
|---|---|
| `release` | the `Linux version` banner inside the Image — the only string `uname -r` will match |
| `page_size`, `page_shift`, `linear_min`/`linear_max` | `file Image`; the direct-map window is `0xffff...` on 16K/64K and `0xffffff...` on 4K |
| `ksu_kmi` | inferred from the banner (`-android16-` + `6.12`) |
| `timer_site` | the `bl kmem_cache_alloc[_noprof]` in `alloc_posix_timer`/`do_timer_create` whose `x0` was built from `posix_timers_cache`, skipping the alloc-tag twin |
| `copy_process_low21` | the same, for `task_struct_cachep` in `dup_task_struct`/`copy_process` |
| `timer_alloc`, `timer_node_off`, all `cred_*`, `task_cred_off`, `alloc_req_off` | BTF (`k_itimer`, `cred`, `task_struct`, `trace_event_raw_kmem_cache_alloc`) |
| `selinux_blob_off` | replaying `lsm_set_blob_size` over `__start_lsm_info`..`__end_lsm_info`, using only LSMs the registry actually contains |
| `task_alloc_bytes` | BTF `sizeof(task_struct)` + `android_arch_task_struct_size` from `vendor_boot.img` (not rounded — the exploit's scanner matches the exact request) |
| `pcp_free` | `1` on 5.10/5.15/6.1; let the QEMU run decide on 6.6+ |

Four things it deliberately does **not** guess:

- **`slab_order`/`slab_size`.** SLUB derives the order from the device's
  possible-CPU count, so it is a hardware fact. The script emits a placeholder
  (0 on 16K+, else 1) and warns; pass `--slab-order` once `/proc/slabinfo`
  answers. Pixel 11 on 4K is order 0, not the family default 1.
- **`task_alloc_bytes`** is not rounded to 64: the scanner compares against the
  literal `bytes_req`, so the vendor extension has to be added unrounded
  (`0x1440 + 0x310 = 0x1750`).
- **F1.** Whether the Image still calls `posix_cpu_timers_exit()` before
  `exit_itimers()` decides if the port exists at all.
- **The device run.** Everything up to F6 is static.

If a symbol, a call site or a BTF struct is missing, the script exits non-zero
without writing the file. That is the correct outcome: a profile with
`timer_site = 0x0` is not a draft, it is a memory-corruption bug waiting for a
user (the loader rejects it, but only after the app has shipped it).

---

## Step 3 — Write the profile

Copy the closest existing `conf/*.conf`, rename it to the exact banner, and
change what differs. The format is HOCON (`key = value`, `#` or `//` comments).
The loader **pre-fills defaults** for the 6.6/6.12 layout, so a profile only
needs to state what is different — an omitted key is not a draft, it inherits
the default.

A profile must set, at minimum:

- **identity:** `release` (exact banner; a `-4k` suffix is ignored) or
  `release_prefix` (prefix match at `-` boundaries), `ksu_kmi`, and
  `page_size` / `page_shift` for non-4K builds,
- **slab:** `slab_order`, `slab_size`, `linear_min`, `linear_max`,
- **sites:** `timer_site`, `timer_alloc`, `copy_process_low21`,
- **credentials and task:** `cred_req` / `cred_alloc` / `cred_size`,
  `cred_uid_off`, `cred_euid_off`, `cred_cap_off`, `cred_security_off`,
  `task_cred_off`, `task_alloc_bytes`,
- **symbols:** the six from §2.2,
- **SELinux:** `selinux_blob_off`, `selinux_sid_kernel`.

Set the conditional keys when they differ from the defaults: `pcp_free = 1`
(5.15/6.1 free the slab through the PCP lists), `timer_node_off` on 6.18, and
so on. Leave `fake_cred_off` at `0x18` unless you re-derived it — it follows
from the erase geometry, not from the cred layout.

Keep the derivation notes as comments at the top of the file: hashes, call
sites, BTF sizes, LSM order. That is what makes a profile reviewable.

### Static invariants

`--selfcheck` asserts things like:

- `slab_size == page_size << slab_order`,
- both 21-bit call-site values agree with the static forms,
- `cred_uid_off` matches the `usage` width (4 or 8), `fake_cred_off == 0x18`,
- `cred_req < cred_alloc`, and the fake credential fits in the slab,
- `alloc_req_off` is `0x10` or `0x18` (6.18's `name` field),
- `linear_min < linear_max` bounds the **direct map**; the kernel image is
  mapped above it, so selfcheck requires `timer_site >= linear_max`. At run
  time the voted base must land inside that window and is mapped back to the
  image with the KASLR slide.

---

## Step 4 — Validate before touching a kernel

Run these on the host or with a manually built binary — they never access the
kernel:

```sh
timer --conf conf/<release>.conf target
timer --conf conf/<release>.conf selfcheck
```

`target` must print the expected `kernel=`, `profile=` and `timer_site=`.
`selfcheck` exits non-zero on any invariant failure. Then:

- hand a **deliberately wrong banner** to the binary and confirm it is refused
  before any kernel access,
- run `validate_conf.py` (in the port tree): it re-derives every constant from
  the factory `vmlinux` + BTF and diffs the result against your profile.

Gate F6 is: 0 validator errors, 0 selfcheck failures, correct `target` output,
wrong banner refused.

The app always starts the binary as `timer --conf <profile> --protocol 3`
(`--samsung` too for Samsung profiles). The binary refuses to run without a
profile and prints `OLD_APP_DETECTED` / `TIMER_PROTOCOL=3` if an older app
starts it. A rebuilt binary must keep those literal string markers, or the app
will not select it at all.

---

## Step 5 — Prove it in QEMU

Boot the **unmodified factory Image** at the same page size. The harness is
`work/qemu/` in the separate, gitignored port tree (`timerroot-port/`):
`initramfs/`, `mkinitramfs.sh`, `mass.py`, `runhigh` and `logs/`. `runhigh`
raises the file-descriptor limit and then drops to **uid 2000** before
launching the exploit. That is not cosmetic: in a root-run QEMU the child is
already uid 0, so F11 passes without the exploit having worked. It also has to
`chmod -R a+rwX /sys/kernel/tracing` in `init` (or set the tracefs mounts up
as uid 2000), because the exploit writes tracefs control files and a plain
initramfs leaves them root-only. Confirm the drop from the transcript line
`runhigh: uid=2000 euid=2000 gid=2000`; a `uid=0` there means the helper is an
old build that only raised the fd limit.

**F11 evidence older than the uid-2000 rule is void.** The rule was recorded
in `AGENTS.md` on 2026-11-22, and the harness gained the privilege drop on
2026-11-21 23:37 (`runhigh.c` mtime; the file is in the gitignored port tree,
so the date comes from the filesystem, not from git). Any F11 transcript
before that is a **root** run: the child starts at uid 0, so `resuid=0/0/0`
and `ROOT_SHELL_OK` prove nothing — the exploit may never have fired. Treat
such a profile as "F7–F10 done, F11 never run" and re-run it. Do not cite a
pre-rule pass as a regression control either: a pre-rule pass that a current
run fails is expected and says nothing about the profile or the binary.

**Ship the committed binary, every build.** `mkinitramfs.sh` installs
`p7a/timer_p7a` as `initramfs/timer` by name and prints its sha256, so a
hand-copied experiment left in `initramfs/` can never silently become the
thing every gate is measured against. The current canonical blob is
`b05a46ff9af187eedf5daa81cda028ce9d8f65dfd135d0a85c934b19d94f2616`; a
transcript recorded before the initramfs gained that hash may have run a
different `timer`. `TIMER_BIN=<path>` overrides it for a deliberate
instrumented build — the hash still prints, so such a transcript cannot be
mistaken for the shipped binary. Keep `INIT_OVERRIDE` for a probe `init`.

**Keep one F11 transcript per passing profile** in
`work/qemu/logs/<release>.f11-pass.log`. `mass.py` writes the passing
transcript as `f11-pass` alongside the failing `f11-1`/`f11-2` attempts
(a retry pass also keeps its `f11-0` miss), so the uid-2000 line, the
`pcp reclaim go` line and `resuid=0/0/2000` are all recoverable for the exact
binary that produced them. Earlier harness revisions saved only failures,
which is why some older cells cite a JSON summary no one can re-audit;
re-running such a profile is the only fix.

When the profile's slab geometry should be proven rather than pinned, boot
once **without** `slub_min_order` and read the `posix_timers_cache` line from
`/proc/slabinfo`: if `pagesperslab` still gives the profile's order, the
geometry is the kernel's own choice and not a harness hint. The same boot
can omit `android_arch_task_struct_size` to confirm the profile's
`task_alloc_bytes` needs no vendor extension.

Boot parameters are derived, not guessed:

- pass `android_arch_task_struct_size=<value>` if the firmware sets it,
- pin `slub_min_order=<slab_order>` so SLUB picks the phone's geometry instead
  of choosing from the VM's CPU count,
- leave `--mem` at the harness default. Raising it is not a fix for a 16K
  page-size profile, and it can break one: a 16K profile whose slab is order 0
  (`slab_size = 0x4000`) relies on real memory pressure to push the freed page
  out of the buddy allocator before the spray catches it. At 6144 MB every
  plant logged `free_seen=0 burst hit=0` for all six attempts, while at the
  default 3072 MB `tegu` 16K and `p11` 16K pass on the first attempt in
  20-35 s. Only `blazer` 16K stays tight at 3072 and needs a retry.
- when a 16K run does log `invoked oom-killer` (blazer 16K does, at ~73 s in
  `alloc_skb_with_frags` ← `unix_stream_sendmsg`), treat the OOM as a
  **symptom, not the cause**. The guest only exhausts memory because every
  plant missed and retried six times; the miss comes from a bad `[ids]` line
  (see the `FAIL(ids=… text=…)` row in `SKILL.md`), which leaves the wrong
  page-free event id and makes `scan_reclaim` blind. Fix the `ids` reading —
  re-run, and if it repeats raise the settle before `ids` — rather than giving
  the guest more memory, which suppresses the reclaim the exploit needs.
- raise the socket buffer sysctls in the initramfs (`wmem_max` / `rmem_max`
  around 1 MB) **if the spray starves**. The shipped `base/init` does *not*
  set them, and every 5.10/5.15/6.1/6.6/6.12/6.18 profile that has a
  `CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y` kernel passes F7–F11 without them: the
  phase-2 burst now waits for `mm_page_free` before spending its send budget,
  so the default 212 992-byte queues are enough. Only add the sysctls when a
  transcript shows `send ok` collapsing early with `err` climbing into the
  millions, i.e. the pre-fix starvation signature.

The conf's `slab_order` / `slab_size` are a **hint**, not a fixed truth: SLUB
derives the real order from the phone's possible-CPU count, which can differ
from the QEMU boot. The binary reads `/proc/slabinfo` first when it can — the
`pagesperslab` column of `posix_timers_cache` gives the order directly — and
logs either `slab geometry confirmed by slabinfo` or `slab geometry mismatch …
using slabinfo geometry`. Record the `[base] … order=… size=…` line as a
finding. Do not assume slabinfo is world-readable: the inspected kernels create
it `0400`, and Android commonly changes it to `0440 root:log`. Shell access then
also requires supplementary gid `log` and an SELinux label/rule that permits
`shell` to read `proc_slabinfo`; see
[the factory-image audit](slabinfo-access-audit.md). If any link is missing,
record `slabinfo unreadable` and the geometry derived from timer addresses.

**In the QEMU harness, make slabinfo readable to uid 2000.** The factory
kernel creates `/proc/slabinfo` `0400` (and field Android usually relabels it
`0440 root:log`, which the shell can read). A plain initramfs leaves it
`0400`, so a uid-2000 run cannot open it — and a `pcp_free = 1` profile reads
the `posix_timers_cache` object count as its authoritative free signal. The
burst then guesses instead of waiting, `hit=1` fires against the wrong
lifetime, and the plant misses while every line still looks plausible.
`base/init` does `$BB chmod 0444 /proc/slabinfo` right before it dumps the
three `slabinfo` lines; keep that line, and check the transcript's
`=== slabinfo ===` block appears before `=== RUN` (it is the same state the
phone's shell user sees). This is a harness reproduction of a field fact, not
a privilege bypass — nothing is derived from it.

Do not trust the page-event vote by itself. It only sees slabs created inside
its capture window, so a warm cache (a second run in the same boot) allocates
almost nothing and the vote collapses to the wrong order — `count=31 order=0`
on a device whose real geometry is order 1 with 31 objects. That halves
`slab_size`, which puts the fake cred in the other half of the block and makes
the spray cover only the half without the stale node: root fails while every
"hit" and "reaped" line still looks successful. Calibration now drains the
free objects slabinfo reports before measuring, and a plant whose victim
offset is not a multiple of `timer_alloc` is rejected and retried.

A matching `uname -r` does **not** mean the profile's text layout matches.
Vendor builds on one GKI tag use different defconfigs, so the
`do_timer_create` `kmem_cache_alloc` return address moves while the release
string stays identical — the 6.6.118 family already has `0x195d48`,
`0x195d50`, `0x195d94` and `0x1a4dfc`. The scan filters on
`timer_site & 0x1fffff`, which the 2 MB-aligned KASLR slide does not change,
so a wrong site is not a KASLR accident and must not be "fixed" by relaxing
the filter: the same captured address is the slide anchor
(`site0 - timer_site`), and a profile whose site is off writes the endgame to
the wrong kernel address. Instead, calibration now distinguishes the three
ways the scan can come up empty:

- `the trace holds no kmem_cache_alloc record for pid …` — the event is not
  recording. `enable_events()` used to write the `rss_stat` trigger and ignore
  the result; a rejected write left the page events on, so `ids` passed and
  only the timer scan starved. It now reads every event back and retries
  through `events/kmem/<event>/enable`, naming any event that stays off.
- `… none with bytes_req == bytes_alloc == …` — the object size is different;
  re-derive `timer_alloc`.
- `no call_site has low21 …` plus `observed call_site=… low21=… count=…` — the
  text layout is different. Take the observed `low21`, match it against the
  known builds for that family, and port that boot.img; do not reuse the
  sibling's `timer_site`.

The same applies to the CPU: every capture reads one CPU's `trace_pipe_raw`,
so the allocating process must be pinned to it. `sched_setaffinity()` to
`CPU_TRIG` can be denied by the vendor cpuset for the shell domain; the binary
then traces an allowed CPU and logs `[!] cannot pin to cpu …` instead of
reading a buffer the allocations never touched (which looks exactly like a bad
profile).

Run the gates in order and keep the log:

| Gate | Command | What you want to see |
|---|---|---|
| F7 | `timer target` | correct `kernel=`, `pagesize=`, `profile=` and `timer_site=`, exit 0. Do not gate on `target=lynx`: the binary prints that constant for every profile, so it proves nothing about which Image booted |
| F8 | `timer ids` | trace event ids, no `dmesg` noise; safe to repeat |
| F9 | `timer probe` | page-base votes agree, no `victim index missing`; safe to repeat |
| F10 | `timer leak` | credential leak on 8/10 or better |
| F11 | `timer` / `timer shell` | `child report uid=0 euid=2000`, `setuid(0)=0`, `resuid=0/0/2000`, `ROOT_SHELL_OK` — a shell-uid run keeps the saved uid at 2000, and the plant only writes `uid`, so `euid` is still 2000 when the child wakes |
| F14 | `mass.py` | profiles with a workspace factory Image pass F7–F11; per-profile results and the two provenance/environment exceptions in `logs/mass-*.json` / `PORT_LOG.md` |

Only F11 arms the spray. Reaping the zombie alone does not prove the payload
was written: if the slab free lands after the phase-1 burst, the page can be
recycled after the stale `rb_erase` has already passed. The plant therefore
reads the child's real uid from `/proc/<pid>/status` and retries the whole
plant with a fresh pool up to six times; `plant n left child uid=…; retrying`
is a normal recoverable miss. A lost race here is a harness artefact, not a
profile fault: retry once and record both attempts. A 16K build needs its own
QEMU pass.

**Do not retry over a bad `[ids]` line.** If F8 reports an event id outside
1..1024 — most often `page_free=1701669690`, which is `":kme"` read as
ASCII — the trace was consumed as text, not binary records. That wrong id
makes `scan_reclaim()` compare against an event that never fires, so every
plant misses for a reason that has nothing to do with the profile. Stop,
re-run the whole profile, and record the miss; retrying F11 or adding guest
memory only buries it.

**`hit=1` proves the reclaim, never the write.** `scan_reclaim()` sets the hit
when *any* spray thread's `page_alloc` took the victim pfn after a `page_free`.
The payload write additionally needs the exit path to run `rb_erase` on the
armed node after that recycle. A transcript can therefore show
`free_seen=1 burst hit=1`, `reaping`, a clean `write mode=zero` and
`EXIT status=0` while the target word never changes — do not read `hit=1`,
`permissive done` or `EXIT status=0` as proof of the primitive. For the
zero-write the proof is `resuid=0/0/2000`; for `permissive` it is the
discriminating readback (`sysctl_perf_event_paranoid` `2` → `0`), because
selinuxfs is not mounted in the stock initramfs and `getenforce` proves
nothing. `timer fake` is no better as a fallback: on a config-blocked kernel
it also ends with the child still at uid 2000 (`mode=fake`,
`resuid=2000/2000/2000`), so the miss is general, not zero-write-specific.

If a `pcp_free = 1` transcript has no `pcp reclaim go (slab N -> M, Xms)`
line, do not trust the result at all: the slabinfo gate did not run, the
burst spent its budget blind, and `hit=1` means something other than what
you think. Check the initramfs hash and the conf's `pcp_free` before reading
anything else in that log.

Some Samsung kernels call the phone's Knox hypervisor and will not boot in QEMU.
For those, boot a **throwaway patched copy** (a "shim") that neutralises those
calls — but never derive a single constant from the shim.

---

## Step 6 — Prove it on the device

The runtime contract matters as much as the constants:

- Run from **`adb shell`** only, as `shell` (uid 2000, `u:r:shell:s0`) — never
  `su`, never a terminal app. The exploit needs `/sys/kernel/tracing`.
- Let the phone settle **2–3 minutes** after boot before the first run.
- `dmesg -C` before every run and pull `/data/local/tmp/timer_last.log` after
  any panic.
- **One variable per run**, and reboot between attempts. A failed plant parks a
  process holding a fake credential page; killing it can panic the kernel.

Build and stage the binary:

```sh
aarch64-linux-gnu-gcc -static -O2 -pthread p7a/timer_p7a.c -o timer
adb push timer /data/local/tmp/timer
adb shell chmod 755 /data/local/tmp/timer
```

That is a host smoke build; for the byte-identical CI asset use the NDK
command in `AGENTS.md`. The app accepts only binaries carrying
`TIMER_PROTOCOL=3` (`TIMER_SAMSUNG=1` for Samsung-capable builds) and always
passes `--conf <profile> --protocol 3`. The shell service can keep an older
binary across an APK update, so the beta channel force-refreshes the rolling
asset — if a fix appears not to take effect, compare the staged binary's hash
with the built one before touching the profile. The app also writes a
shell-uid device spec to `/data/local/tmp/timer-debug.log` before each run;
attach it with `timer_last.log` when reporting a failure.

Then, on the device:

1. re-run `leak` and verify (F10/F11), then `timer shell` for a root shell.
   From `adb shell` the verify child reports `resuid=0/0/2000`; the `shell`
   mode is the real root shell;
2. `timer permissive` → `getenforce` reports `Permissive` (F12);
3. `timer fake` → uid 0 worker, KernelSU loaded, `su -c id` shows
   `u:r:ksu:s0` (F13);
4. cold boot, settle, 10/10, then measure the success rate over **200 runs**
   (F15);
5. only then change the device's table entry from `verified in QEMU` /
   `untested` to `tested` in [Supported devices](supported-devices.md) (F16).

Report the measured rate, not the hoped-for one.

---

## Samsung kernels, in brief

Samsung profiles live in `conf/samsung/` and need a few extra fields:

- `release_prefix` must be the **full banner** — sibling builds share the
  numeric release but differ in the firmware suffix and every address;
- `defex_creds_hash` (from kallsyms) lets the chain clear Samsung's per-pid
  credential table;
- `samsung_package` pins the manager to the `samsung-v*` KernelSU build.

The endgame is a five-plant chain (DEFEX hash → fake cred → SELinux state →
uid/euid repair → init-domain switch). Misses are expected and must be
recoverable. Some Samsung Images boot in QEMU unmodified; those that do not
use the throwaway shim described in Step 5.

---

## Rules you must not break

1. **Never run a non-matching banner.** The conf gate is a safety net, not a
   formality.
2. **Never kill a parked process.** Reboot instead.
3. **Never derive constants from the running device or a QEMU shim** — factory
   `boot.img` only.
4. **Never mix fake-cred offsets between 4-byte and 8-byte `usage` families.**
5. **Never arm the victim timer in a probe.**
6. **Never edit a constant without a source comment** saying where it came
   from.
7. **QEMU before hardware. Always.** 16K gets its own pass.
8. **One gate per commit**, and log every gate.
9. **Do not break** `target=lynx` or the `argv[0] == ""` re-exec branch.
10. **Report the measured rate**, not the hoped-for one.
11. **Never qualify F11 from a root QEMU run** — drop to uid 2000 first; a
    child that starts as root proves nothing.
12. **Never trust a stale binary** — check `TIMER_PROTOCOL=3` and the built
    asset's hash before blaming a profile for a missing fix.
13. **Never widen the `timer_site` match to make a device calibrate.** The
    captured address is the slide anchor; a profile whose site is off writes
    the endgame to the wrong kernel address. Port the image instead.

If something goes wrong, [SKILL.md §11](../SKILL.md#11-diagnostics) maps the
log lines (`victim not captured`, `bad base`, `fake cred spills`, …) to their
causes. `base calibration failed` in particular is no longer opaque: the lines
immediately above it say whether the trace event was off, the object size was
different, or the profile's call site belongs to another image.

---

## Definition of done

- [ ] F1–F16 logged in `PORT_LOG.md` (F12+ may be pending with a device plan).
- [ ] Profile in `conf/`; validator 0 errors; `--selfcheck` 0 failures; wrong
      banner refused.
- [ ] QEMU F7–F11 green against the factory Image, for each page size that
      exists, run as uid 2000 with `resuid=0/0/2000` + `ROOT_SHELL_OK`.
- [ ] Binary carries `TIMER_PROTOCOL=3` and is started with `--conf … --protocol 3`.
- [ ] Device: `woke uid=0`, `getenforce=Permissive`, `u:r:ksu:s0`, 10/10 cold
      boots, measured rate over 200 runs recorded.
- [ ] Stable for 10 minutes, clean `dmesg`, no reboot.
- [ ] [Supported devices](supported-devices.md) updated: `verified in QEMU`
      becomes `tested` only after F15.

---

## Going deeper

- [SKILL.md](../SKILL.md) — the full procedure with scripts, disassembly
  patterns, cross-checks, Samsung details and diagnostics.
- [PORT_LOG.md](../PORT_LOG.md) — worked examples for every kernel family
  already in the tree.
- [Building](building.md#adding-a-kernel-profile) — how the profile is bundled
  into the app.
- [Supported devices](supported-devices.md) — what `verified in QEMU` and
  `tested` mean for users.
