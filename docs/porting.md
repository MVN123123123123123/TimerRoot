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

1. Get `payload.bin` / `boot.img` (and `vendor_boot.img`, `dtbo.img` when you
   need the vendor command line).
2. Unpack `boot.img` and extract the raw kernel `Image` and the `vmlinux` with
   symbols.
3. Extract the `.BTF` section:

   ```sh
   nm vmlinux | wc -l                         # must be non-zero; else vmlinux-to-elf
   objcopy --dump-section .BTF=btf.bin vmlinux
   sha256sum boot.img vmlinux btf.bin
   ```

4. Record a few **runtime facts** from the device (these are allowed because
   they are observations, not constants to derive from):

   ```sh
   adb shell cat /proc/slabinfo | grep -E 'posix_timers_cache|cred_jar|task_struct'
   ```

   These show the object sizes and slab order the kernel actually uses. If the
   device cannot boot yet, QEMU reproduces the same lines from the factory
   Image.

Log the hashes, symbol count and the three slabinfo lines.

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
reconstruct the order from the kernel's LSM info section. Getting it wrong
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
already uid 0, so F11 passes without the exploit having worked.

Boot parameters are derived, not guessed:

- pass `android_arch_task_struct_size=<value>` if the firmware sets it,
- pin `slub_min_order=<slab_order>` so SLUB picks the phone's geometry instead
  of choosing from the VM's CPU count,
- raise the socket buffer sysctls in the initramfs (`wmem_max` / `rmem_max`
  around 1 MB), otherwise the spray starves.

The conf's `slab_order` / `slab_size` are a **hint**, not a fixed truth: SLUB
derives the real order from the phone's possible-CPU count, which can differ
from the QEMU boot. The binary votes orders 0–3 from the trace records and, on
a clear win, overrides the profile and logs `slab geometry mismatch … using
device geometry`. Record the `[base] … order=… size=…` line as a finding.

Run the gates in order and keep the log:

| Gate | Command | What you want to see |
|---|---|---|
| F7 | `timer target` | the correct profile is selected |
| F8 | `timer ids` | trace event ids, no `dmesg` noise; safe to repeat |
| F9 | `timer probe` | page-base votes agree, no `victim index missing`; safe to repeat |
| F10 | `timer leak` | credential leak on 8/10 or better |
| F11 | `timer` / `timer shell` | `child report uid=0`, `setuid(0)=0`, `resuid=0/0/2000`, `ROOT_SHELL_OK` — a shell-uid run keeps the saved uid at 2000 |
| F14 | `mass.py` | profiles with a workspace factory Image pass F7–F11; per-profile results and the two provenance/environment exceptions in `logs/mass-*.json` / `PORT_LOG.md` |

Only F11 arms the spray. Reaping the zombie alone does not prove the payload
was written: if the slab free lands after the phase-1 burst, the page can be
recycled after the stale `rb_erase` has already passed. The plant therefore
reads the child's real uid from `/proc/<pid>/status` and retries the whole
plant with a fresh pool up to six times; `plant n left child uid=…; retrying`
is a normal recoverable miss. A lost race here is a harness artefact, not a
profile fault: retry once and record both attempts. A 16K build needs its own
QEMU pass.

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

If something goes wrong, [SKILL.md §11](../SKILL.md#11-diagnostics) maps the
log lines (`victim not captured`, `bad base`, `fake cred spills`, …) to their
causes.

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
