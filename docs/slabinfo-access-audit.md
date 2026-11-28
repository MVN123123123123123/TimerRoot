# `/proc/slabinfo` access audit

Audit date: **2026-11-24**. Scope: the factory boot artifacts in the
gitignored `timerroot-port/` workspace, plus the Samsung `sam_a1560/` extraction
and one live Pixel 7a reference device.

## Question

Can a normal `adb shell` process — **uid/gid 2000**, `u:r:shell:s0`, with the
supplementary groups compiled into `adbd` — open `/proc/slabinfo` for reading?

**Result:** the 71 table rows contain two confirmed sets — Pixel 9a (`tegu`,
CP3A.261005.005) from exact static artifacts and Pixel 7a (`lynx`) from live
same-build evidence — and 69 **Inconclusive** sets. None is **Unsupported**:
every decoded policy and `adbd` supports the required identity/read path, but
the exact product-system DAC step is missing for the other factory sets. The
affected Xiaomi OS3 exploit fix passed a uid-2000 QEMU replay on its exact
kernel; factory shell access and a hardware re-test on that Android 15 device
remain unproven.

The answer is a chain, not a single file mode:

1. **Kernel creation mode.** `slab_proc_init()` creates the proc file. The
   inspected Linux kernels use `proc_create("slabinfo", 0400, ...)`, i.e.
   `root:root 0400` before Android userspace changes it.
2. **Later DAC change.** Android's platform `init.rc` runs `chown root log
   /proc/slabinfo` and `chmod 0440 /proc/slabinfo` in `on post-fs`. The resulting
   `root:log 0440` file is readable by a process with supplementary gid
   `log` (1007), not by everyone.
3. **Shell identity and groups.** `adbd` must actually drop to uid/gid 2000 and
   install a supplementary-group list containing gid 1007. A shell without
   that group cannot pass DAC even when the file is `0440`.
4. **SELinux.** The loaded policy must label `/slabinfo` as `proc_slabinfo` and
   allow the `shell` domain `file:read` (with the other permissions needed to
   open the file). Enforcing SELinux checks this independently of DAC.

A `ueventd.rc` entry alone does **not** establish the final proc-file DAC mode.
A boot ramdisk with a short, recovery-style `init.rc` does **not** establish what
the platform system image will do later. Conversely, a matching `init.rc` does
not establish the shell's groups or the SELinux decision.

## Verdict rules

- **Confirmed:** the exact image set contains positive evidence for every link.
- **Unsupported:** the exact effective policy denies the required access, or
  the complete exact init configuration positively leaves the file inaccessible
  to the shell. Missing artifacts and short recovery-style init files are not
  “unsupported.”
- **Inconclusive:** at least one required link cannot be decided from the exact
  matching artifacts. This is the verdict for an image set with policy and
  `adbd` but no matching system `init.rc`, or with a kernel but no policy/init.

The per-image tables below report what each artifact contributes. A boot image
is not marked access-confirmed merely because a sibling `vendor_boot.img` has a
permissive policy.

## Method

- Parse Android `boot` v4, `init_boot`, and `vendor_boot` v4 headers and their
  newc cpio ramdisks. Android 13+ places generic init in `init_boot`; a boot
  image with no ramdisk is not evidence that init or policy is absent from the
  device.
- Decode each distinct binary SELinux policy with SETools 4.7.1:
  `GenfsconQuery(fs="proc", path="/slabinfo")` and an allow query for
  `shell proc_slabinfo:file read`.
- Inspect each distinct `adbd` ELF for the uid/gid it selects and the
  supplementary groups it installs.
- Disassemble `slab_proc_init()` in each reconstructed factory `vmlinux` and
  read the mode argument to `proc_create`/`proc_create_data`.
- Read the matching platform `system/etc/init/hw/init.rc`, when present. Do not
  substitute a different device's or a different monthly build's system image.

## Reference findings

### Live Pixel 7a (`lynx`)

The connected device runs Android 17, build
`CP4A.261105.040.A1/16581829`, kernel
`6.1.172-android14-11-g8d0115b07367-ab16385437`. With SELinux **Enforcing**:

```text
uid=2000(shell) gid=2000(shell)
groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),...
context=u:r:shell:s0
/proc/slabinfo: 0440 root:log
label: u:object_r:proc_slabinfo:s0
posix_timers_cache 248 248 264 31 2 : tunables ... : slabdata 8 8 0
```

Its system `init.rc` contains the `chown root log` / `chmod 0440` pair, and its
loaded policy allows `shell proc_slabinfo:file read`. The loaded policy SHA-256
is `267600fd96298e3f54d30f82dea41c9c9de028c3562589be8e905783c5b8e867`;
it is not byte-identical to the factory `vendor_boot` policy
(`5149f80d…`), although both decode to the same slabinfo label and shell-read
allow. This is a complete, positive live reference for the access chain. It is
**not** used to certify a different factory image or the affected Android 15
Xiaomi build.

### Xiaomi `dada` OS4 log reference

`timerroot-port/timer-debug-dada-OS4-1.log` records exact build
`Xiaomi/dada_global/dada:17/CP2A.260605.016/OS4.0.0.11.XOCMIXM:user/release-keys`,
kernel `6.6.118-android15-8-g0908354dac1b-ab16143355-4k`, **uid 2000** with
supplementary gid 1007, SELinux **Enforcing**, and a successful
`posix_timers_cache 248 248 264 31 2` read. That proves effective shell access
for this exact OS4 build. The log does not record the inode owner/mode, label,
or the init rule, so the DAC mechanism remains unproven by that log. This is
**not** the affected OS3 kernel
`6.6.118-android15-8-gc44b714366cc-abogki519650608-4k`; it cannot certify OS3.

### Generic Android 17 system reference

`timerroot-port/work/f13/system.img` is the Google generic system image
`google/generic_system_google/generic:17/CP3A.261005.002.A1/16269273:user/release-keys`.
Its platform `init.rc` has the same `on post-fs` DAC change. This establishes
the AOSP/Google platform behavior for that exact generic build, but it is not a
matching system image for the CP4A Pixel factory set or the Xiaomi OTA builds in
this workspace. It therefore cannot turn those image sets into “confirmed.”

## Coverage and decoded results

The read-only inventory parsed **1,073 artifacts / 181 image files** in 79
identity groups, including 143 Android boot-family images and 102 cpio
ramdisks, with zero parser errors. SHA-256 deduplication found 30 duplicate
image groups; final validation independently rehashed 271 image/kernel artifacts
with no errors or warnings. A follow-up decoded and parsed the exact Samsung
A1560 `init_boot.img.lz4` and `vendor_boot.img.lz4`, which the initial inventory
had recorded as compressed images. The separate policy pass independently
accounted for **179 logical image sources** (142 unique images, 71 ramdisks and
183 source/ramdisk occurrences); it did not include the two A1560 follow-up
images. Those two contain no policy or `adbd`, so they add no decoded policy or
identity evidence.

### SELinux policy

All **34 distinct binary policies** (38 policy occurrences) loaded successfully
with SETools 4.7.1. Every one has both:

```text
genfscon proc /slabinfo u:object_r:proc_slabinfo:s0
allow shell proc_slabinfo:file { getattr ioctl lock map open read watch watch_reads };
```

The allow was checked as a direct rule and again after attribute expansion; all
34 were effectively allowing in both checks. A separate `neverallow` query for
`shell proc_slabinfo:file read` matched none of the 34 policies, and every allow
was unconditional and enabled at policy defaults. A missing policy is **not** a
denial: it leaves the image set inconclusive.

### `adbd` identity and groups

All **12 distinct `adbd` ELFs** (34 occurrences) compile the same privilege-drop
arguments:

```text
uid 2000, gid 2000
supplementary gids: 1011, 1007, 1004, 3003, 3002, 3001, 1028, 1015,
                   3006, 3009, 3011, 1078, 1079, 3012
```

GID 1007 is `log`; gid 1019 (`readproc`) is not in this list. These constants
reach `minijail_change_uid`, `minijail_change_gid` and
`minijail_set_supplementary_gids` on the normal privilege-drop path. Each ELF
also has an alternate `minijail_enter` path that can bypass those setters, so a
compiled constant alone is not proof of the IDs of every possible daemon
invocation. The live `lynx` and `dada` OS4 logs provide runtime corroboration for
normal `adb shell` sessions.

### Kernel creation mode

All **45 reconstructed kernel paths** register `slabinfo` with mode `0x100`
(decimal 256, octal **0400**) as the second argument to `proc_create` or
`proc_create_data`. The paths represent 31 unique ELF hashes and 31 unique
load-segment hashes: 40 expose a named `slab_proc_init`; five recover the
registration through retained `slab_common` init stubs. Provenance comprises 20 factory-tied paths, 15
OTA/FOTA-tied paths, nine exact local-image-only paths and one path without a
source-image tie. No disassembly errors remain.

This includes the affected Xiaomi `dada` OS3 kernel and the live Pixel `lynx`
kernel. The table marks a mode decoded only when the reconstructed kernel is
tied to that row's image by an exact payload hash (including a byte-identical
kernel shared by another named image set, such as the Xiaomi
`byron`/`nezha`/`pudding` raw Image). The November Pixel 11 factory 4K
and 16K kernels are decoded; the older October workspace kernel is a different
Image and is not substituted for them. A1560's FOTA kernel is decoded but is not
tied to the extracted factory `boot.img`, so that factory row remains “not
decoded.” A shared but non-identical workspace candidate is never substituted
for a factory kernel.

### Android DAC change

One exact factory product-system image supplies the missing link. The Pixel 9a
(`tegu`) CP3A.261005.005 factory member
`tegu-cp3a.261005.005/image-tegu-cp3a.261005.005.zip!system.img` has SHA-256
`13ceca8e520ceb661e0f26bc0dd81c1aebbf5abc319bab48f970807c6e1908e2`; its
properties identify `CP3A.261005.005/16271449`, matching the exact `init_boot`
build fingerprint `google/tegu/tegu:17/CP3A.261005.005/16271449:user/release-keys`.
Its ext4
`/system/etc/init/hw/init.rc` contains at lines 591–592:

```text
chown root log /proc/slabinfo
chmod 0440 /proc/slabinfo
```

Its `plat_sepolicy.cil` (SHA-256
`f6422dd5853e815d340f2e9c4dcba2bb1016b55ffc2a073fc916ac23dfe66fc2`) labels
`/slabinfo` as `proc_slabinfo` and itself contains the unconditional
`allow shell proc_slabinfo:file read` rule; it has no `neverallow` denying shell
read. The matching factory `vendor_boot` policy independently decodes to the
same label and allow, and its `adbd` compiles uid/gid 2000 with supplementary
gid 1007. The matching boot kernel Image has SHA-256
`e6762f904c99ca747350f0d5dbb9eac84a3d66e6fca0ce6104f81ecc958a54a3`, tied to
the reconstructed kernel that creates slabinfo `0400`. This exact set is
**Confirmed (static artifacts)**.

| Exact factory member | SHA-256 | Evidence |
|---|---|---|
| `boot.img` | `fa9367effa5eb94321406d3a65cccadd6e0338693430cd1621bea3c52ce99087` | kernel Image `e6762f90…`; decompresses byte-for-byte to the reconstructed `0400` kernel |
| `init_boot.img` | `dc362a7fa732504682f13cfedc194da711af197fc8461779954681e3ff622048` | generic init ramdisk; build fingerprint matches CP3A.261005.005/16271449 |
| `vendor_boot.img` | `e80c82bf6e3e08352d9baa5cf6b3361ae31df946c743009720559d5b00ec56d5` | policy `15ce54b6…` allows shell read; `adbd` `e04a0f97…` compiles uid/gid 2000 + gid 1007 |
| `system.img` | `13ceca8e520ceb661e0f26bc0dd81c1aebbf5abc319bab48f970807c6e1908e2` | exact platform DAC rules and platform CIL label/allow |

The generic Android 17 system reference discussed above has the same DAC pair,
but it is not substituted for any other factory set. The factory `vendor_boot`
copies of `system/etc/init/hw/init.rc` that were inspected are 192-line
recovery-style files beginning with
`import /init.recovery.${ro.hardware}.rc`; they contain no slabinfo rule. They do
not establish what the installed product system image does. Apart from the
`tegu` CP3A factory zip, no audited factory set has its exact matching product
`system.img` available locally.

### Samsung Galaxy A15 5G (`a1560` / SM-A1560)

The exact compressed init/vendor pair was decoded and every cpio ramdisk was
parsed:

| Artifact | Compressed SHA-256 | Decoded SHA-256 | Result |
|---|---|---|---|
| `sam_a1560/init_boot.img.lz4` | `76f2a7dcdcb13854db10c97c4b992b08f1d2f5af0e10c1c057da97b6e68c666e` | `ba03e11d907cc19ffcaf4db031d6440f18999305130db675ace0e3496f471358` | Android boot v4; 16-entry generic ramdisk contains ELF `init` (`bb5af448…`), but no `init.rc`, `ueventd.rc`, binary policy or `adbd` |
| `sam_a1560/vendor_boot.img.lz4` | `842df73b993754dbfc403c32f4890f6caba1d6181cd0809497709e6250acefeb` | `9d225a6f76650e2a461c20999deab2baed2f48d109c3c467611458fea6df357e` | Android vendor_boot v4; 259-entry ramdisk, with none of `sepolicy`, `adbd`, `init`, `init.rc`, `ueventd.rc` or `prop.default` |

Neither image has an exact slabinfo `chown`/`chmod` line in an `init.rc`; no DAC
conclusion was inferred from `ueventd.rc`. This establishes absence only in
those two images, not in recovery, boot or product-system artifacts. The
separate `sam_a1560/boot.img` has no ramdisk, and the exact product
`system.img` is unavailable. The set is therefore **Inconclusive**.

A retained Samsung FOTA package supplies an exact `BOOT/kernel` payload whose
raw Image SHA-256 is
`9dddd18f619c234c5a97e70b5fccdd11e43814b0b28dfa417392fa1dd2b8c6fb`; its
reconstructed kernel creates slabinfo `0400`. The FOTA package has no
`boot.img` entry or matching factory metadata, however, so that result is not
assigned to the extracted factory boot row.

## Live verification checklist

Run these as the ordinary shell user, without `su`, before an on-device exploit
test. Keep the output with the build fingerprint and kernel release:

```sh
id
getprop ro.build.fingerprint
uname -a
getenforce
stat -c '%a %U:%G %n' /proc/slabinfo
ls -Z /proc/slabinfo
head -n 3 /proc/slabinfo
grep '^posix_timers_cache ' /proc/slabinfo
```

A complete positive result has uid/gid 2000, supplementary gid 1007, an
Enforcing policy, a label ending in `proc_slabinfo`, and successful reads. The
mode/owner must be recorded rather than assumed. For offline correlation, also
collect the exact `boot`, `init_boot`, `vendor_boot` and product `system` images
for that build; compare their SHA-256 values with the table.

## Affected Xiaomi `dada` OS3 set

The affected profile targets
`6.6.118-android15-8-gc44b714366cc-abogki519650608-4k`. The matching extracted
images identify `dada:15/OS3.0.307.0.WOCCNXM:user`:

| Artifact | SHA-256 | Contribution |
|---|---|---|
| `work/xi/dada-boot.img` | `ab2d0d00da11e2796a912699f9d83e231b51800e7888d97e01e179bba8eee9bd` | kernel Image; reconstructed `slab_proc_init` creates `slabinfo` mode `0400` |
| `work/xi/dada-vendor_boot.img` | `dc8f650be5ce0ca488b6f41c5d7a5933f98163c84d37f8e1682992598ddf3a4b` | parsed vendor ramdisk has no `sepolicy`, `adbd`, `init`, `init.rc` or `ueventd.rc`; its slabinfo strings are in `minidump.ko`, not access-policy evidence |
| `init_boot.img` | not in this extracted set | Android 15 normally needs it; absence leaves generic-init inspection incomplete |
| matching product `system.img` | not available | no exact proof of the later slabinfo DAC change |

Therefore this OS3 factory set is **Inconclusive**, not unsupported. The
uid-2000 QEMU replay proves the exploit fix against the identical kernel Image;
it does not prove that a factory `adb shell` can read slabinfo. The successful
OS4 field read is a different kernel/build and is not transferred to OS3.

## Factory image inventory

Partitions lists the `boot` / `init_boot` / `vendor_boot` artifacts found in
that source set. `0400*` means the creation mode was independently decoded from
a reconstructed kernel associated with that set; `not decoded` means no matching
reconstructed `vmlinux` was available, not that the mode is known to differ.
Policy/group cells describe only artifacts actually found in that set. Except
for the exact `tegu` CP3A system image, factory-set verdicts are **Inconclusive**
because the product-system DAC step is missing; “unsupported” would require
positive contrary evidence, not an absent artifact.

The per-image summary follows.

| Image set | Partitions | Kernel mode | SELinux | `adbd` | Effective DAC | Verdict |
|---|---|---|---|---|---|---|
| **Pixel** | | | | | | |
| Pixel 8a (`akita`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 10 Pro (`blazer`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (3 rows; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 6a (`bluejay`), cp4a.261105.040.a1 | boot/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 9 Pro (`caiman`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 7 Pro (`cheetah`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 9 Pro Fold (`comet`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 11 (`cubs`), cp4a.261105.040.d1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel Tablet (`felix`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 10 (`frankel`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 11 Pro (`grizzly`), cp4a.261105.040.d1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 8 Pro (`husky`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 11 Pro XL (`kodiak`), cp4a.261105.040.d1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 9 Pro XL (`komodo`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 7a (`lynx`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | live same-build chain | **Confirmed (live)** |
| Pixel 10 Pro XL (`mustang`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 6 (`oriole`), cp3a.261005.002.a1 | boot/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 7 (`panther`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 10 Pro Fold (`rango`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 6 Pro (`raven`), cp3a.261005.002.a1 | boot/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 8 (`shiba`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 10a (`stallion`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel Tablet (`tangorpro`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 9a (`tegu`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 9 (`tokay`), cp4a.261105.040.a1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 11 Pro Fold (`yogi`), cp4a.261105.040.d1 | boot/init/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| Pixel 9a (`tegu`), cp3a.261005.005 factory | boot/init/vendor + exact system | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact system `init.rc`: `root:log 0440` | **Confirmed (static)** |
| Pixel 11 family (`cubs`/`grizzly`/`kodiak`/`yogi`), workspace candidate | boot | 0400* | not available | not available | exact product system missing | **Inconclusive** |
| Pixel 9a (`tegu172`), workspace Android 17 candidate | boot | 0400* | not available | not available | exact product system missing | **Inconclusive** |
| **Xiaomi** | | | | | | |
| `brussels`, brussels_global:16/OS3.0.311.0.WDRMIXM:user | boot/vendor | 0400* | absent from parsed ramdisk(s) | absent from parsed ramdisk(s) | exact product system missing | **Inconclusive** |
| `byron` | boot | 0400* | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| `charoite` | boot/vendor | 0400* | allow + `proc_slabinfo` (2 rows; 2 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| `dada`, dada:15/OS3.0.307.0.WOCCNXM:user | boot/vendor | 0400* | absent from parsed ramdisk(s) | absent from parsed ramdisk(s) | exact product system missing | **Inconclusive** |
| `dada_os4` | boot/init/vendor (init from OTA) | 0400* | absent from parsed ramdisk(s) | absent from parsed ramdisk(s) | effective uid-2000 read logged; DAC mechanism incomplete | **Inconclusive** |
| `flourite`, flourite:14/OS3.0.318.0.WPRCNXM:user | boot/vendor | 0400* | absent from parsed ramdisk(s) | absent from parsed ramdisk(s) | exact product system missing | **Inconclusive** |
| `frankel` | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| `hongkong`, hongkong:17/OS4.0.29.0.XFRCN:user | boot/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| `iolite` | boot/vendor | 0400* | absent from parsed ramdisk(s) | absent from parsed ramdisk(s) | exact product system missing | **Inconclusive** |
| `kunzite`, kunzite:15/OS3.0.304.0.WPQCNXM:user | boot/vendor | 0400* | absent from parsed ramdisk(s) | absent from parsed ramdisk(s) | exact product system missing | **Inconclusive** |
| `lapis` | boot/vendor | 0400* | allow + `proc_slabinfo` (2 rows; 2 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| `lhasa` | boot/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| `madrid`, madrid:17/OS4.0.27.0.XEOCN:user | boot/vendor | 0400* | allow + `proc_slabinfo` (1 row; 1 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| `mist`, mist:15/OS3.0.311.0.WPUCNXM:user | boot/vendor | 0400* | absent from parsed ramdisk(s) | absent from parsed ramdisk(s) | exact product system missing | **Inconclusive** |
| `nezha` | boot/vendor | 0400* | absent from parsed ramdisk(s) | absent from parsed ramdisk(s) | exact product system missing | **Inconclusive** |
| `popsicle`, popsicle:16/OS4.0.5.0.XPBCN:user | boot/vendor | 0400* | absent from parsed ramdisk(s) | absent from parsed ramdisk(s) | exact product system missing | **Inconclusive** |
| `pudding` | boot | 0400* | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| `spinel` | boot/vendor | 0400* | allow + `proc_slabinfo` (2 rows; 2 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| `zephyr`, zephyr:13/OS3.0.311.0.WBUMIXM:user | boot/vendor | 0400* | absent from parsed ramdisk(s) | absent from parsed ramdisk(s) | exact product system missing | **Inconclusive** |
| `duchamp`, OS3.0.10.0.WNLMIXM OTA payload | boot/init/vendor | not decoded | allow + `proc_slabinfo` (2 rows; 2 distinct) | 2000/2000 + gid 1007 | exact product system missing | **Inconclusive** |
| **Samsung** | | | | | | |
| Galaxy A15 5G (SM-A1560) | boot/init/vendor (LZ4; decoded) | not decoded | not available | not available | exact product system missing | **Inconclusive** |
| S23 (SM-S911B) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S23 FE Exynos (SM-S711B) | boot | 0400* | absent from parsed ramdisk(s) | absent from parsed ramdisk(s) | exact product system missing | **Inconclusive** |
| S23 FE Snapdragon (SM-S711U1) | boot | not decoded | absent from parsed ramdisk(s) | absent from parsed ramdisk(s) | exact product system missing | **Inconclusive** |
| S23+ (SM-S916B) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S23 Ultra (SM-S918B) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S24 Exynos (SM-S921B) | boot | 0400* | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S24 Snapdragon (SM-S921U1) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S24 FE (SM-S721B) | boot | 0400* | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S24+ Exynos (SM-S926B) | boot | 0400* | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S24+ Snapdragon (SM-S926U1) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S24 Ultra (SM-S928B) | boot | 0400* | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S25 (SM-S931B) | boot | 0400* | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S25 Edge (SM-S937B) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S25 FE (SM-S731B) | boot | 0400* | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S25+ (SM-S936B) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S25 Ultra (SM-S938B) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S26 Exynos (SM-S942B) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S26 Snapdragon (SM-S942U1) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S26+/Edge EUX (SM-S947B) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S26+/Edge Snapdragon (SM-S947U1) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S26 FE (SM-S741B) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |
| S26 Ultra (SM-S948B) | boot | not decoded | no ramdisk policy | not available | exact product system missing | **Inconclusive** |

The table covers 71 relevant factory, OTA and workspace sets. Duplicate
workspace copies already represented by a factory row are not repeated. In the
SELinux column, “row” counts source-image/ramdisk occurrences and “distinct”
counts distinct policy blobs; “absent from parsed ramdisk(s)” is narrower than
“no policy exists on the device.” “No ramdisk policy” means the boot image has no
ramdisk, so it supplies no policy evidence. The `adbd` cell records the compiled
normal privilege-drop path; the alternate `minijail_enter` caveat above still
applies. The `lynx` verdict is based on live runtime evidence, including its
loaded policy, not on static factory artifacts alone. The `tegu` CP3A verdict
uses its exact factory `system.img`; the compiled `adbd` normal-path caveat
still applies.

## Remaining evidence gaps

- Exact product `system.img` files are missing for all audited factory sets
  except Pixel 9a (`tegu`) CP3A.261005.005. Their final `chown root log` /
  `chmod 0440` step cannot be certified offline.
- The affected Xiaomi OS3 set lacks `init_boot.img` and its vendor ramdisk has
  no policy or `adbd`; the OS4 field log cannot fill those OS3 gaps.
- The A1560 init/vendor pair has no policy or `adbd`; its binary `init` prevents
  init-rule inspection from the available ramdisk content.
- Some factory kernels have no matching reconstructed `vmlinux`; their mode
  cells remain “not decoded.” A shared workspace candidate is not silently
  substituted for a different factory kernel.
- No audited factory set has positive contrary access evidence. “Unsupported”
  would require an effective deny or a complete exact init configuration that
  leaves shell without read access; absence is **Inconclusive**.
