# Unsupported profiles — do not run these

Every profile here is complete and passes F1–F10, but the factory kernel's
embedded config lacks `CONFIG_POSIX_CPU_TIMERS_TASK_WORK` (and
`HAVE_POSIX_CPU_TIMERS_TASK_WORK`). Without it, a fired posix CPU timer is
expired inline from the tick/IRQ path and `posix_cpu_timers_exit{,_group}` only
performs a plain `cleanup_timers()` dequeue, so the exit path never runs
`rb_erase` on the node the spray reclaimed. The result is deterministic:

```
free_seen=1 burst hit=1 ... write mode=zero ... left child uid=2000   (x6)
```

The reclaim succeeds, the write is issued, the uid never changes. No conf
change, constant re-derivation, plant mode or retry helps: it would take a
different vulnerability.

| profile | device |
|---|---|
| `5.10.236-…-ab14313284` | garnet (Redmi Note 13 Pro 5G / POCO X6 5G) |
| `5.15.194-…-ab15212794` | vermeer (Redmi K70 / POCO F6 Pro) |
| `5.15.194-…-ab15936612` | zircon (Redmi Note 13 Pro+ 5G) |
| `5.15.194-…-ab15004895` | zephyr (Redmi Note 17 4G) |
| `samsung-a15xzh-5.15.189` | Galaxy A15 5G (a15xzh) |
| `samsung-s23-5.15.197` | Galaxy S23 |
| `samsung-s23fe-5.10.240` | Galaxy S23 FE |

These files are deliberately **not** packaged into the APK (`app/build.gradle`
excludes this directory) and **not** picked up by a `mass.py` sweep, so nobody
picks one from the app or a default run and waits 15 minutes for six failed
plants.

To reproduce the block deliberately — for the evidence of record, or to
re-check a kernel after a vendor update — name the file explicitly:

```bash
python3 timerroot-port/work/qemu/mass.py --include-unsupported \
  --only 5.15.194-android13-8-00019-gf4321180a397-ab15212794
```

`mkinitramfs.sh` still copies these confs into the test initramfs for exactly
that reason; the QEMU image is a harness, not a shipped artifact.

If a vendor kernel with one of these release strings is ever rebuilt with
`CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y`, re-derive its conf and move it back to
`conf/` (or `conf/samsung/` for the Samsung ones). The gate is the extracted
config, never the kernel version alone.
