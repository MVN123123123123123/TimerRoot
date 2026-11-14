# Building

TimerRoot has two build products: the Android app (`TimerRoot.apk`) and the
native exploit (`timer`). The app is a normal Gradle project; the exploit is
built with the NDK. For installing the finished artifacts see
[Installation](installation.md).

## Requirements

- **JDK 17.** AGP 8.7.3 cannot run on newer JDKs (the `JdkImageTransform` jlink
  step fails on JDK 21+), so the CI pins 17.
- **Android SDK platform 36** and **build-tools 36.0.0**. `compileSdk` and
  `targetSdk` are 36; AGP 8.7's default build-tools 35 cannot compile against
  platform 36.
- **Gradle 9.6**. The wrapper is gitignored, so install
  Gradle. 9.6 is recommended, but i uses 8.9.3.
- **NDK 29.0.14206865** (or another recent NDK) with the
  `aarch64-linux-android21` clang, for the exploit only.
- **PowerShell 7+** for the Gradle-free `scripts/build.ps1` path.
- **Shizuku-API checkout** for the Gradle-free path.

## Build the exploit binary

The source in `p7a/timer_p7a.c` builds statically against the NDK. This is the
exact command the release workflow uses:

```bash
CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"
"$CC" -O2 -ffunction-sections -fdata-sections \
  -Wl,--gc-sections -g -static -pthread \
  -o timer p7a/timer_p7a.c
```

The release workflow sanity-checks the result before shipping it:

```bash
file timer
strings timer | grep -c 'target=lynx'   # must be >= 1
stat -c %s timer                        # must be > 100000 bytes
```

Then place it at `app/src/main/assets/timer` (the workflow copies it there) or
install it on a device yourself.

### Install at runtime

At runtime the app can also fetch the latest release asset with **Settings ->
Exploit -> Download exploit**. That does not require a local build of the
binary; it still needs a matching profile in `conf/`.

## Build the app with Gradle

```bash
gradle assembleDebug
```

or, for a release APK:

```bash
gradle assembleRelease
```

Notes:

- The root `conf/` tree is copied into the build as `assets/conf/**` by the
  `syncConfAssets` task, which is wired to `preBuild` and every
  `merge*Assets` task. The APK therefore always carries the profiles from the
  repository root; nothing needs to be copied by hand.
- `applicationId` is `com.kpgc.timerroot`, `minSdk` 30, `targetSdk` 36 and
  `compileSdk` 36. The version lives in `app/build.gradle`.
- Shizuku's API and provider come from Maven
  (`dev.rikka.shizuku:api:13.1.5`,
  `dev.rikka.shizuku:provider:13.1.5`). No Shizuku-API checkout is needed.
- A Gradle release build is unsigned. Sign it with `apksigner`; see below.

## Sign a Gradle build

The release workflow signs `app/build/outputs/apk/release/*-unsigned.apk`:

```bash
BT="$ANDROID_SDK_ROOT/build-tools/36.0.0"
"$BT/zipalign" -f -p 4 unsigned.apk aligned.apk
"$BT/apksigner" sign --ks release.jks --ks-pass "pass:$KS_PASS" \
  --key-pass "pass:$KEY_PASS" --ks-key-alias "$ALIAS" \
  --out TimerRoot.apk aligned.apk
"$BT/apksigner" verify --print-certs TimerRoot.apk
```

Android refuses to update an install signed with a different key. Use the same
key as the installed app, or uninstall it first.

## Gradle-free build

For a build with only the Android SDK, `javac`, `d8`, `aapt2` and
`apksigner` (Windows/PowerShell):

```powershell
git clone https://github.com/RikkaApps/Shizuku-API
scripts/build.ps1 -Sdk "C:\Users\<you>\AppData\Local\Android\Sdk" -ShizukuApi ..\Shizuku-API
```

The script:

- compiles Shizuku's API, shared and provider sources, plus the app sources,
  against `android.jar` with `javac`;
- generates AIDL bindings and dexes everything with `d8` (`--min-api 30`);
- packages resources, the manifest, the prebuilt `assets/timer` and
  `conf/**` as `assets/conf/**` with `aapt2`;
- zipaligns and signs with a generated debug keystore.

Parameters: `-Sdk`, `-ShizukuApi`, `-Out`, `-VersionCode` (default 40) and
`-VersionName` (default `0.40`). Output is `build/TimerRoot.apk`.


## CI release workflow

`.github/workflows/release-timer.yml` runs on `main` pushes that touch the
exploit source, `conf/**`, app sources/resources/AIDL/manifest, Gradle files or
the workflow itself, and on manual dispatch. It:

1. sets up JDK 17, Gradle 9.6 and the SDK packages (`platforms;android-36`,
   `build-tools;36.0.0`, NDK 29.0.14206865);
2. builds the static arm64 exploit and copies it to
   `app/src/main/assets/timer`;
3. builds the release APK with Gradle;
4. zipaligns and signs it with the repository secrets when
   `KEYSTORE_BASE64` is set, otherwise with a throwaway key;
5. uploads `timer`, `timer_p7a`, `timer_p7a.c` and `TimerRoot.apk` to the
   fixed release tag `bingchiling`.

The tag is fixed so the app's download URL never changes; only the assets are
replaced. The app fetches
`https://github.com/MVN123123123123123/TimerRoot/releases/download/bingchiling/timer`.

## Adding a kernel profile

Add one `conf/<release>.conf` (or `conf/samsung/*.conf`, or `conf/dirty/*.conf`)
and rebuild the app; the asset sync picks it up automatically. No Java or C
change is needed. The profile must be derived from the exact factory
`boot.img`/`vendor_boot.img`; use [SKILL.md](../SKILL.md) for the F1-F16
procedure and record the evidence in [PORT_LOG.md](../PORT_LOG.md).

Before shipping a profile, run its parser and invariants:

```bash
timer --conf conf/<release>.conf target
timer --conf conf/<release>.conf selfcheck
```

`selfcheck` exits non-zero on any invariant failure and never touches the
kernel. A wrong banner must be refused, not fall through to another profile.

## Verification

For the exploit path, F7-F11 (`target`, `ids`, `probe`, `leak`, verify) run in
`qemu-system-aarch64` against the factory kernel; F12/F13 (SELinux and
KernelSU) and F15/F16 (hardware, app) need a device. The harness and the
per-profile gate record are in [PORT_LOG.md](../PORT_LOG.md).
