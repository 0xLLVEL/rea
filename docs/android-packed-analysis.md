# Packed and split APK analysis playbook

Static analysis ends where packers begin. A packed APK ships encrypted DEX
behind a stub loader: JADX returns thin wrappers, methods report
`body_status: "not_available"`, and class counts look small for the APK size.
This playbook composes existing REA tools into one static → runtime → static
loop. It adds no new tool; each step names its own authority and cleanup.

## 1. Detect packing statically

Run the Fase 1–3 static chain first:

```sh
rea inspect-android-package /targets/Example.apk
rea project-android-attack-surface '{"package_name": "com.example", "target_sdk": "33", "permissions": [], "components": [], "component_coverage": "complete"}'
```

Pack signals: `body_status: "not_available"` on app classes, a custom
`Application` subclass with `attachBaseContext`, few DEX classes against a
large APK, and a native loader library in `lib/<abi>/`. Record these as the
reason runtime work is needed. If the APK is not packed, stop here.

## 2. Acquire the full split set

An installed app may span base + splits. Pull the whole set; REA never
guesses which split matters:

```sh
rea list-adb-devices
rea pull-adb-package emulator-5554 com.example.app --output-directory /tmp/acq
rea inspect-android-package /tmp/acq/com.example.app/base.apk
```

`pm path` enumerates every installed split and each file is digested
(see `docs/adb-device-analysis.md`). Split-manifest consistency checks ride
with the open bundletool lanes; until they land, analyze each APK separately
and keep per-file digests in Evidence.

## 3. Dump decrypted DEX on an isolated emulator

Use a caller-supplied emulator and frida-server. REA installs neither; push
the server explicitly and install the APK as a device-mutating step:

```sh
rea push-adb-file emulator-5554 /tools/frida-server /data/local/tmp/frida-server
rea install-adb-package emulator-5554 /tmp/app.apk --replace
```

Spawn paused, load a caller-authored dump script (its SHA-256 is recorded,
its source is not stored), resume, then pull the dump:

```sh
rea start-adb-app emulator-5554 com.example.app
rea read-adb-logcat emulator-5554 --count 200
rea pull-adb-file emulator-5554 /data/local/tmp/dump.dex --output-directory /tmp/dump
rea stop-adb-app emulator-5554 com.example.app
rea uninstall-adb-package emulator-5554 com.example.app
```

Frida sessions, message budgets (16 MiB), spawn-paused semantics and cleanup
follow `docs/frida-instrumentation.md`. REA never kills the target; a paused
spawn stays paused until script cleanup or detach confirms release.

## 4. Re-analyze the dump statically

Feed dumped DEX/APK back through the static chain and link provenance:

`APK sha256 → Frida script sha256 → dumped DEX sha256 → second JADX result`.

Anti-frida, anti-emulator and integrity checks can fail the dump; report that
as `unknown`, never as a complete unpack. `RegisterNatives` bindings,
reflection and dynamic loading stay outside the static inventory even after a
successful dump. Signature verification is `not_performed` throughout.
