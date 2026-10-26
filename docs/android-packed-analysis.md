# Packed and split APK analysis playbook

Static analysis ends where packers begin. A packed APK ships encrypted DEX
behind a stub loader: JADX returns thin wrappers, methods report
`body_status: "not_available"`, and class counts look small for the APK size.
This playbook covers static pack detection and acquiring the complete split set
for such a target. It adds no new tool, and it stops before decrypting or
recovering protected code: `CONTRIBUTING.md` excludes purpose-built workflows
that defeat packing protections and automatically recover protected code, and
that boundary covers documentation too.

## 1. Detect packing statically

Run the static chain first:

```sh
rea inspect-android-package /targets/Example.apk
rea inspect-android-class /targets/Example.apk com.example.MainActivity
rea project-android-attack-surface '{"package_name": "com.example", "components": [], "component_coverage": "complete"}'
```

Pack signals: `body_status: "not_available"` on app classes, a custom
`Application` subclass with `attachBaseContext`, few DEX classes against a
large APK, and a native loader library in `lib/<abi>/`. Record these as the
reason the static inventory is incomplete. If the APK is not packed, continue
with the ordinary static workflow.

## 2. Acquire the full split set

An installed app may span base + splits. Pull the whole set; REA never
guesses which split matters:

```sh
rea list-adb-devices
rea pull-adb-package emulator-5554 com.example.app --output-directory /tmp/acq
rea inspect-android-package /tmp/acq/com.example.app/base.apk
```

`pm path` enumerates every installed split and each file is digested (see
`docs/adb-device-analysis.md`). Split-manifest consistency checks ride
with the open bundletool lanes; until they land, analyze each APK separately
and keep per-file digests in Evidence.

## 3. Report the gap instead of closing it

The static inventory of a packed APK is `partial`, and
`project_android_attack_surface` propagates that coverage instead of claiming
absence. Report the pack signals, the split set you acquired, and the classes
you could not read. Keep the offset between the static view and the real
implementation explicit rather than filling it in.

REA does document the instrumentation surface it does have, including Frida
sessions with caller-authored scripts, in
[frida-instrumentation.md](frida-instrumentation.md). Whether to attach to a
target at all, and what to run, stays your decision and your authority: no REA
playbook prescribes recovering protected code.
