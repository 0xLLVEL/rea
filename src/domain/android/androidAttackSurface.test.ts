import { describe, expect, it } from "vitest";

import { projectManifestComponents } from "./androidManifestComponents.js";
import { projectAttackSurface } from "./androidAttackSurface.js";

const MANIFEST = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="io.example">
  <application>
    <activity android:name=".Main" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
      </intent-filter>
    </activity>
    <service android:name=".Sync" android:permission="android.permission.BIND_JOB_SERVICE" android:foregroundServiceType="shortService">
      <intent-filter><action android:name="SYNC" /></intent-filter>
    </service>
    <receiver android:name=".Sms" android:exported="true">
      <intent-filter><action android:name="android.provider.Telephony.SMS_RECEIVED" /></intent-filter>
    </receiver>
    <provider android:name=".Files" android:authorities="io.example.files" android:exported="false" />
  </application>
</manifest>`;

const facts = (targetSdk: string) => {
  const projected = projectManifestComponents({
    manifestText: MANIFEST,
    manifestStatus: "complete",
    packageName: "io.example",
    targetSdk,
  });
  return {
    package_name: "io.example",
    target_sdk: targetSdk,
    permissions: ["android.permission.INTERNET"],
    components: [...projected.components],
    component_coverage: projected.coverage,
  };
};

describe("projectAttackSurface", () => {
  it("separates unguarded, guarded and unknown exports with an action index", () => {
    const result = projectAttackSurface(facts("30"));
    expect(result.coverage).toBe("complete");
    expect(
      result.exported_without_permission.map((f) => f.resolved_name),
    ).toEqual(["io.example.Main", "io.example.Sms"]);
    expect(result.exported_guarded.map((f) => f.permission)).toEqual([
      "android.permission.BIND_JOB_SERVICE",
    ]);
    expect(result.foreground_service_types).toEqual(["shortService"]);
    expect(result.provider_authorities).toEqual(["io.example.files"]);
    expect(
      result.intent_action_index.find(
        (entry) => entry.action === "android.provider.Telephony.SMS_RECEIVED",
      )?.components,
    ).toEqual(["io.example.Sms"]);
    expect(result.unknowns.join(" ")).toContain("protection levels");
  });

  it("propagates partial component coverage instead of claiming absence", () => {
    const result = projectAttackSurface({
      ...facts("33"),
      component_coverage: "partial",
    });
    expect(result.coverage).toBe("partial");
    expect(result.unknowns.join(" ")).toContain(
      "absence of a finding is unknown",
    );
  });
});
