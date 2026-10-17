import { describe, expect, it } from "vitest";

import { projectManifestComponents } from "./androidManifestComponents.js";

const MANIFEST = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="io.example" android:versionCode="1">
  <application>
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
      <meta-data android:name="note" android:value="x" />
    </activity>
    <service android:name="io.example.Sync" android:permission="android.permission.BIND_JOB_SERVICE" android:foregroundServiceType="shortService">
      <intent-filter>
        <action android:name="SYNC" />
      </intent-filter>
    </service>
    <receiver android:name="Boot" android:enabled="false">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
      </intent-filter>
    </receiver>
    <provider android:name=".Files" android:authorities="io.example.files" android:grantUriPermissions="true" android:exported="false" />
  </application>
</manifest>`;

describe("projectManifestComponents", () => {
  it("projects exported, permission, intent and provider facts with resolved names", () => {
    const result = projectManifestComponents({
      manifestText: MANIFEST,
      manifestStatus: "complete",
      packageName: "io.example",
      targetSdk: "30",
    });
    expect(result.coverage).toBe("complete");
    expect(result.components).toHaveLength(4);
    expect(result.components[0]).toMatchObject({
      kind: "activity",
      name: ".MainActivity",
      resolved_name: "io.example.MainActivity",
      exported: true,
      exported_source: "explicit",
      intent_filters: [
        {
          actions: ["android.intent.action.MAIN"],
          categories: ["android.intent.category.LAUNCHER"],
        },
      ],
      meta_data: ["note"],
    });
    expect(result.components[1]).toMatchObject({
      kind: "service",
      exported: true,
      exported_source: "implicit",
      permission: "android.permission.BIND_JOB_SERVICE",
      foreground_service_type: "shortService",
    });
    expect(result.components[2]).toMatchObject({
      kind: "receiver",
      resolved_name: "io.example.Boot",
      enabled: false,
    });
    expect(result.components[3]).toMatchObject({
      kind: "provider",
      authorities: "io.example.files",
      grant_uri_permissions: true,
      exported: false,
    });
  });

  it("marks implicit export unknown when targetSdk 31+ omits android:exported", () => {
    const result = projectManifestComponents({
      manifestText: MANIFEST,
      manifestStatus: "complete",
      packageName: "io.example",
      targetSdk: "33",
    });
    expect(result.components[1]?.exported).toBeNull();
    expect(result.components[1]?.exported_source).toBe("unknown");
    expect(result.unknowns.join(" ")).toContain("android:exported");
  });

  it("keeps malformed manifests as unknown instead of failing", () => {
    const result = projectManifestComponents({
      manifestText: "not xml",
      manifestStatus: "complete",
      packageName: "io.example",
      targetSdk: "30",
    });
    expect(result.coverage).toBe("unknown");
    expect(result.components).toEqual([]);
  });

  it("marks partial decoded manifests as partial coverage", () => {
    const result = projectManifestComponents({
      manifestText: MANIFEST,
      manifestStatus: "partial",
      packageName: "io.example",
      targetSdk: "30",
    });
    expect(result.coverage).toBe("partial");
  });
});
