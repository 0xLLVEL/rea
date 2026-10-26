import { describe, expect, it } from "vitest";

import { androidManifestComponentSchema } from "./androidAnalysis.js";
import {
  ANDROID_ATTACK_SURFACE_UNKNOWNS,
  coverageUnknown,
  projectAttackSurface,
  providerOverrideUnknown,
  UNGUARDED_COMPONENT_NOTE,
  UNRESOLVED_GUARD_NOTE,
  unresolvedGuardUnknown,
} from "./androidAttackSurface.js";

type Component = typeof androidManifestComponentSchema._output;

const component = (
  overrides: Partial<Component> & Pick<Component, "kind" | "name">,
): Component => ({
  declared_name: overrides.name,
  exported: null,
  exported_default: null,
  permission: null,
  permission_source: "none",
  permission_overrides: "none",
  intent_filter_count: 0,
  actions: [],
  categories: [],
  foreground_service_type: null,
  authorities: null,
  target_activity: null,
  ...overrides,
});

const components: Component[] = [
  component({
    kind: "activity",
    name: "io.example.Main",
    exported: true,
    actions: ["android.intent.action.MAIN"],
    intent_filter_count: 1,
  }),
  component({
    kind: "service",
    name: "io.example.Sync",
    exported_default: true,
    permission: "android.permission.BIND_JOB_SERVICE",
    permission_source: "component",
    foreground_service_type: "shortService",
    actions: ["SYNC"],
    intent_filter_count: 1,
  }),
  component({
    kind: "receiver",
    name: "io.example.Sms",
    exported: true,
    actions: ["android.provider.Telephony.SMS_RECEIVED"],
    intent_filter_count: 1,
  }),
  component({
    kind: "provider",
    name: "io.example.Files",
    exported: false,
    authorities: ["io.example.files"],
  }),
  component({
    kind: "activity",
    name: "io.example.Ambiguous",
    declared_name: ".Ambiguous",
  }),
  component({
    kind: "provider",
    name: "io.example.Bridge",
    exported: true,
    permission_overrides: "read-write",
    authorities: ["io.example.bridge"],
  }),
  component({
    kind: "provider",
    name: "io.example.Open",
    exported: true,
    authorities: ["io.example.open"],
  }),
  component({
    kind: "activity",
    name: "io.example.Tokenized",
    exported: true,
    permission_source: "unknown",
  }),
  component({
    kind: "service",
    name: "io.example.Delegated",
    exported: true,
    permission: "io.example.permission.GUARD",
    permission_source: "application",
  }),
];

const facts = {
  package_name: "io.example",
  components,
  component_coverage: "complete" as const,
};

describe("projectAttackSurface", () => {
  it("separates unguarded, guarded and guard-unknown components", () => {
    const result = projectAttackSurface(facts);
    expect(result.coverage).toBe("complete");
    expect(
      result.exported_without_permission.map(
        (finding) => finding.resolved_name,
      ),
    ).toEqual(["io.example.Main", "io.example.Sms", "io.example.Open"]);
    expect(
      result.exported_without_permission.map((finding) => finding.note),
    ).toEqual([
      UNGUARDED_COMPONENT_NOTE,
      UNGUARDED_COMPONENT_NOTE,
      UNGUARDED_COMPONENT_NOTE,
    ]);
    expect(
      result.exported_without_permission.map(
        (finding) => finding.permission_source,
      ),
    ).toEqual(["none", "none", "none"]);
    expect(
      result.exported_guarded.map((finding) => [
        finding.permission,
        finding.permission_source,
      ]),
    ).toEqual([
      ["android.permission.BIND_JOB_SERVICE", "component"],
      ["io.example.permission.GUARD", "application"],
    ]);
    expect(result.exported_guarded.map((f) => f.exported_source)).toEqual([
      "implicit",
      "explicit",
    ]);
    expect(
      result.exported_guard_unknown.map((finding) => [
        finding.resolved_name,
        finding.permission_source,
        finding.permission_overrides,
        finding.note,
      ]),
    ).toEqual([
      ["io.example.Bridge", "none", "read-write", expect.any(String)],
      ["io.example.Tokenized", "unknown", "none", UNRESOLVED_GUARD_NOTE],
    ]);
    expect(result.exported_guard_unknown[0]?.note).not.toBe(
      UNGUARDED_COMPONENT_NOTE,
    );
    expect(result.export_unknown.map((f) => f.resolved_name)).toEqual([
      "io.example.Ambiguous",
    ]);
    expect(result.export_unknown.map((f) => f.exported_source)).toEqual([
      "unknown",
    ]);
    expect(result.foreground_service_types).toEqual(["shortService"]);
    expect(result.provider_authorities).toEqual([
      "io.example.bridge",
      "io.example.files",
      "io.example.open",
    ]);
    expect(
      result.intent_action_index.find(
        (entry) => entry.action === "android.provider.Telephony.SMS_RECEIVED",
      )?.components,
    ).toEqual(["io.example.Sms"]);
  });

  it("explains unresolved guards, overrides and incomplete coverage", () => {
    const result = projectAttackSurface({
      ...facts,
      component_coverage: "partial",
    });
    expect(result.unknowns).toEqual([
      ...ANDROID_ATTACK_SURFACE_UNKNOWNS,
      unresolvedGuardUnknown(1),
      providerOverrideUnknown(1),
      coverageUnknown("partial"),
    ]);
  });

  it("reports an exported provider as unguarded only without projected overrides", () => {
    const result = projectAttackSurface({
      ...facts,
      components: [
        component({
          kind: "provider",
          name: "io.example.Open",
          exported: true,
        }),
        component({
          kind: "provider",
          name: "io.example.Stale",
          exported: true,
          permission_overrides: "unknown",
        }),
      ],
    });
    expect(
      result.exported_without_permission.map((f) => f.resolved_name),
    ).toEqual(["io.example.Open"]);
    expect(result.exported_guard_unknown.map((f) => f.resolved_name)).toEqual([
      "io.example.Stale",
    ]);
    expect(result.unknowns).toContain(providerOverrideUnknown(1));
  });
});
