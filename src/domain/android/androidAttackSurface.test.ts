import { describe, expect, it } from "vitest";

import { androidManifestComponentSchema } from "./androidAnalysis.js";
import { projectAttackSurface } from "./androidAttackSurface.js";

type Component = typeof androidManifestComponentSchema._output;

const component = (
  overrides: Partial<Component> & Pick<Component, "kind" | "name">,
): Component => ({
  declared_name: overrides.name,
  exported: null,
  exported_default: null,
  permission: null,
  permission_source: "none",
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
];

const facts = (targetSdk: string) => ({
  package_name: "io.example",
  target_sdk: targetSdk,
  permissions: ["android.permission.INTERNET"],
  components,
  component_coverage: "complete" as const,
});

describe("projectAttackSurface", () => {
  it("separates unguarded, guarded and unknown exports with an action index", () => {
    const result = projectAttackSurface(facts("30"));
    expect(result.coverage).toBe("complete");
    expect(
      result.exported_without_permission.map((f) => f.resolved_name),
    ).toEqual(["io.example.Main", "io.example.Sms"]);
    expect(
      result.exported_without_permission.map((f) => f.exported_source),
    ).toEqual(["explicit", "explicit"]);
    expect(result.exported_guarded.map((f) => f.permission)).toEqual([
      "android.permission.BIND_JOB_SERVICE",
    ]);
    expect(result.exported_guarded.map((f) => f.exported_source)).toEqual([
      "implicit",
    ]);
    expect(result.export_unknown.map((f) => f.resolved_name)).toEqual([
      "io.example.Ambiguous",
    ]);
    expect(result.export_unknown.map((f) => f.exported_source)).toEqual([
      "unknown",
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
