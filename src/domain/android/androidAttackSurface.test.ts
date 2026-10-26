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
  component({
    kind: "provider",
    name: "io.example.Bridge",
    exported: true,
    authorities: ["io.example.bridge"],
  }),
  component({
    kind: "activity",
    name: "io.example.Tokenized",
    exported: true,
    permission: null,
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
  it("separates unguarded, guarded and unknown guards with an action index", () => {
    const result = projectAttackSurface(facts);
    expect(result.coverage).toBe("complete");
    expect(
      result.exported_without_permission.map((f) => f.resolved_name),
    ).toEqual(["io.example.Main", "io.example.Sms"]);
    expect(
      result.exported_without_permission.map((f) => f.exported_source),
    ).toEqual(["explicit", "explicit"]);
    expect(
      result.exported_without_permission.map((f) => f.permission_source),
    ).toEqual(["none", "none"]);
    expect(
      result.exported_guarded.map((f) => [f.permission, f.permission_source]),
    ).toEqual([
      ["android.permission.BIND_JOB_SERVICE", "component"],
      ["io.example.permission.GUARD", "application"],
    ]);
    expect(result.exported_guarded.map((f) => f.exported_source)).toEqual([
      "implicit",
      "explicit",
    ]);
    expect(
      result.exported_guard_unknown.map((f) => [
        f.resolved_name,
        f.permission_source,
      ]),
    ).toEqual([
      ["io.example.Bridge", "none"],
      ["io.example.Tokenized", "unknown"],
    ]);
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
    ]);
    expect(
      result.intent_action_index.find(
        (entry) => entry.action === "android.provider.Telephony.SMS_RECEIVED",
      )?.components,
    ).toEqual(["io.example.Sms"]);
    expect(result.unknowns.join(" ")).toContain("protection levels");
    expect(result.unknowns.join(" ")).toContain(
      "they stay guard-unknown rather than unguarded",
    );
    expect(result.unknowns.join(" ")).toContain(
      "operation-specific readPermission/writePermission overrides are not projected",
    );
  });

  it("keeps provable absence of a guard out of the guard-unknown bucket", () => {
    const result = projectAttackSurface({
      ...facts,
      components: [
        component({
          kind: "activity",
          name: "io.example.Plain",
          exported: true,
        }),
        component({
          kind: "provider",
          name: "io.example.Guarded",
          exported: true,
          permission: "io.example.permission.PROVIDER",
          permission_source: "component",
        }),
      ],
    });
    expect(
      result.exported_without_permission.map((f) => f.resolved_name),
    ).toEqual(["io.example.Plain"]);
    expect(result.exported_guarded.map((f) => f.resolved_name)).toEqual([
      "io.example.Guarded",
    ]);
    expect(result.exported_guard_unknown).toEqual([]);
    expect(result.unknowns.join(" ")).not.toContain("readPermission");
  });

  it("propagates partial component coverage instead of claiming absence", () => {
    const result = projectAttackSurface({
      ...facts,
      component_coverage: "partial",
    });
    expect(result.coverage).toBe("partial");
    expect(result.unknowns.join(" ")).toContain(
      "absence of a finding is unknown",
    );
  });
});
