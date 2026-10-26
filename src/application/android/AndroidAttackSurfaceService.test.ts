import { describe, expect, it } from "vitest";

import { projectAndroidAttackSurfaceEvidence } from "./AndroidAttackSurfaceService.js";

describe("projectAndroidAttackSurfaceEvidence", () => {
  it("wraps the projection in derived analyst-inference Evidence", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      components: [],
      component_coverage: "complete",
    });
    if (!result.ok) throw result.error;
    expect(result.value.operation).toBe("project_android_attack_surface");
    expect(result.value.confidence).toBe("derived");
    expect(result.value.parameters).toMatchObject({
      package_name: "io.example",
      component_coverage: "complete",
      component_count: 0,
    });
  });

  it("retains the selected declarations the projection drops from its result", () => {
    const unexported = {
      kind: "provider",
      declared_name: ".Files",
      name: "io.example.Files",
      exported: false,
      exported_default: null,
      permission: null,
      permission_source: "unknown",
      intent_filter_count: 0,
      actions: [],
      categories: [],
      foreground_service_type: null,
      authorities: ["io.example.files"],
      target_activity: null,
    } as const;
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      components: [unexported],
      component_coverage: "partial",
    });
    if (!result.ok) throw result.error;
    expect(result.value.normalized_result).toMatchObject({
      exported_without_permission: [],
    });
    expect(result.value.parameters).toMatchObject({
      component_count: 1,
      components: [unexported],
    });
  });

  it("rejects unused declaration facts instead of ignoring them", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      target_sdk: "30",
      permissions: [],
      components: [],
      component_coverage: "complete",
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });

  it("rejects unknown coverage values as input errors", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: null,
      components: [],
      component_coverage: "everything",
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });
});
