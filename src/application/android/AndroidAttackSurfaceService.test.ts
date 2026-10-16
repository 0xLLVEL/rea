import { describe, expect, it } from "vitest";

import { projectAndroidAttackSurfaceEvidence } from "./AndroidAttackSurfaceService.js";

describe("projectAndroidAttackSurfaceEvidence", () => {
  it("wraps the projection in derived analyst-inference Evidence", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: "io.example",
      target_sdk: "30",
      permissions: [],
      components: [],
      component_coverage: "complete",
    });
    if (!result.ok) throw result.error;
    expect(result.value.operation).toBe("project_android_attack_surface");
    expect(result.value.confidence).toBe("derived");
  });

  it("rejects unknown coverage values as input errors", () => {
    const result = projectAndroidAttackSurfaceEvidence({
      package_name: null,
      target_sdk: null,
      permissions: [],
      components: [],
      component_coverage: "everything",
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });
});
