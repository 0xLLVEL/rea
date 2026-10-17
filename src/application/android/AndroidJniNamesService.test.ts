import { describe, expect, it } from "vitest";

import { projectAndroidJniNamesEvidence } from "./AndroidJniNamesService.js";

describe("projectAndroidJniNamesEvidence", () => {
  it("wraps the projection in derived analyst-inference Evidence", () => {
    const result = projectAndroidJniNamesEvidence({
      class_name: "pkg.Cls",
      methods: [{ method_name: "nativeInit", dex_descriptor: "()V" }],
    });
    if (!result.ok) throw result.error;
    expect(result.value.operation).toBe("project_android_jni_names");
    expect(result.value.confidence).toBe("derived");
    expect(result.value.normalized_result).toMatchObject({
      class_name: "pkg.Cls",
      coverage: "complete",
    });
  });

  it("rejects empty method lists as input errors", () => {
    const result = projectAndroidJniNamesEvidence({
      class_name: "pkg.Cls",
      methods: [],
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  });
});
