import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisProtocolError } from "../../domain/analysisErrorCore.js";
import {
  androidAttackSurfaceInputSchema,
  projectAttackSurface,
} from "../../domain/android/androidAttackSurface.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";
import { ANDROID_APPLICATION_PROVIDER } from "../../domain/investigationProviders.js";

const OPERATION = "project_android_attack_surface" as const;

/** Project structural attack-surface facts from caller-selected package declarations. */
export const projectAndroidAttackSurfaceEvidence = (
  rawInput: unknown,
): Result<Evidence, AnalysisError> => {
  const parsed = androidAttackSurfaceInputSchema.safeParse(rawInput);
  if (!parsed.success)
    return err(
      analysisInputErrorFromIssues(OPERATION, parsed.error.issues, rawInput, {
        cause: parsed.error,
      }),
    );
  try {
    const result = projectAttackSurface(parsed.data);
    return ok(
      createEvidence(undefined, ANDROID_APPLICATION_PROVIDER, {
        predicateType: "rea.android-attack-surface",
        operation: OPERATION,
        parameters: {
          package_name: parsed.data.package_name,
          component_coverage: parsed.data.component_coverage,
          component_count: parsed.data.components.length,
          // The selection stays readable even where the projection drops
          // fields (permission_source) or whole non-exported components.
          components: parsed.data.components,
        },
        result,
        rawResult: null,
        confidence: "derived",
        authority: "analyst-inference",
        environment: null,
        limitations: [
          "Findings rank static declarations from caller-selected facts; they do not read an APK or establish exploitability.",
        ],
        evidenceLinks: [],
      }),
    );
  } catch (cause: unknown) {
    // Input already parsed against the same schema; a failure here is the
    // projection's own invariant, never caller-supplied data.
    return err(
      new AnalysisProtocolError(
        "Android attack-surface projection produced an invalid result",
        { cause },
      ),
    );
  }
};
