import { z } from "zod";

import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisProtocolError } from "../../domain/analysisErrorCore.js";
import {
  androidAttackSurfaceInputSchema,
  projectAttackSurface,
} from "../../domain/android/androidAttackSurface.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import { ANDROID_APPLICATION_PROVIDER } from "../InvestigationProviders.js";
import {
  requestInputError,
  workflowInputError,
} from "../workflowInputError.js";

const OPERATION = "project_android_attack_surface" as const;

/** Project structural attack-surface facts from caller-selected package declarations. */
export const projectAndroidAttackSurfaceEvidence = (
  rawInput: unknown,
): Result<Evidence, AnalysisError> => {
  const parsed = androidAttackSurfaceInputSchema.safeParse(rawInput);
  if (!parsed.success)
    return err(requestInputError(OPERATION, parsed.error, rawInput));
  try {
    const result = projectAttackSurface(parsed.data);
    return ok(
      createEvidence(undefined, ANDROID_APPLICATION_PROVIDER, {
        predicateType: "rea.android-attack-surface",
        operation: OPERATION,
        parameters: {
          package_name: parsed.data.package_name,
          component_count: parsed.data.components.length,
        },
        result: jsonValueSchema.parse(result),
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
    return err(
      cause instanceof TypeError || cause instanceof z.ZodError
        ? workflowInputError(OPERATION, cause)
        : new AnalysisProtocolError(
            "Android attack-surface projection produced an invalid result",
            { cause },
          ),
    );
  }
};
