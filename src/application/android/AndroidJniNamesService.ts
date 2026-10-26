import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisProtocolError } from "../../domain/analysisErrorCore.js";
import {
  androidJniNamesInputSchema,
  projectJniNames,
} from "../../domain/android/androidJniNames.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";
import { ANDROID_APPLICATION_PROVIDER } from "../../domain/investigationProviders.js";

const OPERATION = "project_android_jni_names" as const;

/** Project expected JNI/JNA symbol names for caller-selected DEX methods. */
export const projectAndroidJniNamesEvidence = (
  rawInput: unknown,
): Result<Evidence, AnalysisError> => {
  const parsed = androidJniNamesInputSchema.safeParse(rawInput);
  if (!parsed.success)
    return err(
      analysisInputErrorFromIssues(OPERATION, parsed.error.issues, rawInput, {
        cause: parsed.error,
      }),
    );
  try {
    const result = projectJniNames(parsed.data);
    return ok(
      createEvidence(undefined, ANDROID_APPLICATION_PROVIDER, {
        predicateType: "rea.android-jni-names",
        operation: OPERATION,
        parameters: {
          class_name: parsed.data.class_name,
          method_count: parsed.data.methods.length,
        },
        result,
        rawResult: null,
        confidence: "derived",
        authority: "analyst-inference",
        environment: null,
        limitations: [
          "Expected names are string projections from caller-selected declarations; they do not read an APK or native library.",
        ],
        evidenceLinks: [],
      }),
    );
  } catch (cause: unknown) {
    // Input already parsed against the same schema; a failure here is the
    // projection's own invariant, never caller-supplied data.
    return err(
      new AnalysisProtocolError(
        "Android JNI name projection produced an invalid result",
        { cause },
      ),
    );
  }
};
