import { z } from "zod";

import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisProtocolError } from "../../domain/analysisErrorCore.js";
import {
  androidJniNamesInputSchema,
  projectJniNames,
} from "../../domain/android/androidJniNames.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import { ANDROID_APPLICATION_PROVIDER } from "../InvestigationProviders.js";
import {
  requestInputError,
  workflowInputError,
} from "../workflowInputError.js";

const OPERATION = "project_android_jni_names" as const;

/** Project expected JNI/JNA symbol names for caller-selected DEX methods. */
export const projectAndroidJniNamesEvidence = (
  rawInput: unknown,
): Result<Evidence, AnalysisError> => {
  const parsed = androidJniNamesInputSchema.safeParse(rawInput);
  if (!parsed.success)
    return err(requestInputError(OPERATION, parsed.error, rawInput));
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
        result: jsonValueSchema.parse(result),
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
    return err(
      cause instanceof TypeError || cause instanceof z.ZodError
        ? workflowInputError(OPERATION, cause)
        : new AnalysisProtocolError(
            "Android JNI name projection produced an invalid result",
            { cause },
          ),
    );
  }
};
