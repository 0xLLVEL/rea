import type { z } from "zod";

import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import {
  androidManifestComponentSchema,
  androidResultSchemas,
} from "../../domain/android/androidAnalysis.js";
import type { Evidence, EvidenceSubjectTarget } from "../../domain/evidence.js";
import { err, ok, type Result } from "../../domain/result.js";

/** One caller-selected manifest component, as the inventory reports it. */
type ManifestComponent = z.infer<typeof androidManifestComponentSchema>;

/** Refuse a linked source that cannot establish the requested provenance. */
const sourceInputError = (
  operation: string,
  field: string,
  message: string,
): AnalysisError =>
  new AnalysisInputError(operation, { userMessage: message }, [
    { path: ["source_evidence", field], reason: "invalid_value", message },
  ]);

/**
 * Artifact identity reported by linked source Evidence. The projection copies
 * it so identical declarations read from different APKs stay distinguishable.
 */
export const projectionSourceTarget = (
  source: Evidence,
): EvidenceSubjectTarget | undefined => {
  const { subject } = source;
  if (subject === null) return undefined;
  return {
    path: subject.local_path,
    sha256: subject.digest.sha256,
    format: subject.format,
  };
};

/**
 * Facts the attack-surface projection consumes. Two components authenticate as
 * the same declaration only when every one of them matches.
 */
const componentFactsKey = (component: ManifestComponent): string =>
  JSON.stringify([
    component.kind,
    component.declared_name,
    component.name,
    component.exported,
    component.exported_default,
    component.permission,
    component.permission_source,
    component.permission_overrides,
    component.path_permissions,
    component.actions,
    component.foreground_service_type,
    component.authorities,
  ]);

/**
 * Require every selected component to be one the linked package Evidence
 * reported, so the projection never attributes invented declarations to an
 * artifact. A selection may be narrower than that inventory, never wider.
 */
export const authenticateComponentSelection = (
  operation: string,
  source: Evidence | undefined,
  components: readonly ManifestComponent[],
): Result<Evidence | undefined, AnalysisError> => {
  if (source === undefined) return ok(undefined);
  if (source.operation !== "inspect_android_package")
    return err(
      sourceInputError(
        operation,
        "operation",
        `source_evidence is a ${source.operation} result; select the inspect_android_package Evidence whose components you passed`,
      ),
    );
  const parsed = androidResultSchemas.inspect_android_package.safeParse(
    source.normalized_result,
  );
  if (!parsed.success)
    return err(
      sourceInputError(
        operation,
        "normalized_result",
        "source_evidence does not carry an inspect_android_package result; recreate it with the current REA release",
      ),
    );
  const reported = new Set(parsed.data.components.items.map(componentFactsKey));
  for (const [index, component] of components.entries())
    if (!reported.has(componentFactsKey(component)))
      return err(
        sourceInputError(
          operation,
          `components.${String(index)}`,
          `${component.name} is not a component the linked inventory reported; pass that inventory's own component facts, or omit source_evidence`,
        ),
      );
  return ok(source);
};

/** One selected DEX method awaiting correlation with native symbols. */
interface SelectedMethod {
  readonly method_name: string;
  readonly dex_descriptor?: string | null | undefined;
}

/**
 * Require the selected class and methods to be ones the linked class Evidence
 * reported, including the exact DEX descriptor of each selected overload.
 */
export const authenticateClassSelection = (
  operation: string,
  source: Evidence | undefined,
  selection: {
    readonly class_name: string;
    readonly methods: readonly SelectedMethod[];
  },
): Result<Evidence | undefined, AnalysisError> => {
  if (source === undefined) return ok(undefined);
  if (source.operation !== "inspect_android_class")
    return err(
      sourceInputError(
        operation,
        "operation",
        `source_evidence is a ${source.operation} result; select the inspect_android_class Evidence whose members you passed`,
      ),
    );
  const parsed = androidResultSchemas.inspect_android_class.safeParse(
    source.normalized_result,
  );
  if (!parsed.success)
    return err(
      sourceInputError(
        operation,
        "normalized_result",
        "source_evidence does not carry an inspect_android_class result; recreate it with the current REA release",
      ),
    );
  if (
    parsed.data.class_name !== selection.class_name &&
    parsed.data.dex_class_name !== selection.class_name
  )
    return err(
      sourceInputError(
        operation,
        "class_name",
        `${selection.class_name} is not the class the linked Evidence inspected (${parsed.data.dex_class_name}); pass that class's own DEX identity`,
      ),
    );
  const reported = new Set(
    parsed.data.methods.map(
      (method) => `${method.dex_method_name}\u0000${method.dex_descriptor}`,
    ),
  );
  const reportedNames = new Set(
    parsed.data.methods.map((method) => method.dex_method_name),
  );
  for (const [index, method] of selection.methods.entries()) {
    const matches =
      method.dex_descriptor === null || method.dex_descriptor === undefined
        ? reportedNames.has(method.method_name)
        : reported.has(`${method.method_name}\u0000${method.dex_descriptor}`);
    if (!matches)
      return err(
        sourceInputError(
          operation,
          `methods.${String(index)}`,
          `${method.method_name} ${method.dex_descriptor ?? "(no descriptor)"} is not a method the linked Evidence reported; pass that class inventory's own dex_method_name and dex_descriptor, or omit source_evidence`,
        ),
      );
  }
  return ok(source);
};
