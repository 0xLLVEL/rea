import { z } from "zod";

import { compareUnicodeCodePoints } from "../unicodeCodePointOrder.js";
import { androidManifestComponentSchema } from "./androidAnalysis.js";

/** Caller-selected package facts, mirroring inspect_android_package declarations. */
export const androidAttackSurfaceInputSchema = z.strictObject({
  package_name: z.string().nullable(),
  components: z.array(androidManifestComponentSchema),
  component_coverage: z.enum(["complete", "partial", "unknown"]),
});

/** One exported component with its guard and trigger summary. */
export const attackSurfaceFindingSchema = z.strictObject({
  kind: z.string(),
  name: z.string().nullable(),
  resolved_name: z.string().nullable(),
  exported_source: z.enum(["explicit", "implicit", "unknown"]),
  permission: z.string().nullable(),
  permission_source: z.enum(["component", "application", "none", "unknown"]),
  intent_actions: z.array(z.string()),
  note: z.string(),
});

export type AttackSurfaceFinding = z.infer<typeof attackSurfaceFindingSchema>;

/** Ranked structural attack-surface observations over static declarations. */
export const androidAttackSurfaceResultSchema = z.strictObject({
  package_name: z.string().nullable(),
  exported_without_permission: z.array(attackSurfaceFindingSchema),
  exported_guarded: z.array(attackSurfaceFindingSchema),
  exported_guard_unknown: z.array(attackSurfaceFindingSchema),
  export_unknown: z.array(attackSurfaceFindingSchema),
  intent_action_index: z.array(
    z.strictObject({
      action: z.string(),
      components: z.array(z.string().nullable()),
    }),
  ),
  foreground_service_types: z.array(z.string()),
  provider_authorities: z.array(z.string().nullable()),
  coverage: z.enum(["complete", "partial", "unknown"]),
  unknowns: z.array(z.string()),
});

export type AndroidAttackSurfaceInput = z.infer<
  typeof androidAttackSurfaceInputSchema
>;
export type AndroidAttackSurfaceResult = z.infer<
  typeof androidAttackSurfaceResultSchema
>;

/** How the effective export state was established: declared, defaulted, or unresolved. */
const exportedSource = (
  component: z.infer<typeof androidManifestComponentSchema>,
): "explicit" | "implicit" | "unknown" =>
  component.exported !== null
    ? "explicit"
    : component.exported_default !== null
      ? "implicit"
      : "unknown";

const toFinding = (
  component: z.infer<typeof androidManifestComponentSchema>,
  note: string,
): AttackSurfaceFinding => ({
  kind: component.kind,
  name: component.declared_name,
  resolved_name: component.name,
  exported_source: exportedSource(component),
  permission: component.permission,
  permission_source: component.permission_source,
  intent_actions: [...component.actions],
  note,
});

/**
 * Project structural attack-surface facts from static declarations.
 * Pure ranking; protection levels and runtime enforcement stay unknown.
 */
export const projectAttackSurface = (
  input: AndroidAttackSurfaceInput,
): AndroidAttackSurfaceResult => {
  const parsed = androidAttackSurfaceInputSchema.parse(input);
  const exportedWithout: AttackSurfaceFinding[] = [];
  const guarded: AttackSurfaceFinding[] = [];
  const guardUnknown: AttackSurfaceFinding[] = [];
  const unknown: AttackSurfaceFinding[] = [];
  const actionIndex = new Map<string, (string | null)[]>();
  const serviceTypes = new Set<string>();
  const authorities = new Set<string | null>();
  let unresolvedGuards = 0;
  let providerOverrideGuards = 0;
  for (const component of parsed.components) {
    for (const action of component.actions) {
      const list = actionIndex.get(action) ?? [];
      list.push(component.name);
      actionIndex.set(action, list);
    }
    if (component.foreground_service_type !== null)
      serviceTypes.add(component.foreground_service_type);
    if (component.kind === "provider" && component.authorities !== null) {
      for (const authority of component.authorities) authorities.add(authority);
    }
    // The effective export state is the declared literal, else Android's
    // documented default for an absent android:exported when it applies.
    const exported = component.exported ?? component.exported_default;
    if (exported === null) {
      unknown.push(
        toFinding(
          component,
          "Export state is unresolved; treat the component as reachable.",
        ),
      );
      continue;
    }
    if (!exported) continue;
    if (
      component.permission_source === "component" ||
      component.permission_source === "application"
    ) {
      guarded.push(
        toFinding(component, `Exported, guarded by ${component.permission}.`),
      );
    } else if (component.permission_source === "unknown") {
      unresolvedGuards += 1;
      guardUnknown.push(
        toFinding(
          component,
          "Exported; the guarding permission is unresolved, so absence of a guard is not established.",
        ),
      );
    } else if (component.kind === "provider") {
      // inspect_android_package does not project android:readPermission or
      // android:writePermission, so a null provider permission proves nothing.
      providerOverrideGuards += 1;
      guardUnknown.push(
        toFinding(
          component,
          "Exported; provider readPermission/writePermission overrides are not projected, so absence of a guard is not established.",
        ),
      );
    } else {
      exportedWithout.push(
        toFinding(component, "Exported without a guarding permission."),
      );
    }
  }
  const unknowns = [
    "Permission declarations do not establish protection levels or runtime enforcement.",
    "Reachability through intents, tasks, and deep links was not traced; listed triggers are static declarations.",
  ];
  if (unresolvedGuards > 0) {
    unknowns.push(
      `${String(unresolvedGuards)} exported component(s) have an unresolved permission value; they stay guard-unknown rather than unguarded.`,
    );
  }
  if (providerOverrideGuards > 0) {
    unknowns.push(
      `${String(providerOverrideGuards)} exported provider(s) declare no projected base permission; operation-specific readPermission/writePermission overrides are not projected, so they stay guard-unknown.`,
    );
  }
  if (parsed.component_coverage !== "complete") {
    unknowns.push(
      `Component inventory coverage is ${parsed.component_coverage}; absence of a finding is unknown.`,
    );
  }
  return androidAttackSurfaceResultSchema.parse({
    package_name: parsed.package_name,
    exported_without_permission: exportedWithout,
    exported_guarded: guarded,
    exported_guard_unknown: guardUnknown,
    export_unknown: unknown,
    intent_action_index: [...actionIndex]
      .map(([action, components]) => ({ action, components }))
      .sort((a, b) => compareUnicodeCodePoints(a.action, b.action)),
    foreground_service_types: [...serviceTypes].sort(compareUnicodeCodePoints),
    provider_authorities: [...authorities].sort((a, b) =>
      compareUnicodeCodePoints(a ?? "", b ?? ""),
    ),
    coverage: parsed.component_coverage,
    unknowns,
  });
};
