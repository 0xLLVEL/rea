import { z } from "zod";

import { androidManifestComponentSchema } from "./androidManifestComponents.js";

/** Caller-selected package facts, mirroring inspect_android_package declarations. */
export const androidAttackSurfaceInputSchema = z.strictObject({
  package_name: z.string().nullable(),
  target_sdk: z.string().nullable(),
  permissions: z.array(z.string()),
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
  intent_actions: z.array(z.string()),
  note: z.string(),
});

export type AttackSurfaceFinding = z.infer<typeof attackSurfaceFindingSchema>;

/** Ranked structural attack-surface observations over static declarations. */
export const androidAttackSurfaceResultSchema = z.strictObject({
  package_name: z.string().nullable(),
  exported_without_permission: z.array(attackSurfaceFindingSchema),
  exported_guarded: z.array(attackSurfaceFindingSchema),
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

const actionsOf = (component: {
  intent_filters: readonly { actions: readonly string[] }[];
}): string[] => component.intent_filters.flatMap((filter) => filter.actions);

const toFinding = (
  component: z.infer<typeof androidManifestComponentSchema>,
  note: string,
): AttackSurfaceFinding => ({
  kind: component.kind,
  name: component.name,
  resolved_name: component.resolved_name,
  exported_source: component.exported_source,
  permission: component.permission,
  intent_actions: actionsOf(component),
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
  const unknown: AttackSurfaceFinding[] = [];
  const actionIndex = new Map<string, (string | null)[]>();
  const serviceTypes = new Set<string>();
  const authorities = new Set<string | null>();
  for (const component of parsed.components) {
    for (const action of actionsOf(component)) {
      const list = actionIndex.get(action) ?? [];
      list.push(component.resolved_name ?? component.name);
      actionIndex.set(action, list);
    }
    if (component.foreground_service_type !== null)
      serviceTypes.add(component.foreground_service_type);
    if (component.kind === "provider" && component.authorities !== null) {
      authorities.add(component.authorities);
    }
    if (component.exported === true && component.permission === null) {
      exportedWithout.push(
        toFinding(component, "Exported without a guarding permission."),
      );
    } else if (component.exported === true) {
      guarded.push(
        toFinding(component, `Exported, guarded by ${component.permission}.`),
      );
    } else if (component.exported === null) {
      unknown.push(
        toFinding(
          component,
          "Export state depends on targetSdk defaults; treat as reachable.",
        ),
      );
    }
  }
  const unknowns = [
    "Permission declarations do not establish protection levels or runtime enforcement.",
    "Reachability through intents, tasks, and deep links was not traced; listed triggers are static declarations.",
  ];
  if (parsed.component_coverage !== "complete") {
    unknowns.push(
      `Component inventory coverage is ${parsed.component_coverage}; absence of a finding is unknown.`,
    );
  }
  return androidAttackSurfaceResultSchema.parse({
    package_name: parsed.package_name,
    exported_without_permission: exportedWithout,
    exported_guarded: guarded,
    export_unknown: unknown,
    intent_action_index: [...actionIndex]
      .map(([action, components]) => ({ action, components }))
      .sort((a, b) => (a.action < b.action ? -1 : 1)),
    foreground_service_types: [...serviceTypes].sort(),
    provider_authorities: [...authorities].sort((a, b) =>
      (a ?? "").localeCompare(b ?? ""),
    ),
    coverage: parsed.component_coverage,
    unknowns,
  });
};
