import { z } from "zod";
import {
  DOMParser,
  type Document,
  type Element,
  type Node,
} from "@xmldom/xmldom";

/** One manifest-declared app component projected from decoded XML. */
export const androidManifestComponentSchema = z.strictObject({
  kind: z.enum([
    "activity",
    "activity-alias",
    "service",
    "receiver",
    "provider",
  ]),
  name: z.string().nullable(),
  resolved_name: z.string().nullable(),
  exported: z.boolean().nullable(),
  exported_source: z.enum(["explicit", "implicit", "unknown"]),
  permission: z.string().nullable(),
  enabled: z.boolean().nullable(),
  process: z.string().nullable(),
  foreground_service_type: z.string().nullable(),
  authorities: z.string().nullable(),
  grant_uri_permissions: z.boolean().nullable(),
  intent_filters: z.array(
    z.strictObject({
      actions: z.array(z.string()),
      categories: z.array(z.string()),
      data: z.array(z.string()),
      priority: z.string().nullable(),
    }),
  ),
  meta_data: z.array(z.string()),
  manifest_index: z.number().int().nonnegative(),
});

export type AndroidManifestComponent = z.infer<
  typeof androidManifestComponentSchema
>;

const COMPONENT_TAGS = new Set([
  "activity",
  "activity-alias",
  "service",
  "receiver",
  "provider",
]);

const attr = (element: Element, name: string): string | null =>
  element.getAttribute(`android:${name}`) ?? element.getAttribute(name) ?? null;

const parseBool = (value: string | null): boolean | null => {
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
};

const resolveName = (
  declared: string | null,
  packageName: string | null,
): string | null => {
  if (declared === null || declared.length === 0) return null;
  if (declared.startsWith("."))
    return packageName === null ? null : `${packageName}${declared}`;
  if (declared.includes(".")) return declared;
  return packageName === null ? declared : `${packageName}.${declared}`;
};

const childElements = (node: Node): Element[] => {
  const out: Element[] = [];
  for (let child = node.firstChild; child !== null; child = child.nextSibling) {
    if (child.nodeType === 1) out.push(child as Element);
  }
  return out;
};

const dataDescriptor = (element: Element): string => {
  const parts: string[] = [];
  for (const key of [
    "scheme",
    "host",
    "port",
    "path",
    "pathPrefix",
    "pathPattern",
    "mimeType",
  ]) {
    const value = attr(element, key);
    if (value !== null) parts.push(`${key}=${value}`);
  }
  return parts.length === 0 ? "data" : `data(${parts.join(" ")})`;
};

const parseIntentFilter = (element: Element) => {
  const actions: string[] = [];
  const categories: string[] = [];
  const data: string[] = [];
  for (const child of childElements(element)) {
    if (child.nodeName === "action") {
      const name = attr(child, "name");
      if (name !== null) actions.push(name);
    } else if (child.nodeName === "category") {
      const name = attr(child, "name");
      if (name !== null) categories.push(name);
    } else if (child.nodeName === "data") {
      data.push(dataDescriptor(child));
    }
  }
  return { actions, categories, data, priority: attr(element, "priority") };
};

const parseXml = (xml: string): Document | null => {
  try {
    const errors: string[] = [];
    const document = new DOMParser({
      onError: (_level, message) => errors.push(message),
    }).parseFromString(xml, "application/xml");
    if (errors.length > 0 || document.documentElement === null) return null;
    return document;
  } catch {
    return null;
  }
};

const resolveExported = (
  explicit: boolean | null,
  hasFilters: boolean,
  targetKnown: boolean,
  target: number | null,
): {
  exported: boolean | null;
  source: "explicit" | "implicit" | "unknown";
} => {
  if (explicit !== null) return { exported: explicit, source: "explicit" };
  if (!hasFilters) return { exported: false, source: "implicit" };
  if (targetKnown && (target ?? 31) <= 30)
    return { exported: true, source: "implicit" };
  return { exported: null, source: "unknown" };
};

const projectComponent = (
  element: Element,
  context: {
    index: number;
    packageName: string | null;
    targetKnown: boolean;
    target: number | null;
    targetLabel: string | null;
    unknowns: string[];
  },
): AndroidManifestComponent => {
  const name = attr(element, "name");
  const filters = childElements(element)
    .filter((child) => child.nodeName === "intent-filter")
    .map(parseIntentFilter);
  const meta = childElements(element)
    .filter((child) => child.nodeName === "meta-data")
    .map((child) => attr(child, "name"))
    .filter((value): value is string => value !== null);
  const decision = resolveExported(
    parseBool(attr(element, "exported")),
    filters.length > 0,
    context.targetKnown,
    context.target,
  );
  if (decision.source === "unknown") {
    context.unknowns.push(
      `Component ${name ?? `#${context.index}`} has intent filters without an explicit android:exported; the default depends on targetSdk ${context.targetLabel ?? "unknown"} (targetSdk 31+ requires explicit).`,
    );
  }
  const kind = element.nodeName as AndroidManifestComponent["kind"];
  return {
    kind,
    name,
    resolved_name: resolveName(name, context.packageName),
    exported: decision.exported,
    exported_source: decision.source,
    permission: attr(element, "permission"),
    enabled: parseBool(attr(element, "enabled")),
    process: attr(element, "process"),
    foreground_service_type:
      kind === "service" ? attr(element, "foregroundServiceType") : null,
    authorities: kind === "provider" ? attr(element, "authorities") : null,
    grant_uri_permissions:
      kind === "provider"
        ? parseBool(attr(element, "grantUriPermissions"))
        : null,
    intent_filters: filters,
    meta_data: meta,
    manifest_index: context.index,
  };
};

/**
 * Project structured components from already-decoded manifest XML.
 * Never throws on malformed input; unparsable bytes become unknown coverage.
 */
export const projectManifestComponents = (input: {
  manifestText: string;
  manifestStatus: "complete" | "partial";
  packageName: string | null;
  targetSdk: string | null;
}): {
  components: readonly AndroidManifestComponent[];
  coverage: "complete" | "partial" | "unknown";
  unknowns: readonly string[];
} => {
  const document = parseXml(input.manifestText);
  if (document === null) {
    return {
      components: [],
      coverage: "unknown",
      unknowns: [
        "The decoded manifest is not well-formed XML; component inventory is unknown.",
      ],
    };
  }
  const root = document.documentElement;
  if (root === null || root.nodeName !== "manifest") {
    return {
      components: [],
      coverage: "unknown",
      unknowns: [
        "AndroidManifest.xml root must be <manifest>; component inventory is unknown.",
      ],
    };
  }
  const target =
    input.targetSdk === null ? null : Number.parseInt(input.targetSdk, 10);
  const targetKnown = target !== null && Number.isSafeInteger(target);
  const scopes: Element[] = [root];
  for (const child of childElements(root)) {
    if (child.nodeName === "application") scopes.push(child);
  }
  const components: AndroidManifestComponent[] = [];
  const unknowns: string[] = [];
  if (input.manifestStatus === "partial") {
    unknowns.push(
      "The decoded manifest is partial; exhausting these components does not establish complete manifest coverage.",
    );
  }
  let overflowed = false;
  for (const scope of scopes) {
    for (const element of childElements(scope)) {
      if (!COMPONENT_TAGS.has(element.nodeName)) continue;
      if (components.length >= 5000) {
        overflowed = true;
        break;
      }
      components.push(
        projectComponent(element, {
          index: components.length,
          packageName: input.packageName,
          targetKnown,
          target,
          targetLabel: input.targetSdk,
          unknowns,
        }),
      );
    }
    if (overflowed) break;
  }
  if (overflowed) {
    return {
      components,
      coverage: "partial",
      unknowns: [
        ...unknowns,
        "Component inventory exceeded the 5000-entry projection budget; remaining components are omitted.",
      ],
    };
  }
  return {
    components,
    coverage: input.manifestStatus === "partial" ? "partial" : "complete",
    unknowns,
  };
};
