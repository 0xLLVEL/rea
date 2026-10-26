import { z } from "zod";

import { dexDescriptorSchema } from "./androidAnalysis.js";

/**
 * One request projects at most this many methods. Each method yields four names
 * plus its overload count, so a larger selection is split by class or method
 * group instead of growing one response without bound.
 */
const JNI_NAME_METHOD_LIMIT = 2000;

/** JVM constant-pool text limit for one class name, method name or descriptor. */
const JNI_SYMBOL_TEXT_LIMIT = 65_535;

/**
 * Aggregate caller text allowed per call. Mangling expands each UTF-16 unit to
 * at most six ASCII characters, so this also bounds the projected symbols and
 * the Evidence that carries them.
 */
const JNI_SYMBOL_INPUT_BYTES_LIMIT = 1_048_576;

/** One caller-selected DEX method awaiting native-symbol correlation. */
export const jniMethodInputSchema = z.strictObject({
  method_name: z.string().min(1).max(JNI_SYMBOL_TEXT_LIMIT),
  /** Omitted and explicit null both mean "project the short name only". */
  dex_descriptor: dexDescriptorSchema
    .max(JNI_SYMBOL_TEXT_LIMIT)
    .nullable()
    .optional(),
});

/** Caller-selected class plus the DEX methods to project. */
export const androidJniNamesInputSchema = z
  .strictObject({
    class_name: z
      .string()
      .min(1)
      .max(JNI_SYMBOL_TEXT_LIMIT)
      .describe(
        "DEX binary class name, e.g. pkg.Outer$Inner; nested classes keep the $ separator",
      ),
    methods: z
      .array(jniMethodInputSchema)
      .min(1)
      .max(JNI_NAME_METHOD_LIMIT)
      .describe(
        `At most ${String(JNI_NAME_METHOD_LIMIT)} methods per call; split a larger selection by class or method group`,
      ),
  })
  .superRefine((input, context) => {
    const bytes =
      Buffer.byteLength(input.class_name, "utf8") +
      input.methods.reduce(
        (total, method) =>
          total +
          Buffer.byteLength(method.method_name, "utf8") +
          Buffer.byteLength(method.dex_descriptor ?? "", "utf8"),
        0,
      );
    if (bytes > JNI_SYMBOL_INPUT_BYTES_LIMIT)
      context.addIssue({
        code: "custom",
        path: ["methods"],
        message: `Selection text is ${String(bytes)} bytes; at most ${String(JNI_SYMBOL_INPUT_BYTES_LIMIT)} bytes are projected per call. Split the selection by class or method group.`,
      });
  });

/** Expected native symbol spellings for one DEX method. */
export const jniNameProjectionSchema = z.strictObject({
  method_name: z.string(),
  dex_descriptor: dexDescriptorSchema.nullable(),
  jni_short_name: z.string(),
  jni_long_name: z.string().nullable(),
  jna_expected_name: z.string(),
  overload_group_size: z.number().int().min(1),
});

/** Deterministic JNI/JNA name projection over caller-selected methods. */
export const androidJniNamesResultSchema = z.strictObject({
  class_name: z.string(),
  methods: z.array(jniNameProjectionSchema),
  coverage: z.literal("complete"),
  unknowns: z.array(z.string()),
});

export type AndroidJniNamesInput = z.infer<typeof androidJniNamesInputSchema>;
export type AndroidJniNamesResult = z.infer<typeof androidJniNamesResultSchema>;

/** Names cover only statically exported JNI symbols. */
export const STATIC_EXPORT_ONLY_NOTE =
  "Expected names cover statically exported JNI symbols only; RegisterNatives dynamic registration is unknown.";

/** A name match never establishes loading or invocation. */
export const NAME_MATCH_NOTE =
  "A name match against a native library does not establish that the library is loaded or the method is called.";

/** Overload groups come from the selection, not the class inventory. */
export const SELECTION_SCOPED_OVERLOADS_NOTE =
  "overload_group_size counts the distinct descriptors you selected; a class can declare more overloads than were supplied, and the short name stays ambiguous without every overload.";

/** Guidance for selected methods without a descriptor. */
export const MISSING_DESCRIPTOR_NOTE =
  "Methods without a dex_descriptor report only the short name; supply the dex_descriptor that inspect_android_class reports per method to get the long name.";

/** Guidance for identities copied from decompiler display names. */
export const DISPLAY_NAME_NOTE =
  "Supply raw DEX identities: inspect_android_class reports each method's dex_method_name and the class's dex_class_name, because its display names can be decompiler aliases or dotted nested names that do not match a native export.";

const hex4 = (code: number): string => code.toString(16).padStart(4, "0");

/**
 * Escape one internal-form UTF-16 code unit per the JNI mangling rules:
 * ASCII alphanumerics pass through, `_` becomes `_1`, `;` becomes `_2`,
 * `[` becomes `_3`, and anything else becomes `_0xxxx`.
 */
const escapeChar = (char: string): string => {
  if (/^[A-Za-z0-9]$/u.test(char)) return char;
  if (char === "_") return "_1";
  if (char === ";") return "_2";
  if (char === "[") return "_3";
  const code = char.charCodeAt(0);
  return `_0${hex4(code)}`;
};

/**
 * Walk UTF-16 code units, not code points: `javac -h` mangles each half of a
 * supplementary character separately (`𐐀` becomes `_0d801_0dc00`).
 */
const mangle = (value: string): string =>
  value
    .split("")
    .map((char) => (char === "/" ? "_" : escapeChar(char)))
    .join("");

/** `pkg.Cls` (binary name, `$` for nested classes) becomes the JNI class part. */
const mangleClass = (className: string): string =>
  mangle(className.replaceAll(".", "/"));

const argumentDescriptor = (descriptor: string): string => {
  const args = descriptor.slice(1, descriptor.indexOf(")"));
  return mangle(args);
};

/**
 * Project expected JNI short/long names plus the JNA exact name.
 * Pure string projection; it never reads an APK or native library.
 */
export const projectJniNames = (
  input: AndroidJniNamesInput,
): AndroidJniNamesResult => {
  const parsed = androidJniNamesInputSchema.parse(input);
  const classPart = mangleClass(parsed.class_name);
  // Normalize an omitted descriptor once, so every later step sees null.
  const methods = parsed.methods.map((method) => ({
    method_name: method.method_name,
    dex_descriptor: method.dex_descriptor ?? null,
  }));
  // Distinct descriptors identify one overload; a repeated or omitted
  // descriptor cannot be told apart, so it counts once.
  const overloadGroups = new Map<string, Set<string | null>>();
  for (const method of methods) {
    const group = overloadGroups.get(method.method_name) ?? new Set();
    group.add(method.dex_descriptor);
    overloadGroups.set(method.method_name, group);
  }
  return androidJniNamesResultSchema.parse({
    class_name: parsed.class_name,
    methods: methods.map((method) => {
      const methodPart = mangle(method.method_name);
      return {
        method_name: method.method_name,
        dex_descriptor: method.dex_descriptor,
        jni_short_name: `Java_${classPart}_${methodPart}`,
        jni_long_name:
          method.dex_descriptor === null
            ? null
            : `Java_${classPart}_${methodPart}__${argumentDescriptor(method.dex_descriptor)}`,
        jna_expected_name: method.method_name,
        overload_group_size: overloadGroups.get(method.method_name)?.size ?? 1,
      };
    }),
    coverage: "complete",
    unknowns: [
      STATIC_EXPORT_ONLY_NOTE,
      NAME_MATCH_NOTE,
      SELECTION_SCOPED_OVERLOADS_NOTE,
      DISPLAY_NAME_NOTE,
      ...(methods.some((method) => method.dex_descriptor === null)
        ? [MISSING_DESCRIPTOR_NOTE]
        : []),
    ],
  });
};
