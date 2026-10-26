import { z } from "zod";

import { dexDescriptorSchema } from "./androidAnalysis.js";

/**
 * One request projects at most this many methods. Each method yields four names
 * plus its overload count, so a larger selection is split by class or method
 * group instead of growing one response without bound.
 */
const JNI_NAME_METHOD_LIMIT = 2000;

/** One caller-selected DEX method awaiting native-symbol correlation. */
export const jniMethodInputSchema = z.strictObject({
  method_name: z.string().min(1),
  /** Omitted and explicit null both mean "project the short name only". */
  dex_descriptor: dexDescriptorSchema.nullable().optional(),
});

/** Caller-selected class plus the DEX methods to project. */
export const androidJniNamesInputSchema = z.strictObject({
  class_name: z
    .string()
    .min(1)
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
  const groupSizes = new Map<string, number>();
  for (const method of methods) {
    groupSizes.set(
      method.method_name,
      (groupSizes.get(method.method_name) ?? 0) + 1,
    );
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
        overload_group_size: groupSizes.get(method.method_name) ?? 1,
      };
    }),
    coverage: "complete",
    unknowns: [
      "Expected names cover statically exported JNI symbols only; RegisterNatives dynamic registration is unknown.",
      "A name match against a native library does not establish that the library is loaded or the method is called.",
      "When overload_group_size exceeds 1, the short name is ambiguous and only the long name identifies one overload.",
      ...(methods.some((method) => method.dex_descriptor === null)
        ? [
            "Methods without a dex_descriptor report only the short name; supply the dex_descriptor that inspect_android_class reports per method to get the long name.",
          ]
        : []),
    ],
  });
};
