import { z } from "zod";

/**
 * DEX method prototype syntax, kept locally: REA's class inventory no longer
 * reports prototypes, so long-name projection needs a caller-supplied
 * descriptor and rejects malformed ones instead of guessing.
 */
const dexDescriptorInputSchema = z
  .string()
  .regex(
    /^\((?:\[*(?:[ZBSCIJFD]|L[^;\x28\x29]+;))*\)(?:V|\[*(?:[ZBSCIJFD]|L[^;\x28\x29]+;))$/u,
  );

/** One caller-selected DEX method awaiting native-symbol correlation. */
export const jniMethodInputSchema = z.strictObject({
  method_name: z.string().min(1),
  dex_descriptor: dexDescriptorInputSchema.nullable(),
});

/** Caller-selected class plus the DEX methods to project. */
export const androidJniNamesInputSchema = z.strictObject({
  class_name: z
    .string()
    .min(1)
    .describe("Fully qualified DEX class name, e.g. pkg.Outer.Inner"),
  methods: z.array(jniMethodInputSchema).min(1).max(2000),
});

/** Expected native symbol spellings for one DEX method. */
export const jniNameProjectionSchema = z.strictObject({
  method_name: z.string(),
  dex_descriptor: dexDescriptorInputSchema.nullable(),
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
 * Escape one internal-form character per the JNI mangling rules:
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

const mangle = (value: string): string =>
  [...value].map((char) => (char === "/" ? "_" : escapeChar(char))).join("");

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
  const groupSizes = new Map<string, number>();
  for (const method of parsed.methods) {
    groupSizes.set(
      method.method_name,
      (groupSizes.get(method.method_name) ?? 0) + 1,
    );
  }
  return androidJniNamesResultSchema.parse({
    class_name: parsed.class_name,
    methods: parsed.methods.map((method) => {
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
      ...(parsed.methods.some((method) => method.dex_descriptor === null)
        ? [
            "Methods without a dex_descriptor report only the short name; overloads need the long name from an external descriptor (REA class inventory no longer reports DEX prototypes).",
          ]
        : []),
    ],
  });
};
