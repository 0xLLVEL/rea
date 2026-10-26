import { describe, expect, it } from "vitest";

import { projectJniNames } from "./androidJniNames.js";

/**
 * Short-name goldens for BinaryEye's ZxingCpp come from a real APK
 * (F-Droid de.markusfisch.android.binaryeye vc 180): `inspect-android-class`
 * lists the class and the .so exports carry these exact JNI names.
 * Underscore/array/overload/nested/unicode spellings were verified against
 * `javac -h` on JDK 25 before encoding them here.
 */
describe("projectJniNames", () => {
  it("matches real JNI exports for BinaryEye ZxingCpp methods", () => {
    const result = projectJniNames({
      class_name: "de.markusfisch.android.zxingcpp.ZxingCpp",
      methods: [
        {
          method_name: "readYBuffer",
          dex_descriptor:
            "(Ljava/nio/ByteBuffer;IIIIIILde/markusfisch/android/zxingcpp/ZxingCpp$ReaderOptions;)Ljava/util/List;",
        },
        {
          method_name: "readByteArray",
          dex_descriptor:
            "([BIIIIIILde/markusfisch/android/zxingcpp/ZxingCpp$ReaderOptions;)Ljava/util/List;",
        },
        {
          method_name: "encodeString",
          dex_descriptor: "(Ljava/lang/String;I)[B",
        },
      ],
    });
    expect(result.coverage).toBe("complete");
    expect(result.methods.map((m) => m.jni_short_name)).toEqual([
      "Java_de_markusfisch_android_zxingcpp_ZxingCpp_readYBuffer",
      "Java_de_markusfisch_android_zxingcpp_ZxingCpp_readByteArray",
      "Java_de_markusfisch_android_zxingcpp_ZxingCpp_encodeString",
    ]);
    expect(result.methods[0]?.jni_long_name).toBe(
      "Java_de_markusfisch_android_zxingcpp_ZxingCpp_readYBuffer__Ljava_nio_ByteBuffer_2IIIIIILde_markusfisch_android_zxingcpp_ZxingCpp_00024ReaderOptions_2",
    );
    expect(result.methods[0]?.jna_expected_name).toBe("readYBuffer");
  });

  it("escapes underscores, arrays and overloads like javac -h", () => {
    const result = projectJniNames({
      class_name: "pkg.ZxingCpp",
      methods: [
        { method_name: "foo_bar", dex_descriptor: "([B)V" },
        { method_name: "take", dex_descriptor: "([B)V" },
        { method_name: "take", dex_descriptor: "(I)V" },
      ],
    });
    expect(result.methods[0]).toMatchObject({
      jni_short_name: "Java_pkg_ZxingCpp_foo_1bar",
      overload_group_size: 1,
    });
    expect(result.methods[1]).toMatchObject({
      jni_short_name: "Java_pkg_ZxingCpp_take",
      jni_long_name: "Java_pkg_ZxingCpp_take___3B",
      overload_group_size: 2,
    });
    expect(result.methods[2]).toMatchObject({
      jni_long_name: "Java_pkg_ZxingCpp_take__I",
      overload_group_size: 2,
    });
  });

  it("mangles nested binary names and unicode like javac -h", () => {
    const result = projectJniNames({
      class_name: "pkg.Outer$Inner",
      methods: [
        { method_name: "deep", dex_descriptor: "(Ljava/lang/String;)V" },
      ],
    });
    expect(result.methods[0]?.jni_short_name).toBe(
      "Java_pkg_Outer_00024Inner_deep",
    );
    const uni = projectJniNames({
      class_name: "pkg.Uni",
      methods: [{ method_name: "café", dex_descriptor: "()V" }],
    });
    expect(uni.methods[0]?.jni_short_name).toBe("Java_pkg_Uni_caf_000e9");
  });

  it("mangles both halves of a supplementary character like javac -h", () => {
    const result = projectJniNames({
      class_name: "pkg.Uni",
      methods: [{ method_name: "\u{10400}method", dex_descriptor: "()V" }],
    });
    expect(result.methods[0]?.jni_short_name).toBe(
      "Java_pkg_Uni__0d801_0dc00method",
    );
  });

  it("keeps dynamic registration and runtime loading unknown", () => {
    const result = projectJniNames({
      class_name: "pkg.Cls",
      methods: [{ method_name: "m", dex_descriptor: "()V" }],
    });
    expect(result.unknowns.join(" ")).toContain("RegisterNatives");
  });

  it("reports only the short name for an explicit null descriptor", () => {
    const result = projectJniNames({
      class_name: "pkg.Cls",
      methods: [{ method_name: "m", dex_descriptor: null }],
    });
    expect(result.methods[0]).toMatchObject({
      jni_short_name: "Java_pkg_Cls_m",
      jni_long_name: null,
    });
    expect(result.unknowns.join(" ")).toContain(
      "dex_descriptor that inspect_android_class reports",
    );
  });

  it("accepts an omitted descriptor as null", () => {
    const result = projectJniNames({
      class_name: "pkg.Cls",
      methods: [{ method_name: "m" }],
    });
    expect(result.methods[0]).toMatchObject({
      dex_descriptor: null,
      jni_short_name: "Java_pkg_Cls_m",
      jni_long_name: null,
    });
  });

  it("bounds one call's method selection", () => {
    expect(() =>
      projectJniNames({
        class_name: "pkg.Cls",
        methods: Array.from({ length: 2001 }, () => ({ method_name: "m" })),
      }),
    ).toThrow();
  });

  it("rejects malformed descriptors instead of guessing", () => {
    expect(() =>
      projectJniNames({
        class_name: "pkg.Cls",
        methods: [{ method_name: "m", dex_descriptor: "nope" }],
      }),
    ).toThrow();
  });
});
