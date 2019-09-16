#!/usr/bin/env python

from __future__ import unicode_literals, print_function
from base64 import b64decode
import codecs
import glob
import json
import os
import platform
import re
import subprocess
import sys


def generate_runtime_v8(runtime_name, output_dir, output, inputs):
    with codecs.open(os.path.join(output_dir, output), 'wb', 'utf-8') as output_file:
        output_file.write("#include \"gumv8bundle.h\"\n")

        modules = []
        for input_path in inputs:
            input_name = os.path.basename(input_path)

            base, ext = os.path.splitext(input_name)

            input_source_code_identifier = "gumjs_{0}_source_code".format(identifier(base))
            input_source_map_identifier = "gumjs_{0}_source_map".format(identifier(base))

            with codecs.open(input_path, 'rb', 'utf-8') as input_file:
                source_code = input_file.read()
            (stripped_source_code, source_map) = extract_source_map(input_name, source_code)
            source_code_bytes = bytearray(stripped_source_code.encode('utf-8'))
            source_code_bytes.append(0)
            source_code_size = len(source_code_bytes)

            output_file.write("\nstatic const gchar {0}[{1}] =\n{{".format(input_source_code_identifier, source_code_size))
            write_bytes(source_code_bytes, output_file)
            output_file.write("\n};\n")

            if source_map is not None:
                source_map_bytes = bytearray(source_map.encode('utf-8'))
                source_map_bytes.append(0)
                source_map_size = len(source_map_bytes)

                output_file.write("\nstatic const gchar {0}[{1}] =\n{{".format(input_source_map_identifier, source_map_size))
                write_bytes(source_map_bytes, output_file)
                output_file.write("\n};\n")

                modules.append((input_name, input_source_code_identifier, input_source_map_identifier))
            else:
                modules.append((input_name, input_source_code_identifier, "NULL"))

        output_file.write("\nstatic const GumV8RuntimeModule gumjs_{0}_modules[] =\n{{".format(runtime_name))
        for filename, source_code_identifier, source_map_identifier in modules:
            output_file.write("\n  {{ \"{0}\", {1}, {2} }},".format(filename, source_code_identifier, source_map_identifier))
        output_file.write("\n  { NULL, NULL, NULL }\n};")


def generate_runtime_duk(runtime_name, output_dir, output, input_dir, inputs):
    with codecs.open(os.path.join(output_dir, output), 'wb', 'utf-8') as output_file:
        output_file.write("#include \"gumdukbundle.h\"\n")

        build_os = platform.system().lower()

        if build_os == 'windows':
            program_suffix = ".exe"
        else:
            program_suffix = ""

        dukcompile = os.path.join(output_dir, "gumdukcompile" + program_suffix)
        if not os.path.exists(dukcompile):
            dukcompile_sources = list(map(lambda name: os.path.join(input_dir, name), ["gumdukcompile.c", "duktape.c"]))
            if build_os == 'windows':
                subprocess.check_call(["cl.exe",
                    "/nologo", "/MT", "/W3", "/O1", "/GL", "/MP",
                    "/D", "WIN32",
                    "/D", "_WINDOWS",
                    "/D", "WINVER=0x0501",
                    "/D", "_WIN32_WINNT=0x0501",
                    "/D", "NDEBUG",
                    "/D", "_CRT_SECURE_NO_WARNINGS",
                    "/D", "_USING_V110_SDK71_",
                    "/D", "GUM_DUK_NO_COMPAT"] + dukcompile_sources, cwd=output_dir)
            else:
                dukcompile_libs = []
                if build_os == 'darwin':
                    sdk = "macosx"
                    CC = [
                        subprocess.check_output(["xcrun", "--sdk", sdk, "-f", "clang"]).decode('utf-8').rstrip("\n"),
                        "-isysroot", subprocess.check_output(["xcrun", "--sdk", sdk, "--show-sdk-path"]).decode('utf-8').rstrip("\n")
                    ]
                else:
                    CC = ["gcc"]
                    dukcompile_libs.append("-lm")
                subprocess.check_call(CC + ["-Wall", "-pipe", "-O1", "-fomit-frame-pointer", "-DGUM_DUK_NO_COMPAT"] +
                    dukcompile_sources +
                    ["-o", dukcompile] + dukcompile_libs)

        modules = []
        for input_path in inputs:
            input_name = os.path.basename(input_path)

            base, ext = os.path.splitext(input_name)

            input_name_duk = base + ".duk"
            input_path_duk = os.path.join(output_dir, input_name_duk)

            input_bytecode_identifier = "gumjs_{0}_bytecode".format(identifier(base))
            input_source_map_identifier = "gumjs_{0}_source_map".format(identifier(base))

            subprocess.check_call([dukcompile, input_path, input_path_duk])

            with open(input_path_duk, 'rb') as duk:
                bytecode = duk.read()
            bytecode_size = len(bytecode)

            output_file.write("\nstatic const guint8 {0}[{1}] =\n{{".format(input_bytecode_identifier, bytecode_size))
            write_bytes(bytecode, output_file)
            output_file.write("\n};\n")

            with codecs.open(input_path, 'rb', 'utf-8') as input_file:
                source_code = input_file.read()

            (stripped_source_code, source_map) = extract_source_map(input_name, source_code)

            if source_map is not None:
                source_map_bytes = bytearray(source_map.encode('utf-8'))
                source_map_bytes.append(0)
                source_map_size = len(source_map_bytes)

                output_file.write("\nstatic const gchar {0}[{1}] =\n{{".format(input_source_map_identifier, source_map_size))
                write_bytes(source_map_bytes, output_file)
                output_file.write("\n};\n")

                modules.append((input_bytecode_identifier, bytecode_size, input_source_map_identifier))
            else:
                modules.append((input_bytecode_identifier, bytecode_size, "NULL"))

        output_file.write("\nstatic const GumDukRuntimeModule gumjs_{0}_modules[] =\n{{".format(runtime_name))
        for bytecode_identifier, bytecode_size, source_map_identifier in modules:
            output_file.write("\n  {{ {0}, {1}, {2} }},".format(bytecode_identifier, bytecode_size, source_map_identifier))
        output_file.write("\n  { NULL, 0, NULL }\n};")


cmodule_function_pattern = re.compile(
    r"^(void|size_t|int|unsigned int|bool|const char \*|gpointer|gsize|gssize|gint[0-9]*|guint[0-9]*|gfloat|gdouble|gboolean|\w+ \*|cs_err) ([a-z][a-z0-9_]+)\s?\(",
    re.MULTILINE)
cmodule_variable_pattern = re.compile(r"^(extern .+? )(\w+);", re.MULTILINE)
capstone_include_pattern = re.compile(r'^#include "(\w+)\.h"$', re.MULTILINE)
capstone_export_pattern = re.compile(r"^CAPSTONE_EXPORT$", re.MULTILINE)

c_comment_pattern = re.compile(r"\/\*(\*(?!\/)|[^*])*\*\/")
cpp_comment_pattern = re.compile(r"\s+?\/\/.+")


def generate_runtime_cmodule(output_dir, output, arch, input_dir, gum_dir, capstone_dir):
    writer_arch = "x86" if arch.startswith("x86") or arch == "x64" else arch
    writer_name = "thumb" if writer_arch == "arm" else writer_arch
    capstone_arch = writer_arch

    def gum_header_matches_writer(name):
        return name == "gum" + writer_name + "writer.h"

    def optimize_gum_header(source):
        return source.replace("GUM_API ", "")

    def capstone_header_matches_arch(name):
        if name in ("capstone.h", "platform.h"):
            return True
        return name == capstone_arch + ".h"

    def optimize_capstone_header(source):
        result = capstone_include_pattern.sub(transform_capstone_include, source)
        result = capstone_export_pattern.sub("", result)
        result = result.replace("CAPSTONE_API ", "")
        return result

    def transform_capstone_include(m):
        name = m.group(1)

        if name in ("platform", capstone_arch):
            return m.group(0)

        if name == "systemz":
            name = "sysz"

        return "typedef int cs_{0};".format(name)

    inputs = [
        (os.path.join(input_dir, "runtime", "cmodule"), None, is_header, identity_transform),
        (os.path.join(input_dir, "..", "..", "ext", "tinycc", "include"), None, is_header, identity_transform),
        (os.path.join(gum_dir, "arch-" + writer_arch), os.path.dirname(gum_dir), gum_header_matches_writer, optimize_gum_header),
        (os.path.dirname(capstone_dir), None, capstone_header_matches_arch, optimize_capstone_header),
    ]

    with codecs.open(os.path.join(output_dir, output), 'wb', 'utf-8') as output_file:
        modules = []
        symbols = []

        for header_dir, header_reldir, header_filter, header_transform in inputs:
            for header_name, header_source in find_headers(header_dir, header_reldir, header_filter, header_transform):
                input_identifier = "gum_cmodule_{0}".format(identifier(header_name))

                for pattern in (cmodule_function_pattern, cmodule_variable_pattern):
                    for m in pattern.finditer(header_source):
                        name = m.group(2)
                        symbols.append(name)

                source_bytes = bytearray(header_source.encode('utf-8'))
                source_bytes.append(0)
                source_size = len(source_bytes)

                output_file.write("static const gchar {0}[{1}] =\n{{".format(input_identifier, source_size))
                write_bytes(source_bytes, output_file)
                output_file.write("\n};\n\n")

                modules.append((header_name, input_identifier, source_size - 1))

        output_file.write("static const GumCModuleHeader gum_cmodule_headers[] =\n{")
        for input_name, input_identifier, input_size in modules:
            output_file.write("\n  {{ \"{0}\", {1}, {2} }},".format(input_name, input_identifier, input_size))
        output_file.write("\n};\n")

        symbol_insertions = ["    g_hash_table_insert (symbols, \"{0}\", GUM_FUNCPTR_TO_POINTER ({0}));".format(name) for name in symbols]
        output_file.write("""
static void gum_cmodule_deinit_symbols (void);

static GHashTable *
gum_cmodule_get_symbols (void)
{{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {{
    GHashTable * symbols;

    symbols = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);

{insertions}

    _gum_register_destructor (gum_cmodule_deinit_symbols);

    g_once_init_leave (&gonce_value, GPOINTER_TO_SIZE (symbols) + 1);
  }}

  return GSIZE_TO_POINTER (gonce_value - 1);
}}

static void
gum_cmodule_deinit_symbols (void)
{{
  g_hash_table_unref (gum_cmodule_get_symbols ());
}}
""".format(insertions="\n".join(symbol_insertions)))


def find_headers(include_dir, relative_to_dir, is_header, transform):
    if relative_to_dir is None:
        relative_to_dir = include_dir

    for root, dirs, files in os.walk(include_dir):
        for name in files:
            if is_header(name):
                path = os.path.join(root, name)
                name = os.path.relpath(path, relative_to_dir).replace("\\", "/")
                with codecs.open(path, 'rb', 'utf-8') as f:
                    source = strip_header(transform(strip_header(f.read())))
                yield (name, source)


def is_header(name):
    return name.endswith(".h")


def identity_transform(v):
    return v


def strip_header(source):
    result = c_comment_pattern.sub("", source)
    result = cpp_comment_pattern.sub("", result)
    while True:
        if "\n\n" not in result:
            break
        result = result.replace("\n\n", "\n")
    return result


source_map_pattern = re.compile("//[#@][ \t]sourceMappingURL=[ \t]*data:application/json;.*?base64,([^\\s'\"]*)[ \t]*\n")


def extract_source_map(filename, source_code):
    m = source_map_pattern.search(source_code)
    if m is None:
        return (source_code, None)
    raw_source_map = m.group(1)

    source_map = json.loads(b64decode(raw_source_map).decode('utf-8'))
    source_map['file'] = filename
    source_map['sources'] = list(map(to_canonical_source_path, source_map['sources']))

    raw_source_map = json.dumps(source_map)

    stripped_source_code = source_map_pattern.sub("", source_code)

    return (stripped_source_code, raw_source_map)


def to_canonical_source_path(path):
    return "frida/" + path


def write_bytes(data, sink):
    sink.write("\n  ")
    line_length = 0
    offset = 0
    for b in bytearray(data):
        if offset > 0:
            sink.write(",")
            line_length += 1
        if line_length >= 70:
            sink.write("\n  ")
            line_length = 0
        token = str(b)
        sink.write(token)

        line_length += len(token)
        offset += 1


def identifier(filename):
    result = ""
    if filename.startswith("frida-"):
        filename = filename[6:]
    for c in filename:
        if c.isalnum():
            result += c.lower()
        else:
            result += "_"
    return result


def node_script_path(name):
    return os.path.abspath(os.path.join(sys.path[0], "node_modules", ".bin", name + script_suffix()))


def script_suffix():
    build_os = platform.system().lower()
    return ".cmd" if build_os == 'windows' else ""


if __name__ == '__main__':
    arch = sys.argv[1]
    input_dir = sys.argv[2]
    gum_dir = sys.argv[3]
    capstone_dir = sys.argv[4]
    output_dir = sys.argv[5]

    v8_tmp_dir = os.path.join(output_dir, "runtime-build-v8")
    runtime = os.path.abspath(os.path.join(v8_tmp_dir, "frida.js"))
    objc = os.path.abspath(os.path.join(v8_tmp_dir, "objc.js"))
    java = os.path.abspath(os.path.join(v8_tmp_dir, "java.js"))

    subprocess.check_call([node_script_path("frida-compile"), "./runtime/entrypoint-v8.js", "-o", runtime, "-x"], cwd=input_dir)
    subprocess.check_call([node_script_path("frida-compile"), "./runtime/objc.js", "-o", objc, "-x"], cwd=input_dir)
    subprocess.check_call([node_script_path("frida-compile"), "./runtime/java.js", "-o", java, "-x"], cwd=input_dir)

    generate_runtime_v8("runtime", output_dir, "gumv8script-runtime.h", [runtime])
    generate_runtime_v8("objc", output_dir, "gumv8script-objc.h", [objc])
    generate_runtime_v8("java", output_dir, "gumv8script-java.h", [java])

    duk_tmp_dir = os.path.join(output_dir, "runtime-build-duk")
    runtime = os.path.abspath(os.path.join(duk_tmp_dir, "frida.js"))
    promise = os.path.abspath(os.path.join(duk_tmp_dir, "promise.js"))
    objc = os.path.abspath(os.path.join(duk_tmp_dir, "objc.js"))
    java = os.path.abspath(os.path.join(duk_tmp_dir, "java.js"))

    subprocess.check_call([node_script_path("frida-compile"), "./runtime/entrypoint-duktape.js", "-o", runtime, "-c"], cwd=input_dir)
    subprocess.check_call([node_script_path("frida-compile"), "./runtime/promise.js", "-o", promise, "-c", "-x"], cwd=input_dir)
    subprocess.check_call([node_script_path("frida-compile"), "./runtime/objc.js", "-o", objc, "-c"], cwd=input_dir)
    subprocess.check_call([node_script_path("frida-compile"), "./runtime/java.js", "-o", java, "-c"], cwd=input_dir)

    generate_runtime_duk("runtime", output_dir, "gumdukscript-runtime.h", input_dir, [runtime])
    generate_runtime_duk("promise", output_dir, "gumdukscript-promise.h", input_dir, [promise])
    generate_runtime_duk("objc", output_dir, "gumdukscript-objc.h", input_dir, [objc])
    generate_runtime_duk("java", output_dir, "gumdukscript-java.h", input_dir, [java])

    generate_runtime_cmodule(output_dir, "gumcmodule-runtime.h", arch, input_dir, gum_dir, capstone_dir)
