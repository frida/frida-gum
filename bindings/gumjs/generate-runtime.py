#!/usr/bin/env python

from __future__ import unicode_literals, print_function
from base64 import b64decode
import codecs
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
    return os.path.join("frida", path).replace("\\", "/")

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
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]

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
    generate_runtime_v8("debug", output_dir, "gumv8script-debug.h", [os.path.join(input_dir, "frida-debug.js")])

    duk_tmp_dir = os.path.join(output_dir, "runtime-build-duk")
    runtime = os.path.abspath(os.path.join(duk_tmp_dir, "frida.js"))
    promise = os.path.abspath(os.path.join(duk_tmp_dir, "promise.js"))
    objc = os.path.abspath(os.path.join(duk_tmp_dir, "objc.js"))
    java = os.path.abspath(os.path.join(duk_tmp_dir, "java.js"))

    subprocess.check_call([node_script_path("frida-compile"), "./runtime/entrypoint-duktape.js", "-o", runtime, "-c"], cwd=input_dir)
    subprocess.check_call([node_script_path("frida-compile"), "./runtime/promise.js", "-o", promise, "-c"], cwd=input_dir)
    subprocess.check_call([node_script_path("frida-compile"), "./runtime/objc.js", "-o", objc, "-c"], cwd=input_dir)
    subprocess.check_call([node_script_path("frida-compile"), "./runtime/java.js", "-o", java, "-c"], cwd=input_dir)

    generate_runtime_duk("runtime", output_dir, "gumdukscript-runtime.h", input_dir, [runtime])
    generate_runtime_duk("promise", output_dir, "gumdukscript-promise.h", input_dir, [promise])
    generate_runtime_duk("objc", output_dir, "gumdukscript-objc.h", input_dir, [objc])
    generate_runtime_duk("java", output_dir, "gumdukscript-java.h", input_dir, [java])
