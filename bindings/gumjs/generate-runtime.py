#!/usr/bin/env python

from __future__ import unicode_literals, print_function
import codecs
import os
import platform
import subprocess
import sys

def generate_runtime_v8(output_dir, output, input_dir, inputs):
    with codecs.open(os.path.join(output_dir, output), 'wb', 'utf-8') as output_file:
        output_file.write("""\
#include "gumv8bundle.h"

static const {entry_type} {entries_identifier}[] =
{{""".format(entry_type="GumV8Source",
            entries_identifier=underscorify(output) + "_sources"))

        for input_name in inputs:
            output_file.write("""
  {{
    "{filename}",
    {{
""".format(filename=input_name))
            with codecs.open(os.path.join(input_dir, input_name), 'rb', 'utf-8') as input_file:
                write_code(input_file.read(), output_file)
            output_file.write("      NULL\n    }\n  },\n")

        output_file.write("\n  { NULL, { NULL } }\n};")

def generate_runtime_jsc(output_dir, output, input_dir, inputs):
    with codecs.open(os.path.join(output_dir, output), 'wb', 'utf-8') as output_file:
        output_file.write("""\
#include "gumjscbundle.h"

static const {entry_type} {entries_identifier}[] =
{{""".format(entry_type="GumJscSource",
            entries_identifier=underscorify(output) + "_sources"))

        for input_name_es6 in inputs:
            input_path_es6 = os.path.join(input_dir, input_name_es6)

            base, ext = os.path.splitext(input_name_es6)
            input_name_es5 = base + "-es5" + ext
            input_path_es5 = os.path.join(output_dir, input_name_es5)

            subprocess.call(["./node_modules/.bin/babel", "--presets", "es2015", os.path.abspath(input_path_es6), "-o", os.path.abspath(input_path_es5)], cwd=input_dir)

            output_file.write("""
  {{
    "{filename}",
    {{
""".format(filename=input_name_es5))
            with codecs.open(input_path_es5, 'rb', 'utf-8') as input_file:
                write_code(input_file.read(), output_file)
            output_file.write("      NULL\n    }\n  },\n")

        output_file.write("\n  { NULL, { NULL } }\n};")

def generate_runtime_duk(output_dir, output, input_dir, inputs):
    with codecs.open(os.path.join(output_dir, output), 'wb', 'utf-8') as output_file:
        output_file.write("""\
#include "gumdukbundle.h"

static const {entry_type} {entries_identifier}[] =
{{""".format(entry_type="GumDukSource",
            entries_identifier=underscorify(output) + "_sources"))

        for input_name_es6 in inputs:
            input_path_es6 = os.path.join(input_dir, input_name_es6)

            base, ext = os.path.splitext(input_name_es6)
            input_name_es5 = base + "-es5" + ext
            input_path_es5 = os.path.join(output_dir, input_name_es5)

            subprocess.call(["./node_modules/.bin/babel", "--presets", "es2015", os.path.abspath(input_path_es6), "-o", os.path.abspath(input_path_es5)], cwd=input_dir)

            output_file.write("""
  {{
    "{filename}",
    {{
""".format(filename=input_name_es5))
            with codecs.open(input_path_es5, 'rb', 'utf-8') as input_file:
                write_code(input_file.read(), output_file)
            output_file.write("      NULL\n    }\n  },\n")

        output_file.write("\n  { NULL, { NULL } }\n};")
def write_code(js_code, sink):
    MAX_LINE_LENGTH = 80
    INDENT = 6
    QUOTATION_OVERHEAD = 2
    LINE_OVERHEAD = 1
    NULL_TERMINATOR_SIZE = 1
    MAX_CHARACTER_SIZE = 4
    # MSVC's limit is roughly 65535 bytes, but we'll play it safe
    MAX_LITERAL_SIZE = 32768

    # MSVC's individual quoted string limit is 2048 bytes
    assert MAX_LINE_LENGTH <= 2048 / MAX_CHARACTER_SIZE

    pending = js_code.replace('\\', '\\\\').replace('"', '\\"').replace("\n", "\\n")
    size = 0
    while len(pending) > 0:
        chunk_length = min(MAX_LINE_LENGTH - INDENT - QUOTATION_OVERHEAD, len(pending))
        while True:
            chunk = pending[:chunk_length]
            chunk_size = len(chunk.encode('utf-8'))
            if chunk[-1] != "\\" and size + chunk_size + LINE_OVERHEAD + NULL_TERMINATOR_SIZE <= MAX_LITERAL_SIZE:
                pending = pending[chunk_length:]
                size += chunk_size + LINE_OVERHEAD
                break
            chunk_length -= 1
        sink.write((" " * INDENT) + "\"" + chunk + "\"")
        capacity = MAX_LITERAL_SIZE - size
        if capacity < INDENT + QUOTATION_OVERHEAD + (2 * MAX_CHARACTER_SIZE) + LINE_OVERHEAD + NULL_TERMINATOR_SIZE:
            sink.write(",")
            size = 0
        if len(pending) > 0:
            sink.write("\n")
    if size != 0:
        sink.write(",")
    sink.write("\n")

def underscorify(filename):
    if filename.startswith("gumv8"):
        result = "gum_v8_"
        filename = filename[5:]
    elif filename.startswith("gumjsc"):
        result = "gum_jsc_"
        filename = filename[6:]
    elif filename.startswith("gumduk"):
        result = "gum_duk_"
        filename = filename[6:]
    else:
        result = ""
    return result + os.path.splitext(filename)[0].lower().replace("-", "_")


if __name__ == '__main__':
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]

    modules = [
        "gumjs-core.js",
        "gumjs-source-map.js",
        "gumjs-java.js",
        "gumjs-objc.js",
    ]
    jsc_polyfill_modules = [
        "gumjs-promise.js",
    ]
    duk_polyfill_modules = [
        "gumjs-promise.js",
        "harmony-collections.js",
        "gumjs-symbol.js"
    ]
    generate_runtime_v8(output_dir, "gumv8script-runtime.h", input_dir, modules)
    generate_runtime_duk(output_dir, "gumdukscript-runtime.h", input_dir, modules +
                         duk_polyfill_modules)
    if platform.system() == 'Darwin':
        generate_runtime_jsc(output_dir, "gumjscscript-runtime.h", input_dir, modules +
                             jsc_polyfill_modules)

    generate_runtime_v8(output_dir, "gumv8script-debug.h", input_dir, [
        "gumjs-debug.js",
    ])
