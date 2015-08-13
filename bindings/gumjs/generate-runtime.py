#!/usr/bin/env python

import codecs
import os
import sys

def generate_runtime(output_dir, output, input_dir, inputs):
    with codecs.open(os.path.join(output_dir, output), 'wb', 'utf-8') as output_file:
        output_file.write("""\
#include "gumscriptbundle.h"

static const {entry_type} {entries_identifier}[] =
{{""".format(entry_type="GumScriptSource",
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
    if filename.startswith("gum"):
        result = "gum_"
        filename = filename[3:]
    else:
        result = ""
    return result + os.path.splitext(filename)[0].lower().replace("-", "_")


if __name__ == '__main__':
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]

    generate_runtime(output_dir, "gumscript-runtime.h", input_dir, [
        "gumscript-runtime-core.js",
        "gumscript-runtime-java.js",
        "gumscript-runtime-objc.js",
    ])

    generate_runtime(output_dir, "gumscript-debug.h", input_dir, [
        "gumscript-debug.js",
    ])
