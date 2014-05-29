#!/usr/bin/env python3

import codecs
import sys

MAX_LINE_LENGTH = 80
INDENT = 8
QUOTATION_OVERHEAD = 2
LINE_OVERHEAD = 1
NULL_TERMINATOR_SIZE = 1
MAX_CHARACTER_SIZE = 4
# MSVC's limit is roughly 65535 bytes, but we'll play it safe
MAX_LITERAL_SIZE = 32768

# MSVC's individual quoted string limit is 2048 bytes
assert MAX_LINE_LENGTH <= 2048 / MAX_CHARACTER_SIZE

def read_js_code(source):
    result = ""
    for line in source:
        if line.lstrip().startswith("//"):
            continue
        result += line.replace('\\', '\\\\').replace('"', '\\"').strip()
    return result

def write_c_code(js_code, sink):
    pending = js_code
    size = 0
    while len(pending) > 0:
        chunk_length = min(MAX_LINE_LENGTH - INDENT - QUOTATION_OVERHEAD, len(pending))
        while True:
            chunk = pending[:chunk_length]
            chunk_size = len(chunk.encode('utf-8'))
            if size + chunk_size + LINE_OVERHEAD + NULL_TERMINATOR_SIZE <= MAX_LITERAL_SIZE:
                pending = pending[chunk_length:]
                size += chunk_size + LINE_OVERHEAD
                break
            chunk_length -= 1
        sink.write((" " * INDENT) + "\"" + chunk + "\"")
        capacity = MAX_LITERAL_SIZE - size
        if capacity < INDENT + QUOTATION_OVERHEAD + MAX_CHARACTER_SIZE + LINE_OVERHEAD + NULL_TERMINATOR_SIZE:
            sink.write(",")
            size = 0
        if len(pending) > 0:
            sink.write("\n")
    if size != 0:
        sink.write(",")
    sink.write("\n")

sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
write_c_code(read_js_code(sys.stdin), sys.stdout)
