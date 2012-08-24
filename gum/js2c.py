#!/usr/bin/env python

import sys

def find_indent_level(line):
    level = 0
    for c in line:
        if c == ' ':
            level += 0.5
        else:
            break
    return int(level)

for line in sys.stdin:
    if line.lstrip().startswith("//"):
        continue
    escaped_line = line.replace('\\', '\\\\').replace('"', '\\"').rstrip()
    level = find_indent_level(escaped_line)
    indent_str = '  ' * level
    print '%s\"%s\"' % (indent_str, escaped_line.lstrip())
