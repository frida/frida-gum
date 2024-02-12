#!/usr/bin/env python3

import json
from pathlib import Path
import re
import sys


MACRO_DEFINE_PATTERN = re.compile(r"^#\s*define\s")
STRING_LITERAL_PATTERN = re.compile(r"\"[^\"]+?\"")

def function_parameters_are_aligned(match):
    lines = match.group(1).rstrip().split("\n")
    if lines[0].endswith(" ="):
        return True

    if len(lines) < 2:
        return False

    if lines[1].endswith(" ="):
        return True

    offset = lines[1].find("(")
    if offset == -1:
        return False

    if offset == len(lines[1]) - 1:
        offset = 3

    expected_num_leading_spaces = offset + 1
    for line in lines[2:]:
        num_leading_spaces = len(line) - len(line.lstrip(" "))
        if num_leading_spaces != expected_num_leading_spaces:
            return False

    return True

COMMON_MISTAKES = [
    (
        "line exceeds 80 columns",
        re.compile(r"^.{81}()", re.MULTILINE),
    ),
    (
        "missing space before parentheses",
        re.compile(r"\w()\("),
        ("unless-line-matches", MACRO_DEFINE_PATTERN),
        ("unless-found-inside", STRING_LITERAL_PATTERN),
    ),
    (
        "missing space after cast",
        re.compile(r"\([^()]+\)()\w"),
    ),
    (
        "missing space in pointer declaration",
        re.compile(r"\w+()\* \w+"),
    ),
    (
        "missing space in pointer declaration",
        re.compile(r"\w+ \*()\w+"),
        ("unless-line-matches", re.compile(r"\s+return \*")),
    ),
    (
        "blank line after block start",
        re.compile("{\n(\n)"),
    ),
    (
        "blank line before block end",
        re.compile("\n(\n)}"),
    ),
    (
        "two or more consecutive blank lines",
        re.compile("\n(\n{2})"),
    ),
    (
        "opening brace on the same line as the statement opening it",
        re.compile(r"^.+\)[^\n]*({)", re.MULTILINE),
        ("unless-line-matches", MACRO_DEFINE_PATTERN),
        ("unless-found-inside", STRING_LITERAL_PATTERN),
    ),
    (
        "incorrectly formatted function definition",
        re.compile(r"^(static [^;{]+){", re.MULTILINE),
        ("unless-true", function_parameters_are_aligned),
    ),
]

COMMENT_PATTERN = re.compile(r"\/\*(.+?)\*\/", re.DOTALL)

INCLUDED_EXTENSIONS = {
    ".c",
    ".h",
    ".cpp",
    ".hpp",
}

EXCLUDED_SOURCES = {
    "gum/dlmalloc.c",
    "gum/gummetalhash.c",
    "gum/gummetalhash.h",
    "gum/gumprintf.c",
    "gum/valgrind.h",
}


def main():
    changed_lines = json.loads(sys.argv[1])

    repo_dir = Path(__file__).parent.parent.resolve()
    changed_files = [Path(repo_dir / f) for f in changed_lines.keys()]
    files_to_check = [f for f in changed_files if f.suffix in INCLUDED_EXTENSIONS]

    num_mistakes_found = 0
    for path in files_to_check:
        relpath = path.relative_to(repo_dir).as_posix()
        if relpath in EXCLUDED_SOURCES:
            continue

        code = path.read_text(encoding="utf-8")
        lines = code.split("\n")

        comment_lines = set()
        for m in COMMENT_PATTERN.finditer(code):
            start_offset, end_offset = m.span(1)
            start_line = offset_to_line(start_offset, code)
            end_line = offset_to_line(end_offset, code)
            for i in range(start_line, end_line + 1):
                comment_lines.add(i)

        for (description, pattern, *predicates) in COMMON_MISTAKES:
            for match in pattern.finditer(code):
                match_offset = match.start(1)
                line_number = offset_to_line(match_offset, code)

                if line_number in comment_lines:
                    continue

                prev_newline_offset = code.rfind("\n", 0, match_offset)
                if prev_newline_offset == -1:
                    prev_newline_offset = 0
                line_offset = match_offset - prev_newline_offset

                is_actual_mistake = True
                line = lines[line_number - 1]
                for (condition, parameter) in predicates:
                    if condition == "unless-line-matches":
                        if parameter.match(line) is not None:
                            is_actual_mistake = False
                    elif condition == "unless-found-inside":
                        for m in parameter.finditer(line):
                            start, end = m.span()
                            if line_offset >= start and line_offset < end:
                                is_actual_mistake = False
                                break
                    elif condition == "unless-true":
                        if parameter(match):
                            is_actual_mistake = False
                    else:
                        assert False, "unexpected condition"
                    if not is_actual_mistake:
                        break

                if is_actual_mistake and line_number in changed_lines[relpath]:
                    print(f"{relpath}:{line_number}: {description}")
                    num_mistakes_found += 1

    sys.exit(0 if num_mistakes_found == 0 else 1)


def offset_to_line(i, code):
    return len(code[:i].split("\n"))


if __name__ == "__main__":
    main()
