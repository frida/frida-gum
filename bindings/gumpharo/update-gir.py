#!/usr/bin/env python3
import pathlib
import shutil
import sys
import xml.etree.ElementTree as ET

NS = {"g": "http://www.gtk.org/introspection/core/1.0"}

PLATFORM_BACKENDS = ["backend-darwin", "backend-linux", "backend-windows",
                     "backend-freebsd", "backend-qnx", "backend-barebone",
                     "backend-dbghelp"]


def main(argv):
    scanned = pathlib.Path(argv[1])
    checked_in = pathlib.Path(__file__).parent / "Gum-1.0.gir"

    intruders = platform_specific_entries(scanned)
    if intruders:
        sys.stderr.write("scanned gir carries per-platform API:\n")
        for name in sorted(intruders):
            sys.stderr.write("  %s\n" % name)
        raise SystemExit(1)

    shutil.copy(scanned, checked_in)


def platform_specific_entries(gir):
    found = set()
    for element in ET.parse(gir).getroot().iter():
        position = element.find("g:source-position", NS)
        if position is None:
            continue
        filename = position.get("filename", "")
        if any(backend in filename for backend in PLATFORM_BACKENDS):
            found.add(filename)
    return found


if __name__ == "__main__":
    main(sys.argv)
