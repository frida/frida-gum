#!/usr/bin/env python3
import gzip
import pathlib
import shutil
import sys


def main(argv):
    source = pathlib.Path(argv[1])
    destination = pathlib.Path(argv[2])

    with source.open("rb") as raw, \
            gzip.GzipFile(destination, "wb", compresslevel=9, mtime=0) as packed:
        shutil.copyfileobj(raw, packed)


if __name__ == "__main__":
    main(sys.argv)
