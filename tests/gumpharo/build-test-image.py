#!/usr/bin/env python3
import argparse
import ctypes.util
import os
import pathlib
import shutil
import subprocess
import sys


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--handwritten", required=True)
    parser.add_argument("--generated-source", required=True)
    parser.add_argument("--tests", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args(argv[1:])

    image = pathlib.Path(arguments.image)
    output = pathlib.Path(arguments.output)
    tonel = output.parent / "tests-tonel"

    stage(pathlib.Path(arguments.handwritten),
          pathlib.Path(arguments.generated_source).parent / "pharo",
          pathlib.Path(arguments.tests), tonel)

    shutil.copy(image, output)
    changes = image.with_suffix(".changes")
    if changes.exists():
        shutil.copy(changes, output.with_suffix(".changes"))

    run(arguments.host, "--headless", str(output), "eval", "--save",
        "Metacello new repository: 'tonel://%s'; baseline: 'GumPharo'; "
        "onConflict: [ :e | e useIncoming ]; load: 'tests'. 'ok'" % tonel)


def stage(handwritten, generated, tests, tonel):
    if tonel.exists():
        shutil.rmtree(tonel)
    shutil.copytree(handwritten, tonel)
    for source in (generated / "GumPharo").iterdir():
        shutil.copy(source, tonel / "GumPharo" / source.name)
    for package in tests.iterdir():
        shutil.copytree(package, tonel / package.name)


def run(*command):
    result = subprocess.run(command, env=environment_with_freetype(),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        sys.stderr.write(result.stdout.decode("utf-8", "replace"))
        raise SystemExit(result.returncode)


def environment_with_freetype():
    environment = os.environ.copy()

    freetype = ctypes.util.find_library("freetype")
    if freetype is None:
        return environment

    libdir = str(pathlib.Path(freetype).parent)
    for name in ("DYLD_FALLBACK_LIBRARY_PATH", "LD_LIBRARY_PATH"):
        existing = environment.get(name)
        environment[name] = libdir if existing is None else libdir + os.pathsep + existing

    return environment


if __name__ == "__main__":
    main(sys.argv)
