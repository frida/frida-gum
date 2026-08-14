#!/usr/bin/env python3
import argparse
import io
import pathlib
import shutil
import subprocess
import sys
import urllib.request
import zipfile

IMAGE_URL = "https://files.pharo.org/image/130/Pharo13.0-SNAPSHOT.build.732.sha.e84a2d15c7.arch.64bit.zip"


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--handwritten", required=True)
    parser.add_argument("--generated-source", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args(argv[1:])

    output = pathlib.Path(arguments.output)
    workdir = output.parent / "image"

    stage_packages(pathlib.Path(arguments.handwritten),
                   pathlib.Path(arguments.generated_source).parent / "pharo",
                   workdir / "tonel")
    fetch_image(workdir)
    load_packages(arguments.host, workdir, output)


def stage_packages(handwritten, generated, tonel):
    if tonel.exists():
        shutil.rmtree(tonel)
    shutil.copytree(handwritten, tonel)
    for source in (generated / "GumPharo").iterdir():
        shutil.copy(source, tonel / "GumPharo" / source.name)


def fetch_image(workdir):
    if next(workdir.glob("Pharo*.image"), None) is not None:
        return

    workdir.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(IMAGE_URL) as response:
        zipfile.ZipFile(io.BytesIO(response.read())).extractall(workdir)


def load_packages(host, workdir, output):
    pristine = next(workdir.glob("Pharo*.image"))
    shutil.copy(pristine, output)
    changes = pristine.with_suffix(".changes")
    if changes.exists():
        shutil.copy(changes, output.with_suffix(".changes"))

    run(host, "--headless", str(output), "eval", "--save",
        "Metacello new repository: 'tonel://%s'; baseline: 'GumPharo'; load. 'ok'"
        % (workdir / "tonel"))


def run(*command):
    result = subprocess.run(command, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    if result.returncode != 0:
        sys.stderr.write(result.stdout.decode("utf-8", "replace"))
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main(sys.argv)
