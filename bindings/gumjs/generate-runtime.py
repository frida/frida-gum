from base64 import b64decode
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


RELAXED_DEPS = {
    "frida-compile": "^10.2.5",
}

EXACT_DEPS = {
    "frida-java-bridge": "6.3.7",
    "frida-objc-bridge": "7.1.0",
    "frida-swift-bridge": "2.0.8"
}


def main(argv):
    output_dir, priv_dir, input_dir, gum_dir, capstone_incdir, libtcc_incdir, npm, quickcompile = \
            [Path(d).resolve() if d else None for d in argv[1:9]]
    backends = set(argv[9].split(","))
    arch, endian = argv[10:]

    try:
        generate_runtime(output_dir, priv_dir, input_dir, gum_dir, capstone_incdir, libtcc_incdir,
                         npm, quickcompile,
                         backends, arch, endian)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)


def generate_runtime(output_dir, priv_dir, input_dir, gum_dir, capstone_incdir, libtcc_incdir, npm, quickcompile, backends, arch, endian):
    frida_compile = priv_dir / "node_modules" / ".bin" / make_script_filename("frida-compile")
    if not frida_compile.exists():
        if priv_dir.exists():
            shutil.rmtree(priv_dir)
        priv_dir.mkdir()

        (priv_dir / "tsconfig.json").write_text("{ \"files\": [], \"compilerOptions\": { \"typeRoots\": [] } }", encoding="utf-8")

        subprocess.run([npm, "init", "-y"],
                       capture_output=True,
                       cwd=priv_dir,
                       check=True)
        subprocess.run([npm, "install"] + [f"{name}@{version_spec}" for name, version_spec in RELAXED_DEPS.items()],
                       capture_output=True,
                       cwd=priv_dir,
                       check=True)
        subprocess.run([npm, "install", "-E"] + [f"{name}@{version_spec}" for name, version_spec in EXACT_DEPS.items()],
                       capture_output=True,
                       cwd=priv_dir,
                       check=True)

    runtime_reldir = Path("runtime")
    runtime_srcdir = input_dir / runtime_reldir
    runtime_intdir = priv_dir / runtime_reldir
    if runtime_intdir.exists():
        shutil.rmtree(runtime_intdir)
    shutil.copytree(runtime_srcdir, runtime_intdir)

    call_compiler = lambda *args: subprocess.run([frida_compile, *args], cwd=priv_dir, check=True)

    if "qjs" in backends:
        quick_tmp_dir = Path("out-qjs")
        runtime = quick_tmp_dir / "frida.js"
        objc = quick_tmp_dir / "objc.js"
        swift = quick_tmp_dir / "swift.js"
        java = quick_tmp_dir / "java.js"

        quick_options = [
            "-c", # Compress for smaller code and better performance.
        ]
        call_compiler(runtime_reldir / "entrypoint-quickjs.js", "-o", runtime, *quick_options)
        call_compiler(runtime_reldir / "objc.js", "-o", objc, *quick_options)
        call_compiler(runtime_reldir / "swift.js", "-o", swift, *quick_options)
        call_compiler(runtime_reldir / "java.js", "-o", java, *quick_options)

        qcflags = []
        if endian != sys.byteorder:
            qcflags.append("--bswap")

        generate_runtime_quick("runtime", output_dir, priv_dir, "gumquickscript-runtime.h", [runtime], quickcompile, qcflags)
        generate_runtime_quick("objc", output_dir, priv_dir, "gumquickscript-objc.h", [objc], quickcompile, qcflags)
        generate_runtime_quick("swift", output_dir, priv_dir, "gumquickscript-swift.h", [swift], quickcompile, qcflags)
        generate_runtime_quick("java", output_dir, priv_dir, "gumquickscript-java.h", [java], quickcompile, qcflags)

    if "v8" in backends:
        v8_tmp_dir = Path("out-v8")
        runtime = v8_tmp_dir / "frida.js"
        objc = v8_tmp_dir / "objc.js"
        swift = v8_tmp_dir / "swift.js"
        java = v8_tmp_dir / "java.js"

        v8_options = [
            "-c", # Compress for smaller code and better performance.
        ]
        call_compiler(runtime_reldir / "entrypoint-v8.js", "-o", runtime, *v8_options)
        call_compiler(runtime_reldir / "objc.js", "-o", objc, *v8_options)
        call_compiler(runtime_reldir / "swift.js", "-o", swift, *v8_options)
        call_compiler(runtime_reldir / "java.js", "-o", java, *v8_options)

        generate_runtime_v8("runtime", output_dir, priv_dir, "gumv8script-runtime.h", [runtime])
        generate_runtime_v8("objc", output_dir, priv_dir, "gumv8script-objc.h", [objc])
        generate_runtime_v8("swift", output_dir, priv_dir, "gumv8script-swift.h", [swift])
        generate_runtime_v8("java", output_dir, priv_dir, "gumv8script-java.h", [java])

    generate_runtime_cmodule(output_dir, "gumcmodule-runtime.h", input_dir, gum_dir, capstone_incdir, libtcc_incdir, arch)

    (output_dir / "runtime.bundle").write_bytes(b"")


def generate_runtime_quick(runtime_name, output_dir, priv_dir, output, inputs, quickcompile, flags):
    with (output_dir / output).open('w', encoding='utf-8') as output_file:
        output_file.write("#include \"gumquickbundle.h\"\n")

        modules = []
        for input_relpath in inputs:
            input_path = priv_dir / input_relpath
            stem = input_relpath.stem

            input_quick_relpath = input_relpath.parent / (stem + ".qjs")
            input_quick_path = priv_dir / input_quick_relpath
            subprocess.run([quickcompile] + flags + [input_relpath, input_quick_relpath], cwd=priv_dir, check=True)
            bytecode = input_quick_path.read_bytes()
            bytecode_size = len(bytecode)

            stem_cname = identifier(stem)
            input_bytecode_identifier = "gumjs_{0}_bytecode".format(stem_cname)
            input_source_map_identifier = "gumjs_{0}_source_map".format(stem_cname)

            output_file.write("\nstatic const guint8 {0}[{1}] =\n{{".format(input_bytecode_identifier, bytecode_size))
            write_bytes(bytecode, output_file, 'unsigned')
            output_file.write("\n};\n")

            source_code = input_path.read_text(encoding='utf-8')
            (stripped_source_code, source_map) = extract_source_map(input_relpath.name, source_code)

            if source_map is not None:
                source_map_bytes = bytearray(source_map.encode('utf-8'))
                source_map_bytes.append(0)
                source_map_size = len(source_map_bytes)

                output_file.write("\nstatic const gchar {0}[{1}] =\n{{".format(input_source_map_identifier, source_map_size))
                write_bytes(source_map_bytes, output_file, 'signed')
                output_file.write("\n};\n")

                modules.append((input_bytecode_identifier, bytecode_size, input_source_map_identifier))
            else:
                output_file.write("\nstatic const gchar {0}[1] = {{ 0 }};\n".format(input_source_map_identifier))
                modules.append((input_bytecode_identifier, bytecode_size, "NULL"))

        output_file.write("\nstatic const GumQuickRuntimeModule gumjs_{0}_modules[] =\n{{".format(runtime_name))
        for bytecode_identifier, bytecode_size, source_map_identifier in modules:
            output_file.write("\n  {{ {0}, {1}, {2} }},".format(bytecode_identifier, bytecode_size, source_map_identifier))
        output_file.write("\n  { NULL, 0, NULL }\n};")


def generate_runtime_v8(runtime_name, output_dir, priv_dir, output, inputs):
    with (output_dir / output).open('w', encoding='utf-8') as output_file:
        output_file.write("#include \"gumv8bundle.h\"\n")

        modules = []
        for input_relpath in inputs:
            input_path = priv_dir / input_relpath
            input_name = input_relpath.name

            stem_cname = identifier(input_relpath.stem)
            input_source_code_identifier = "gumjs_{0}_source_code".format(stem_cname)
            input_source_map_identifier = "gumjs_{0}_source_map".format(stem_cname)

            source_code = input_path.read_text(encoding='utf-8')
            (stripped_source_code, source_map) = extract_source_map(input_name, source_code)
            source_code_bytes = bytearray(stripped_source_code.encode('utf-8'))
            source_code_bytes.append(0)
            source_code_size = len(source_code_bytes)

            output_file.write("\nstatic const gchar {0}[{1}] =\n{{".format(input_source_code_identifier, source_code_size))
            write_bytes(source_code_bytes, output_file, 'signed')
            output_file.write("\n};\n")

            if source_map is not None:
                source_map_bytes = bytearray(source_map.encode('utf-8'))
                source_map_bytes.append(0)
                source_map_size = len(source_map_bytes)

                output_file.write("\nstatic const gchar {0}[{1}] =\n{{".format(input_source_map_identifier, source_map_size))
                write_bytes(source_map_bytes, output_file, 'signed')
                output_file.write("\n};\n")

                modules.append((input_name, input_source_code_identifier, input_source_map_identifier))
            else:
                output_file.write("\nstatic const gchar {0}[1] = {{ 0 }};\n".format(input_source_map_identifier))
                modules.append((input_name, input_source_code_identifier, "NULL"))

        output_file.write("\nstatic const GumV8RuntimeModule gumjs_{0}_modules[] =\n{{".format(runtime_name))
        for filename, source_code_identifier, source_map_identifier in modules:
            output_file.write("\n  {{ \"{0}\", {1}, {2} }},".format(filename, source_code_identifier, source_map_identifier))
        output_file.write("\n  { NULL, NULL, NULL }\n};")


cmodule_function_pattern = re.compile(
        r"^(void|size_t|int|unsigned int|bool|const char \*|gpointer|gsize|gssize|gint[0-9]*|guint[0-9]*|gfloat|gdouble|gboolean||(?:const )?\w+ \*|Gum\w+|csh|cs_err) ([a-z][a-z0-9_]+)\s?\(",
    re.MULTILINE)
cmodule_variable_pattern = re.compile(r"^(extern .+? )(\w+);", re.MULTILINE)
capstone_include_pattern = re.compile(r'^#include "(\w+)\.h"$', re.MULTILINE)
capstone_export_pattern = re.compile(r"^CAPSTONE_EXPORT$", re.MULTILINE)

c_comment_pattern = re.compile(r"\/\*(\*(?!\/)|[^*])*\*\/")
cpp_comment_pattern = re.compile(r"\s+?\/\/.+")


def generate_runtime_cmodule(output_dir, output, input_dir, gum_dir, capstone_incdir, libtcc_incdir, arch):
    if arch.startswith("x86") or arch == "x64":
        writer_arch = "x86"
    elif arch.startswith("mips"):
        writer_arch = "mips"
    else:
        writer_arch = arch
    capstone_arch = writer_arch

    def gum_header_matches_writer(name):
        if writer_arch == "arm":
            return name in ("gumarmwriter.h", "gumthumbwriter.h")
        else:
            return name == "gum" + writer_arch + "writer.h"

    def optimize_gum_header(source):
        return source.replace("GUM_API ", "")

    def capstone_header_matches_arch(name):
        if name in ("capstone.h", "platform.h"):
            return True
        return name == capstone_arch + ".h"

    def optimize_capstone_header(source):
        result = capstone_include_pattern.sub(transform_capstone_include, source)
        result = capstone_export_pattern.sub("", result)
        result = result.replace("CAPSTONE_API ", "")
        return result

    def transform_capstone_include(m):
        name = m.group(1)

        if name in ("platform", capstone_arch):
            return m.group(0)

        if name == "systemz":
            name = "sysz"

        return "typedef int cs_{0};".format(name)

    def libtcc_is_header(name):
        """Ignore symbols from the TinyCC standard library: dlclose() etc."""
        return is_header(name) and name != "tcclib.h"

    inputs = [
        (input_dir / "runtime" / "cmodule", None, is_header, identity_transform, 'GUM_CHEADER_FRIDA'),
        (gum_dir / ("arch-" + writer_arch), gum_dir.parent, gum_header_matches_writer, optimize_gum_header, 'GUM_CHEADER_FRIDA'),
        (capstone_incdir, None, capstone_header_matches_arch, optimize_capstone_header, 'GUM_CHEADER_FRIDA'),
    ]
    if libtcc_incdir is not None:
        inputs += [
            (input_dir / "runtime" / "cmodule-tcc", None, is_header, identity_transform, 'GUM_CHEADER_TCC'),
            (libtcc_incdir, None, libtcc_is_header, identity_transform, 'GUM_CHEADER_TCC'),
        ]

    with (output_dir / output).open('w', encoding='utf-8') as output_file:
        modules = []
        symbols = []

        for header_dir, header_reldir, header_filter, header_transform, header_kind in inputs:
            for header_name, header_source in find_headers(header_dir, header_reldir, header_filter, header_transform):
                input_identifier = "gum_cmodule_{0}".format(identifier(header_name))

                for pattern in (cmodule_function_pattern, cmodule_variable_pattern):
                    for m in pattern.finditer(header_source):
                        name = m.group(2)
                        if name.startswith("cs_arch_register_"):
                            continue
                        symbols.append(name)

                source_bytes = bytearray(header_source.encode('utf-8'))
                source_bytes.append(0)
                source_size = len(source_bytes)

                output_file.write("static const gchar {0}[{1}] =\n{{".format(input_identifier, source_size))
                write_bytes(source_bytes, output_file, 'signed')
                output_file.write("\n};\n\n")

                modules.append((header_name, input_identifier, source_size - 1, header_kind))

        output_file.write("static const GumCHeaderDetails gum_cmodule_headers[] =\n{")
        for input_name, input_identifier, input_size, header_kind in modules:
            output_file.write("\n  {{ \"{0}\", {1}, {2}, {3} }},".format(input_name, input_identifier, input_size, header_kind))
        output_file.write("\n};\n")

        symbol_insertions = ["    g_hash_table_insert (symbols, \"{0}\", GUM_FUNCPTR_TO_POINTER ({0}));".format(name) for name in symbols]
        output_file.write("""
static void gum_cmodule_deinit_symbols (void);

static GHashTable *
gum_cmodule_get_symbols (void)
{{
  static gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {{
    GHashTable * symbols;

    symbols = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4996)
#endif

{insertions}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

    _gum_register_destructor (gum_cmodule_deinit_symbols);

    g_once_init_leave (&gonce_value, GPOINTER_TO_SIZE (symbols) + 1);
  }}

  return GSIZE_TO_POINTER (gonce_value - 1);
}}

static void
gum_cmodule_deinit_symbols (void)
{{
  g_hash_table_unref (gum_cmodule_get_symbols ());
}}
""".format(insertions="\n".join(symbol_insertions)))


def find_headers(include_dir, relative_to_dir, is_header, transform):
    if relative_to_dir is None:
        relative_to_dir = include_dir

    for root, dirs, files in os.walk(include_dir):
        for name in files:
            if is_header(name):
                path = Path(root) /  name
                name = os.path.relpath(path, relative_to_dir).replace("\\", "/")
                source = strip_header(transform(strip_header(path.read_text(encoding='utf-8'))))
                yield (name, source)


def is_header(name):
    return name.endswith(".h")


def identity_transform(v):
    return v


def strip_header(source):
    result = c_comment_pattern.sub("", source)
    result = cpp_comment_pattern.sub("", result)
    while True:
        if "\n\n" not in result:
            break
        result = result.replace("\n\n", "\n")
    return result


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
    return "frida/" + path


def write_bytes(data, sink, encoding):
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
        if encoding == 'signed' and b >= 128:
            b -= 256
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


def make_script_filename(name):
    build_os = platform.system().lower()
    extension = ".cmd" if build_os == 'windows' else ""
    return name + extension


if __name__ == '__main__':
    main(sys.argv)
