#!/usr/bin/env python

from __future__ import unicode_literals, print_function
import codecs
import os
import re
import sys

def generate_and_write_bindings(source_dir, output_dir):
    binding_params = [
        ("writer", { 'ignore': ['new', 'ref', 'unref', 'init', 'clear', 'reset',
                                'set_target_cpu', 'set_target_abi', 'set_target_os',
                                'cur', 'offset', 'flush', 'get_cpu_register_for_nth_argument'] }),
        ("relocator", { 'ignore': ['new', 'ref', 'unref', 'init', 'clear', 'reset',
                                   'read_one', 'eob', 'eoi', 'can_relocate'] }),
    ]

    flavor_combos = [
        ("x86", "x86"),
        ("arm", "arm"),
        ("arm", "thumb"),
        ("arm64", "arm64"),
        ("mips", "mips"),
    ]

    docs = {}

    for name, options in binding_params:
        for filename, code in generate_umbrellas(name, flavor_combos).items():
            with codecs.open(os.path.join(output_dir, filename), "w", 'utf-8') as f:
                f.write(code)

        for arch, flavor in flavor_combos:
            api_header_path = os.path.join(source_dir, "arch-" + arch, "gum{0}{1}.h".format(flavor, name))
            with codecs.open(api_header_path, "r", 'utf-8') as f:
                api_header = f.read()

            bindings = generate_bindings(name, arch, flavor, api_header, options)

            for filename, code in bindings.code.items():
                with codecs.open(os.path.join(output_dir, filename), "w", 'utf-8') as f:
                    f.write(code)

            docs.update(bindings.docs)

    sections = []
    for arch, flavor in flavor_combos:
        for name, options in binding_params:
            sections.append(docs["{0}-{1}.md".format(flavor, name)])
        if flavor != "arm":
            sections.append(docs["{0}-enums.md".format(arch)])
    api_reference = "\n\n".join(sections)
    with codecs.open(os.path.join(output_dir, "api-reference.md"), "w", 'utf-8') as f:
        f.write(api_reference)

def generate_umbrellas(name, flavor_combos):
    umbrellas = {}
    for runtime in ["duk", "v8"]:
        for section in ["", "-fields", "-methods", "-init", "-dispose"]:
            filename, code = generate_umbrella(runtime, name, section, flavor_combos)
            umbrellas[filename] = code
    return umbrellas

def generate_umbrella(runtime, name, section, flavor_combos):
    lines = []

    arch_defines = {
        "x86": "HAVE_I386",
        "arm": "HAVE_ARM",
        "arm64": "HAVE_ARM64",
        "mips": "HAVE_MIPS",
    }

    current_arch = None
    for arch, flavor in flavor_combos:
        if arch != current_arch:
            if current_arch is not None:
                lines.append("#endif")
            lines.append("#ifdef " + arch_defines[arch])
            current_arch = arch
        lines.append("# include \"gum{0}code{1}{2}-{3}.inc\"".format(runtime, name, section, flavor))
    lines.append("#endif")

    filename = "gum{0}code{1}{2}.inc".format(runtime, name, section)
    code = "\n".join(lines)

    return (filename, code)

class Bindings(object):
    def __init__(self, code, docs):
        self.code = code
        self.docs = docs

def generate_bindings(name, arch, flavor, api_header, options):
    api = parse_api(name, flavor, api_header, options)

    code = {}
    code.update(generate_duk_bindings(name, arch, flavor, api))
    code.update(generate_v8_bindings(name, arch, flavor, api))

    docs = generate_docs(name, arch, flavor, api)

    return Bindings(code, docs)

def generate_duk_bindings(name, arch, flavor, api):
    component = Component(name, arch, flavor, "duk")
    return {
        "gumdukcode{0}-{1}.inc".format(name, flavor): generate_duk_wrapper_code(component, api),
        "gumdukcode{0}-fields-{1}.inc".format(name, flavor): generate_duk_fields(component),
        "gumdukcode{0}-methods-{1}.inc".format(name, flavor): generate_duk_methods(component),
        "gumdukcode{0}-init-{1}.inc".format(name, flavor): generate_duk_init_code(component),
        "gumdukcode{0}-dispose-{1}.inc".format(name, flavor): generate_duk_dispose_code(component),
    }

def generate_duk_wrapper_code(component, api):
    lines = [
        "/* Auto-generated, do not edit. */",
        "",
        "#include <gum/arch-{0}/gum{1}{2}.h>".format(component.arch, component.flavor, component.name),
        "#include <string.h>",
        "",
        "typedef struct _{0} {0};".format(component.wrapper_struct_name),
        "",
        "struct _{0}".format(component.wrapper_struct_name),
        "{",
        "  {0} * impl;".format(component.impl_struct_name),
    ]

    if component.name == "relocator":
        lines.append("  const cs_insn * input;")

    lines.extend([
        "  {0} * module;".format(component.module_struct_name),
        "};",
    ])

    conversion_decls, conversion_code = generate_conversion_methods(component, generate_duk_enum_parser)
    if len(conversion_decls) > 0:
        lines.append("")
        lines.extend(conversion_decls)

    lines.append("")

    lines.extend(generate_duk_base_methods(component))

    for method in api.instance_methods:
        args = method.args

        is_put_array = method.is_put_array
        if method.is_put_call:
            array_item_type = "GumArgument"
            array_item_parse_logic = generate_duk_parse_call_arg_array_element(component)
        elif method.is_put_regs:
            array_item_type = api.native_register_type
            array_item_parse_logic = generate_duk_parse_register_array_element(component)

        lines.extend([
            "GUMJS_DEFINE_FUNCTION ({0}_{1})".format(component.gumjs_function_prefix, method.name),
            "{",
            "  {0} * self;".format(component.wrapper_struct_name),
        ])

        for arg in args:
            type_raw = arg.type_raw
            if type_raw == "$array":
                type_raw = "GumDukHeapPtr"
            lines.append("  {0} {1};".format(type_raw, arg.name_raw))
            converter = arg.type_converter
            if converter is not None:
                if converter == "bytes":
                    lines.extend([
                        "  const guint8 * {0};".format(arg.name),
                        "  gsize {0}_size;".format(arg.name)
                    ])
                else:
                    lines.append("  {0} {1};".format(arg.type, arg.name))
        if is_put_array:
            lines.extend([
                "  duk_uarridx_t items_length, items_index;",
                "  {0} * items;".format(array_item_type),
            ])

        if method.return_type == "void":
            return_capture = ""
        else:
            lines.append("  {0} result;".format(method.return_type))
            return_capture = "result = "

        lines.extend([
            "",
            "  self = {0}_from_args (args);".format(component.wrapper_function_prefix)
        ])

        if len(args) > 0:
            arglist_signature = "".join([arg.type_format for arg in args])
            arglist_pointers = ", ".join(["&" + arg.name_raw for arg in args])

            lines.extend([
                "",
                "  _gum_duk_args_parse (args, \"{0}\", {1});".format(arglist_signature, arglist_pointers)
            ])

        args_needing_conversion = [arg for arg in args if arg.type_converter is not None]
        if len(args_needing_conversion) > 0:
            lines.append("")
            for arg in args_needing_conversion:
                converter = arg.type_converter
                if converter == "address":
                    lines.append("  {value} = GUM_ADDRESS ({value_raw});".format(
                        value=arg.name,
                        value_raw=arg.name_raw))
                elif converter == "bytes":
                    lines.append("  {value} = g_bytes_get_data ({value_raw}, &{value}_size);".format(
                        value=arg.name,
                        value_raw=arg.name_raw))
                else:
                    lines.append("  {value} = gum_parse_{arch}_{type} (ctx, {value_raw});".format(
                        value=arg.name,
                        value_raw=arg.name_raw,
                        arch=component.arch,
                        type=arg.type_converter))

        if is_put_array:
            lines.extend(generate_duk_parse_array_elements(array_item_type, array_item_parse_logic).split("\n"))

        impl_function_name = "{0}_{1}".format(component.impl_function_prefix, method.name)

        arglist = ["self->impl"]
        if method.needs_calling_convention_arg:
            arglist.append("GUM_CALL_CAPI")
        for arg in args:
            if arg.type_converter == "bytes":
                arglist.extend([arg.name, arg.name + "_size"])
            else:
                arglist.append(arg.name)
        if is_put_array:
            impl_function_name += "_array"
            arglist.insert(len(arglist) - 1, "items_length")

        lines.extend([
            "",
            "  {0}{1} ({2});".format(return_capture, impl_function_name, ", ".join(arglist))
        ])

        args_needing_cleanup = [arg for arg in args if arg.type_converter == "bytes"]
        if len(args_needing_cleanup) > 0:
            lines.append("")
            for arg in args_needing_cleanup:
                lines.append("  g_bytes_unref ({0});".format(arg.name_raw))

        if method.return_type == "gboolean" and method.name.startswith("put_"):
            if len(args_needing_cleanup) > 0:
                lines.append("")
            lines.extend([
                "  if (!result)",
                "    _gum_duk_throw (ctx, \"invalid argument\");",
                "",
                "  return 0;",
            ])
        elif method.return_type == "void":
            lines.append("")
            lines.append("  return 0;")
        else:
            lines.append("")
            if method.return_type == "gboolean":
                lines.append("  duk_push_boolean (ctx, result);")
            elif method.return_type == "guint":
                lines.append("  duk_push_uint (ctx, result);")
            elif method.return_type == "gpointer":
                lines.append("  _gum_duk_push_native_pointer (ctx, result, args->core);")
            elif method.return_type == "cs_insn *":
                if component.flavor == "x86":
                    target = "GSIZE_TO_POINTER (result->address)"
                else:
                    target = "self->impl->input_start + (result->address - (self->impl->input_pc - self->impl->inpos))"
                    if component.flavor == "thumb":
                        target = "GSIZE_TO_POINTER (GPOINTER_TO_SIZE ({0}) | 1)".format(target)
                lines.extend([
                    "  if (result != NULL)",
                    "  {",
                    "    _gum_duk_push_instruction (ctx, result, {0}, self->module->instruction);".format(target),
                    "  }",
                    "  else",
                    "  {",
                    "    duk_push_null (ctx);"
                    "  }",
                ])
            else:
                raise ValueError("Unsupported return type: {0}".format(method.return_type))
            lines.append("  return 1;")

        lines.extend([
            "}",
            ""
        ])

    lines.extend([
        "static const duk_function_list_entry {0}_functions[] =".format(component.gumjs_function_prefix),
        "{",
    ])
    if component.name == "writer":
        lines.extend([
            "  {{ \"reset\", {0}_reset, 1 }},".format(component.gumjs_function_prefix),
            "  {{ \"dispose\", {0}_dispose, 0 }},".format(component.gumjs_function_prefix),
            "  {{ \"flush\", {0}_flush, 0 }},".format(component.gumjs_function_prefix),
        ])
    elif component.name == "relocator":
        lines.extend([
            "  {{ \"reset\", {0}_reset, 2 }},".format(component.gumjs_function_prefix),
            "  {{ \"dispose\", {0}_dispose, 0 }},".format(component.gumjs_function_prefix),
            "  {{ \"readOne\", {0}_read_one, 0 }},".format(component.gumjs_function_prefix),
        ])

    for method in api.instance_methods:
        lines.append("  {{ \"{0}\", {1}_{2}, {3} }},".format(
            method.name_js,
            component.gumjs_function_prefix,
            method.name,
            len(method.args)
        ))

    lines.extend([
        "",
        "  { NULL, NULL, 0 }",
        "};",
        ""
    ])

    lines.extend(conversion_code)

    return "\n".join(lines)

def generate_duk_parse_array_elements(item_type, parse_item):
    return """
  duk_push_heapptr (ctx, items_value);
  items_length = (duk_uarridx_t) duk_get_length (ctx, -1);
  items = g_alloca (items_length * sizeof ({item_type}));

  for (items_index = 0; items_index != items_length; items_index++)
  {{
    {item_type} * item = &items[items_index];

    duk_get_prop_index (ctx, -1, items_index);
{parse_item}

    duk_pop (ctx);
  }}

  duk_pop (ctx);""".format(item_type=item_type, parse_item=parse_item)

def generate_duk_parse_call_arg_array_element(component):
    return """
    if (duk_is_string (ctx, -1))
    {{
      item->type = GUM_ARG_REGISTER;
      item->value.reg = gum_parse_{arch}_register (ctx, duk_require_string (ctx, -1));
    }}
    else
    {{
      gpointer ptr;
      item->type = GUM_ARG_ADDRESS;
      if (!_gum_duk_parse_pointer (ctx, -1, args->core, &ptr))
        _gum_duk_throw (ctx, "expected a pointer or number");
      item->value.address = GUM_ADDRESS (ptr);
    }}""".format(arch=component.arch)

def generate_duk_parse_register_array_element(component):
    return """
    *item = gum_parse_{arch}_register (ctx, duk_require_string (ctx, -1));""".format(arch=component.arch)

def generate_duk_fields(component):
    return "  GumDukHeapPtr {0}_{1};".format(component.flavor, component.name)

def generate_duk_methods(component):
    if component.name == "writer":
        template = """\
#include <gum/arch-{arch}/gum{flavor}{name}.h>

G_GNUC_INTERNAL {impl_struct_name} * _gum_duk_require_{flavor}_writer (duk_context * ctx,
    duk_idx_t index, {module_struct_name} * module);"""
        return template.format(**component.__dict__)
    return ""

def generate_duk_init_code(component):
    return """\
  duk_push_c_function (ctx, {gumjs_function_prefix}_construct, 2);
  duk_push_object (ctx);
  _gum_duk_add_properties_to_class_by_heapptr (ctx,
      duk_require_heapptr (ctx, -1), {gumjs_function_prefix}_values);
  duk_put_function_list (ctx, -1, {gumjs_function_prefix}_functions);
  duk_push_c_function (ctx, {gumjs_function_prefix}_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->{gumjs_field_name} = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "{gumjs_class_name}");
""".format(**component.__dict__)

def generate_duk_dispose_code(component):
    return """\
  _gum_duk_release_heapptr (scope.ctx, self->{gumjs_field_name});
""".format(**component.__dict__)

def generate_duk_base_methods(component):
    if component.name == "writer":
        return generate_duk_writer_base_methods(component)
    elif component.name == "relocator":
        return generate_duk_relocator_base_methods(component)

def generate_duk_writer_base_methods(component):
    template = """\
{impl_struct_name} *
_gum_duk_require_{flavor}_writer (duk_context * ctx,
{require_writer_arglist_indent}duk_idx_t index,
{require_writer_arglist_indent}{module_struct_name} * module)
{{
  {wrapper_struct_name} * writer;

  duk_dup (ctx, index);
  duk_push_heapptr (ctx, module->{flavor}_writer);
  if (!duk_instanceof (ctx, -2, -1))
    _gum_duk_throw (ctx, "expected {flavor} writer");

  writer = _gum_duk_require_data (ctx, -2);
  if (writer == NULL)
    _gum_duk_throw (ctx, "writer is disposed");

  duk_pop_2 (ctx);

  return writer->impl;
}}

static {wrapper_struct_name} *
{wrapper_function_prefix}_new (gpointer code_address,
{wrapper_ctor_arglist_indent}{module_struct_name} * module)
{{
  {wrapper_struct_name} * writer;

  writer = g_slice_new ({wrapper_struct_name});
  writer->impl = {impl_function_prefix}_new (code_address);
  writer->module = module;

  return writer;
}}

static void
{wrapper_function_prefix}_free ({wrapper_struct_name} * self)
{{
  {impl_function_prefix}_unref (self->impl);

  g_slice_free ({wrapper_struct_name}, self);
}}

static {wrapper_struct_name} *
{wrapper_function_prefix}_from_args (const GumDukArgs * args)
{{
  duk_context * ctx = args->ctx;
  {wrapper_struct_name} * self;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  if (self == NULL)
    _gum_duk_throw (ctx, "writer is disposed");
  duk_pop (ctx);

  return self;
}}

GUMJS_DEFINE_CONSTRUCTOR ({gumjs_function_prefix}_construct)
{{
  gpointer code_address;
  GumDukHeapPtr options;
  GumAddress pc;
  gboolean pc_specified;
  {wrapper_struct_name} * writer;

  if (!duk_is_constructor_call (ctx))
    _gum_duk_throw (ctx, "use constructor syntax to create a new instance");

  options = NULL;
  _gum_duk_args_parse (args, "p|O", &code_address, &options);

  pc = 0;
  pc_specified = FALSE;
  if (options != NULL)
  {{
    duk_push_heapptr (ctx, options);

    duk_get_prop_string (ctx, -1, "pc");
    if (!duk_is_undefined (ctx, -1))
    {{
      pc = GUM_ADDRESS (_gum_duk_require_pointer (ctx, -1, args->core));
      pc_specified = TRUE;
    }}

    duk_pop_2 (ctx);
  }}

  writer = {wrapper_function_prefix}_new (code_address,
      gumjs_module_from_args (args));

  if (pc_specified)
    writer->impl->pc = pc;

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, writer);
  duk_pop (ctx);

  return 0;
}}

GUMJS_DEFINE_FUNCTION ({gumjs_function_prefix}_reset)
{{
  {wrapper_struct_name} * self;
  gpointer code_address, pc;

  self = {wrapper_function_prefix}_from_args (args);

  pc = NULL;
  _gum_duk_args_parse (args, "p|p", &code_address);

  {impl_function_prefix}_reset (self->impl, code_address);

  if (pc != NULL)
    self->impl->pc = GUM_ADDRESS (pc);

  return 0;
}}

GUMJS_DEFINE_FUNCTION ({gumjs_function_prefix}_dispose)
{{
  {wrapper_struct_name} * self;

  duk_push_this (ctx);
  self = _gum_duk_steal_data (ctx, -1);
  duk_pop (ctx);

  if (self != NULL)
    {wrapper_function_prefix}_free (self);

  return 0;
}}

GUMJS_DEFINE_FINALIZER ({gumjs_function_prefix}_finalize)
{{
  {wrapper_struct_name} * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  {wrapper_function_prefix}_free (self);

  return 0;
}}

GUMJS_DEFINE_FUNCTION ({gumjs_function_prefix}_flush)
{{
  {wrapper_struct_name} * self;
  gboolean success;

  self = {wrapper_function_prefix}_from_args (args);

  success = {impl_function_prefix}_flush (self->impl);
  if (!success)
    _gum_duk_throw (ctx, "unable to resolve references");

  return 0;
}}

GUMJS_DEFINE_GETTER ({gumjs_function_prefix}_get_offset)
{{
  {wrapper_struct_name} * self;

  self = {wrapper_function_prefix}_from_args (args);

  duk_push_uint (ctx, {impl_function_prefix}_offset (self->impl));
  return 1;
}}

static const GumDukPropertyEntry {gumjs_function_prefix}_values[] =
{{
  {{ "offset", {gumjs_function_prefix}_get_offset, NULL }},

  {{ NULL, NULL, NULL }}
}};
"""

    params = {
        "require_writer_arglist_indent": (len(component.flavor) + 26) * " ",
        "wrapper_ctor_arglist_indent": (len(component.wrapper_function_prefix) + 6) * " "
    }
    params.update(component.__dict__)

    return template.format(**params).split("\n")

def generate_duk_relocator_base_methods(component):
    template = """\
static {wrapper_struct_name} *
{wrapper_function_prefix}_new (gconstpointer input_code,
{wrapper_ctor_arglist_indent}{writer_impl_struct_name} * output,
{wrapper_ctor_arglist_indent}{module_struct_name} * module)
{{
  {wrapper_struct_name} * relocator;

  relocator = g_slice_new ({wrapper_struct_name});
  relocator->impl = {impl_function_prefix}_new (input_code, output);
  relocator->input = NULL;
  relocator->module = module;

  return relocator;
}}

static void
{wrapper_function_prefix}_free ({wrapper_struct_name} * self)
{{
  {impl_function_prefix}_unref (self->impl);

  g_slice_free ({wrapper_struct_name}, self);
}}

static {wrapper_struct_name} *
{wrapper_function_prefix}_from_args (const GumDukArgs * args)
{{
  duk_context * ctx = args->ctx;
  {wrapper_struct_name} * self;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  if (self == NULL)
    _gum_duk_throw (ctx, "relocator is disposed");
  duk_pop (ctx);

  return self;
}}

GUMJS_DEFINE_CONSTRUCTOR ({gumjs_function_prefix}_construct)
{{
  {module_struct_name} * module;
  gconstpointer input_code;
  GumDukHeapPtr writer_object;
  {writer_impl_struct_name} * writer;
  {wrapper_struct_name} * relocator;

  if (!duk_is_constructor_call (ctx))
    _gum_duk_throw (ctx, "use constructor syntax to create a new instance");

  module = gumjs_module_from_args (args);

  _gum_duk_args_parse (args, "pO", &input_code, &writer_object);

  duk_push_heapptr (ctx, writer_object);
  writer = _gum_duk_require_{flavor}_writer (ctx, -1, module->writer);

  relocator = {wrapper_function_prefix}_new (input_code, writer, module);

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, relocator);
  duk_pop_2 (ctx);

  return 0;
}}

GUMJS_DEFINE_FUNCTION ({gumjs_function_prefix}_reset)
{{
  {wrapper_struct_name} * self;
  gconstpointer input_code;
  GumDukHeapPtr writer_object;
  {writer_impl_struct_name} * writer;

  self = {wrapper_function_prefix}_from_args (args);

  _gum_duk_args_parse (args, "pO", &input_code, &writer_object);

  duk_push_heapptr (ctx, writer_object);
  writer = _gum_duk_require_{flavor}_writer (ctx, -1, self->module->writer);
  duk_pop (ctx);

  {impl_function_prefix}_reset (self->impl, input_code, writer);

  self->input = NULL;

  return 0;
}}

GUMJS_DEFINE_FUNCTION ({gumjs_function_prefix}_dispose)
{{
  {wrapper_struct_name} * self;

  duk_push_this (ctx);
  self = _gum_duk_steal_data (ctx, -1);
  duk_pop (ctx);

  if (self != NULL)
    {wrapper_function_prefix}_free (self);

  return 0;
}}

GUMJS_DEFINE_FINALIZER ({gumjs_function_prefix}_finalize)
{{
  {wrapper_struct_name} * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  {wrapper_function_prefix}_free (self);

  return 0;
}}

GUMJS_DEFINE_FUNCTION ({gumjs_function_prefix}_read_one)
{{
  {wrapper_struct_name} * self;
  guint n_read;

  self = {wrapper_function_prefix}_from_args (args);

  n_read = {impl_function_prefix}_read_one (self->impl, &self->input);

  duk_push_uint (ctx, n_read);
  return 1;
}}

GUMJS_DEFINE_GETTER ({gumjs_function_prefix}_get_input)
{{
  {wrapper_struct_name} * self;

  self = {wrapper_function_prefix}_from_args (args);

  if (self->input != NULL)
  {{
    _gum_duk_push_instruction (ctx, self->input,
        {get_input_target_expression},
        self->module->instruction);
  }}
  else
  {{
    duk_push_null (ctx);
  }}
  return 1;
}}

GUMJS_DEFINE_GETTER ({gumjs_function_prefix}_get_eob)
{{
  {wrapper_struct_name} * self;

  self = {wrapper_function_prefix}_from_args (args);

  duk_push_boolean (ctx, {impl_function_prefix}_eob (self->impl));
  return 1;
}}

GUMJS_DEFINE_GETTER ({gumjs_function_prefix}_get_eoi)
{{
  {wrapper_struct_name} * self;

  self = {wrapper_function_prefix}_from_args (args);

  duk_push_boolean (ctx, {impl_function_prefix}_eoi (self->impl));
  return 1;
}}

static const GumDukPropertyEntry {gumjs_function_prefix}_values[] =
{{
  {{ "input", {gumjs_function_prefix}_get_input, NULL }},
  {{ "eob", {gumjs_function_prefix}_get_eob, NULL }},
  {{ "eoi", {gumjs_function_prefix}_get_eoi, NULL }},

  {{ NULL, NULL, NULL }}
}};
"""

    if component.flavor == "x86":
        target = "GSIZE_TO_POINTER (self->input->address)"
    else:
        target = "self->impl->input_start + (self->input->address - (self->impl->input_pc - self->impl->inpos))"
        if component.flavor == "thumb":
            target = "GSIZE_TO_POINTER (GPOINTER_TO_SIZE ({0}) | 1)".format(target)

    params = {
        "writer_impl_struct_name": to_camel_case('gum_{0}_writer'.format(component.flavor), start_high=True),
        "get_input_target_expression": target,
        "wrapper_ctor_arglist_indent": (len(component.wrapper_function_prefix) + 6) * " "
    }
    params.update(component.__dict__)

    return template.format(**params).split("\n")

def generate_duk_enum_parser(name, type, prefix, values):
    common_decls, common_code = generate_enum_parser(name, type, prefix, values)

    params = {
        'name': name,
        'description': name.replace("_", " "),
        'type': type,
        'arglist_indent': (len(name) + 12) * " ",
    }

    decls = [
        "static {type} gum_parse_{name} (duk_context * ctx, const gchar * name);".format(**params)
    ] + common_decls

    code = """\
static {type}
gum_parse_{name} (duk_context * ctx,
{arglist_indent}const gchar * name)
{{
  {type} value = 0;

  if (!gum_try_parse_{name} (name, &value))
    _gum_duk_throw (ctx, "invalid {description}");

  return value;
}}
""".format(**params).split("\n") + common_code

    return (decls, code)

def generate_v8_bindings(name, arch, flavor, api):
    component = Component(name, arch, flavor, "v8")
    return {
        "gumv8code{0}-{1}.inc".format(name, flavor): generate_v8_wrapper_code(component, api),
        "gumv8code{0}-fields-{1}.inc".format(name, flavor): generate_v8_fields(component),
        "gumv8code{0}-methods-{1}.inc".format(name, flavor): generate_v8_methods(component),
        "gumv8code{0}-init-{1}.inc".format(name, flavor): generate_v8_init_code(component),
        "gumv8code{0}-dispose-{1}.inc".format(name, flavor): generate_v8_dispose_code(component),
    }

def generate_v8_wrapper_code(component, api):
    lines = [
        "/* Auto-generated, do not edit. */",
        "",
        "#include <gum/arch-{0}/gum{1}{2}.h>".format(component.arch, component.flavor, component.name),
        "#include <string>",
        "#include <string.h>",
        "",
        "struct {0}".format(component.wrapper_struct_name),
        "{",
        "  GumPersistent<v8::Object>::type * wrapper;",
        "  {0} * impl;".format(component.impl_struct_name),
    ]

    if component.name == "writer":
        lines.append("  GHashTable * labels;")
    elif component.name == "relocator":
        lines.append("  const cs_insn * input;")

    lines.extend([
        "  {0} * module;".format(component.module_struct_name),
        "};",
    ])

    conversion_decls, conversion_code = generate_conversion_methods(component, generate_v8_enum_parser)
    if len(conversion_decls) > 0:
        lines.append("")
        lines.extend(conversion_decls)

    lines.append("")

    lines.extend(generate_v8_base_methods(component))

    for method in api.instance_methods:
        args = method.args

        is_put_array = method.is_put_array
        if method.is_put_call:
            array_item_type = "GumArgument"
            array_item_parse_logic = generate_v8_parse_call_arg_array_element(component, api)
        elif method.is_put_regs:
            array_item_type = api.native_register_type
            array_item_parse_logic = generate_v8_parse_register_array_element(component, api)

        lines.extend([
            "GUMJS_DEFINE_CLASS_METHOD ({0}_{1}, {2})".format(component.gumjs_function_prefix, method.name, component.wrapper_struct_name),
            "{",
            "  if (!{0}_check (self, isolate))".format(component.wrapper_function_prefix),
            "    return;",
        ])

        if len(args) > 0:
            lines.append("")

            for arg in args:
                type_raw = arg.type_raw_for_cpp()
                if type_raw == "$array":
                    type_raw = "Local<Array>"
                lines.append("  {0} {1};".format(type_raw, arg.name_raw_for_cpp()))

            arglist_signature = "".join([arg.type_format_for_cpp() for arg in args])
            arglist_pointers = ", ".join(["&" + arg.name_raw_for_cpp() for arg in args])

            lines.extend([
                "  if (!_gum_v8_args_parse (args, \"{0}\", {1}))".format(arglist_signature, arglist_pointers),
                "    return;",
            ])

        args_needing_conversion = [arg for arg in args if arg.type_converter_for_cpp() is not None]
        if len(args_needing_conversion) > 0:
            lines.append("")
            for arg in args_needing_conversion:
                converter = arg.type_converter_for_cpp()
                if converter == "label":
                    lines.append("  auto {value} = {wrapper_function_prefix}_resolve_label (self, {value_raw});".format(
                        value=arg.name,
                        value_raw=arg.name_raw_for_cpp(),
                        wrapper_function_prefix=component.wrapper_function_prefix))
                elif converter == "address":
                    lines.append("  auto {value} = GUM_ADDRESS ({value_raw});".format(
                        value=arg.name,
                        value_raw=arg.name_raw_for_cpp()))
                elif converter == "bytes":
                    lines.extend([
                        "  gsize {0}_size;".format(arg.name),
                        "  auto {value} = (const guint8 *) g_bytes_get_data ({value_raw}, &{value}_size);".format(
                            value=arg.name,
                            value_raw=arg.name_raw_for_cpp()),
                    ])
                else:
                    lines.extend([
                        "  {0} {1};".format(arg.type, arg.name),
                        "  if (!gum_parse_{arch}_{type} (isolate, {value_raw}, &{value}))".format(
                            value=arg.name,
                            value_raw=arg.name_raw_for_cpp(),
                            arch=component.arch,
                            type=arg.type_converter_for_cpp()),
                        "    return;",
                    ])

        if is_put_array:
            lines.extend(generate_v8_parse_array_elements(array_item_type, array_item_parse_logic).split("\n"))

        impl_function_name = "{0}_{1}".format(component.impl_function_prefix, method.name)

        arglist = ["self->impl"]
        if method.needs_calling_convention_arg:
            arglist.append("GUM_CALL_CAPI")
        for arg in args:
            if arg.type_converter_for_cpp() == "bytes":
                arglist.extend([arg.name, arg.name + "_size"])
            else:
                arglist.append(arg.name)
        if is_put_array:
            impl_function_name += "_array"
            arglist.insert(len(arglist) - 1, "items_length")

        if method.return_type == "void":
            return_capture = ""
        else:
            return_capture = "auto result = "

        lines.extend([
            "",
            "  {0}{1} ({2});".format(return_capture, impl_function_name, ", ".join(arglist))
        ])

        if method.return_type == "gboolean" and method.name.startswith("put_"):
            lines.extend([
                "  if (!result)",
                "    _gum_v8_throw_ascii_literal (isolate, \"invalid argument\");",
            ])
        elif method.return_type != "void":
            lines.append("")
            if method.return_type == "gboolean":
                lines.append("  info.GetReturnValue ().Set (!!result);")
            elif method.return_type == "guint":
                lines.append("  info.GetReturnValue ().Set ((uint32_t) result);")
            elif method.return_type == "gpointer":
                lines.append("  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (result, core));")
            elif method.return_type == "cs_insn *":
                if component.flavor == "x86":
                    target = "GSIZE_TO_POINTER (result->address)"
                else:
                    target = "self->impl->input_start + (result->address - (self->impl->input_pc - self->impl->inpos))"
                    if component.flavor == "thumb":
                        target = "GSIZE_TO_POINTER (GPOINTER_TO_SIZE ({0}) | 1)".format(target)
                lines.extend([
                    "  if (result != NULL)",
                    "  {",
                    "    info.GetReturnValue ().Set (_gum_v8_instruction_new (result,",
                    "        {0}, module->instruction));".format(target),
                    "  }",
                    "  else",
                    "  {",
                    "    info.GetReturnValue ().SetNull ();"
                    "  }",
                ])
            else:
                raise ValueError("Unsupported return type: {0}".format(method.return_type))

        args_needing_cleanup = [arg for arg in args if arg.type_converter_for_cpp() == "bytes"]
        if len(args_needing_cleanup) > 0:
            lines.append("")
            for arg in args_needing_cleanup:
                lines.append("  g_bytes_unref ({0});".format(arg.name_raw_for_cpp()))

        lines.extend([
            "}",
            ""
        ])

    lines.extend([
        "static const GumV8Function {0}_functions[] =".format(component.gumjs_function_prefix),
        "{",
        "  {{ \"reset\", {0}_reset }},".format(component.gumjs_function_prefix),
        "  {{ \"dispose\", {0}_dispose }},".format(component.gumjs_function_prefix),
    ])
    if component.name == "writer":
        lines.append("  {{ \"flush\", {0}_flush }},".format(component.gumjs_function_prefix))
    elif component.name == "relocator":
        lines.append("  {{ \"readOne\", {0}_read_one }},".format(component.gumjs_function_prefix))

    for method in api.instance_methods:
        lines.append("  {{ \"{0}\", {1}_{2} }},".format(
            method.name_js,
            component.gumjs_function_prefix,
            method.name
        ))

    lines.extend([
        "",
        "  { NULL, NULL }",
        "};",
        ""
    ])

    lines.extend(conversion_code)

    return "\n".join(lines)

def generate_v8_parse_array_elements(item_type, parse_item):
    return """
  auto context = isolate->GetCurrentContext ();

  uint32_t items_length = items_value->Length ();
  auto items = ({item_type} *) g_alloca (items_length * sizeof ({item_type}));

  for (uint32_t items_index = 0; items_index != items_length; items_index++)
  {{
    {item_type} * item = &items[items_index];
{parse_item}
  }}""".format(item_type=item_type, parse_item=parse_item)

def generate_v8_parse_call_arg_array_element(component, api):
    return """
    auto value = items_value->Get (context, items_index).ToLocalChecked ();
    if (value->IsString ())
    {{
      item->type = GUM_ARG_REGISTER;

      String::Utf8Value value_as_utf8 (value.As<String> ());
      {native_register_type} value_as_reg;
      if (!gum_parse_{arch}_register (isolate, *value_as_utf8, &value_as_reg))
        return;
      item->value.reg = value_as_reg;
    }}
    else
    {{
      item->type = GUM_ARG_ADDRESS;

      gpointer ptr;
      if (!_gum_v8_native_pointer_parse (value, &ptr, core))
        return;
      item->value.address = GUM_ADDRESS (ptr);
    }}""".format(arch=component.arch, native_register_type=api.native_register_type)

def generate_v8_parse_register_array_element(component, api):
    return """
    auto value = items_value->Get (context, items_index).ToLocalChecked ();
    if (!value->IsString ())
    {{
      _gum_v8_throw_ascii_literal (isolate, "expected an array with register names");
      return;
    }}

    String::Utf8Value value_as_utf8 (value.As<String> ());
    {native_register_type} value_as_reg;
    if (!gum_parse_{arch}_register (isolate, *value_as_utf8, &value_as_reg))
      return;

    *item = value_as_reg;""".format(arch=component.arch, native_register_type=api.native_register_type)

def generate_v8_fields(component):
    return """\
  GHashTable * {flavor}_{name}s;
  GumPersistent<v8::FunctionTemplate>::type * {flavor}_{name};""".format(**component.__dict__)

def generate_v8_methods(component):
    if component.name == "writer":
        template = """\
#include <gum/arch-{arch}/gum{flavor}{name}.h>

G_GNUC_INTERNAL gboolean _gum_v8_{flavor}_writer_get (v8::Handle<v8::Value> value,
    {impl_struct_name} ** writer, {module_struct_name} * module);"""
        return template.format(**component.__dict__)
    return ""

def generate_v8_init_code(component):
    return """\
  auto {flavor}_{name} = _gum_v8_create_class ("{gumjs_class_name}",
      {gumjs_function_prefix}_construct, scope, module, isolate);
  _gum_v8_class_add ({flavor}_{name}, {gumjs_function_prefix}_values, module,
      isolate);
  _gum_v8_class_add ({flavor}_{name}, {gumjs_function_prefix}_functions, module,
      isolate);
  self->{flavor}_{name} =
      new GumPersistent<FunctionTemplate>::type (isolate, {flavor}_{name});

  self->{flavor}_{name}s = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) {wrapper_function_prefix}_free);
""".format(**component.__dict__)

def generate_v8_dispose_code(component):
    return """\
  g_hash_table_unref (self->{flavor}_{name}s);
  self->{flavor}_{name}s = NULL;

  delete self->{flavor}_{name};
  self->{flavor}_{name} = nullptr;
""".format(**component.__dict__)

def generate_v8_base_methods(component):
    if component.name == "writer":
        return generate_v8_writer_base_methods(component)
    elif component.name == "relocator":
        return generate_v8_relocator_base_methods(component)

def generate_v8_writer_base_methods(component):
    template = """\
static void {wrapper_function_prefix}_on_weak_notify (
    const WeakCallbackInfo<{wrapper_struct_name}> & info);
static gboolean {wrapper_function_prefix}_check ({wrapper_struct_name} * self,
    Isolate * isolate);

gboolean
_gum_v8_{flavor}_writer_get (v8::Handle<v8::Value> value,
{writer_get_arglist_indent}{impl_struct_name} ** writer,
{writer_get_arglist_indent}{module_struct_name} * module)
{{
  auto isolate = module->core->isolate;

  auto writer_class = Local<FunctionTemplate>::New (isolate,
      *module->{flavor}_writer);
  if (!writer_class->HasInstance (value))
  {{
    _gum_v8_throw_ascii_literal (isolate, "expected {flavor} writer");
    return FALSE;
  }}

  auto writer_wrapper = ({wrapper_struct_name} *)
      value.As<Object> ()->GetAlignedPointerFromInternalField (0);
  if (!{wrapper_function_prefix}_check (writer_wrapper, isolate))
    return FALSE;

  *writer = writer_wrapper->impl;
  return TRUE;
}}

static {wrapper_struct_name} *
{wrapper_function_prefix}_new (Handle<Object> wrapper,
{wrapper_ctor_arglist_indent}gpointer code_address,
{wrapper_ctor_arglist_indent}GumV8CodeWriter * module)
{{
  {wrapper_struct_name} * writer;

  writer = g_slice_new ({wrapper_struct_name});
  writer->wrapper =
      new GumPersistent<Object>::type (module->core->isolate, wrapper);
  writer->wrapper->MarkIndependent ();
  writer->wrapper->SetWeak (writer, {wrapper_function_prefix}_on_weak_notify,
      WeakCallbackType::kParameter);
  writer->impl = {impl_function_prefix}_new (code_address);
  writer->labels =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  writer->module = module;

  g_hash_table_add (module->{flavor}_{name}s, writer);

  return writer;
}}

static void
{wrapper_function_prefix}_dispose ({wrapper_struct_name} * self)
{{
  if (self->impl == NULL)
    return;

  g_hash_table_unref (self->labels);
  self->labels = NULL;

  {impl_function_prefix}_unref (self->impl);
  self->impl = NULL;
}}

static void
{wrapper_function_prefix}_free ({wrapper_struct_name} * self)
{{
  {wrapper_function_prefix}_dispose (self);

  delete self->wrapper;

  g_slice_free ({wrapper_struct_name}, self);
}}
{label_resolver}
static void
{wrapper_function_prefix}_on_weak_notify (
    const WeakCallbackInfo<{wrapper_struct_name}> & info)
{{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->{flavor}_{name}s, self);
}}

static gboolean
{wrapper_function_prefix}_check ({wrapper_struct_name} * self,
{wrapper_check_arglist_indent}Isolate * isolate)
{{
  if (self->impl == NULL)
  {{
    _gum_v8_throw_ascii_literal (isolate, "writer is disposed");
    return FALSE;
  }}

  return TRUE;
}}

GUMJS_DEFINE_CONSTRUCTOR ({gumjs_function_prefix}_construct)
{{
  if (!info.IsConstructCall ())
  {{
    _gum_v8_throw_ascii_literal (isolate,
        "use constructor syntax to create a new instance");
    return;
  }}

  gpointer code_address;
  Local<Object> options;
  if (!_gum_v8_args_parse (args, "p|O", &code_address, &options))
    return;

  GumAddress pc = 0;
  gboolean pc_specified = FALSE;
  if (!options.IsEmpty ())
  {{
    auto pc_value = options->Get (_gum_v8_string_new_ascii (isolate, "pc"));
    if (!pc_value->IsUndefined ())
    {{
      gpointer raw_value;
      if (!_gum_v8_native_pointer_get (pc_value, &raw_value, core))
        return;
      pc = GUM_ADDRESS (raw_value);
      pc_specified = TRUE;
    }}
  }}

  auto writer = {wrapper_function_prefix}_new (wrapper, code_address, module);

  if (pc_specified)
    writer->impl->pc = pc;

  wrapper->SetAlignedPointerInInternalField (0, writer);
}}

GUMJS_DEFINE_CLASS_METHOD ({gumjs_function_prefix}_reset, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  gpointer code_address;
  gpointer pc = NULL;
  if (!_gum_v8_args_parse (args, "p|p", &code_address))
    return;

  {impl_function_prefix}_reset (self->impl, code_address);

  if (pc != NULL)
    self->impl->pc = GUM_ADDRESS (pc);

  g_hash_table_remove_all (self->labels);
}}

GUMJS_DEFINE_CLASS_METHOD ({gumjs_function_prefix}_dispose, {wrapper_struct_name})
{{
  {wrapper_function_prefix}_dispose (self);
}}

GUMJS_DEFINE_CLASS_METHOD ({gumjs_function_prefix}_flush, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  auto success = {impl_function_prefix}_flush (self->impl);
  if (!success)
    _gum_v8_throw_ascii_literal (isolate, "unable to resolve references");
}}

GUMJS_DEFINE_CLASS_GETTER ({gumjs_function_prefix}_get_offset, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  info.GetReturnValue ().Set ({impl_function_prefix}_offset (self->impl));
}}

static const GumV8Property {gumjs_function_prefix}_values[] =
{{
  {{ "offset", {gumjs_function_prefix}_get_offset, NULL }},

  {{ NULL, NULL, NULL }}
}};
"""

    wrapper_arglist_indent_level = len(component.wrapper_function_prefix)
    params = {
        "writer_get_arglist_indent": (len(component.flavor) + 21) * " ",
        "wrapper_ctor_arglist_indent": (wrapper_arglist_indent_level + 6) * " ",
        "wrapper_resolve_arglist_indent": (wrapper_arglist_indent_level + 16) * " ",
        "wrapper_check_arglist_indent": (wrapper_arglist_indent_level + 8) * " ",
    }
    params.update(component.__dict__)

    label_resolver = """
static gconstpointer
{wrapper_function_prefix}_resolve_label ({wrapper_struct_name} * self,
{wrapper_resolve_arglist_indent}const std::string & str)
{{
  gchar * label = (gchar *) g_hash_table_lookup (self->labels, str.c_str ());
  if (label != NULL)
    return label;

  label = g_strdup (str.c_str ());
  g_hash_table_add (self->labels, label);
  return label;
}}
""".format(**params)
    if component.flavor != "arm":
        params["label_resolver"] = label_resolver
    else:
        params["label_resolver"] = ""

    return template.format(**params).split("\n")

def generate_v8_relocator_base_methods(component):
    template = """\
static void {wrapper_function_prefix}_on_weak_notify (
    const WeakCallbackInfo<{wrapper_struct_name}> & info);

static {wrapper_struct_name} *
{wrapper_function_prefix}_new (Handle<Object> wrapper,
{wrapper_ctor_arglist_indent}gconstpointer input_code,
{wrapper_ctor_arglist_indent}{writer_impl_struct_name} * output,
{wrapper_ctor_arglist_indent}{module_struct_name} * module)
{{
  {wrapper_struct_name} * relocator;

  relocator = g_slice_new ({wrapper_struct_name});
  relocator->wrapper =
      new GumPersistent<Object>::type (module->core->isolate, wrapper);
  relocator->wrapper->MarkIndependent ();
  relocator->wrapper->SetWeak (relocator, {wrapper_function_prefix}_on_weak_notify,
      WeakCallbackType::kParameter);
  relocator->impl = {impl_function_prefix}_new (input_code, output);
  relocator->input = NULL;
  relocator->module = module;

  g_hash_table_add (module->{flavor}_{name}s, relocator);

  return relocator;
}}

static void
{wrapper_function_prefix}_dispose ({wrapper_struct_name} * self)
{{
  if (self->impl == NULL)
    return;

  self->input = NULL;

  {impl_function_prefix}_unref (self->impl);
  self->impl = NULL;
}}

static void
{wrapper_function_prefix}_free ({wrapper_struct_name} * self)
{{
  {wrapper_function_prefix}_dispose (self);

  delete self->wrapper;

  g_slice_free ({wrapper_struct_name}, self);
}}

static void
{wrapper_function_prefix}_on_weak_notify (
    const WeakCallbackInfo<{wrapper_struct_name}> & info)
{{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->{flavor}_{name}s, self);
}}

static gboolean
{wrapper_function_prefix}_check ({wrapper_struct_name} * self,
{wrapper_check_arglist_indent}Isolate * isolate)
{{
  if (self->impl == NULL)
  {{
    _gum_v8_throw_ascii_literal (isolate, "relocator is disposed");
    return FALSE;
  }}

  return TRUE;
}}

GUMJS_DEFINE_CONSTRUCTOR ({gumjs_function_prefix}_construct)
{{
  if (!info.IsConstructCall ())
  {{
    _gum_v8_throw_ascii_literal (isolate,
        "use constructor syntax to create a new instance");
    return;
  }}

  gconstpointer input_code;
  Local<Object> writer_object;
  if (!_gum_v8_args_parse (args, "pO", &input_code, &writer_object))
    return;

  {writer_impl_struct_name} * writer;
  if (!_gum_v8_{flavor}_writer_get (writer_object, &writer, module->writer))
    return;

  auto relocator = {wrapper_function_prefix}_new (wrapper, input_code, writer,
      module);

  wrapper->SetAlignedPointerInInternalField (0, relocator);
}}

GUMJS_DEFINE_CLASS_METHOD ({gumjs_function_prefix}_reset, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  gconstpointer input_code;
  Local<Object> writer_object;
  if (!_gum_v8_args_parse (args, "pO", &input_code, &writer_object))
    return;

  {writer_impl_struct_name} * writer;
  if (!_gum_v8_{flavor}_writer_get (writer_object, &writer, module->writer))
    return;

  {impl_function_prefix}_reset (self->impl, input_code, writer);

  self->input = NULL;
}}

GUMJS_DEFINE_CLASS_METHOD ({gumjs_function_prefix}_dispose, {wrapper_struct_name})
{{
  {wrapper_function_prefix}_dispose (self);
}}

GUMJS_DEFINE_CLASS_METHOD ({gumjs_function_prefix}_read_one, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  uint32_t n_read = {impl_function_prefix}_read_one (self->impl, &self->input);

  info.GetReturnValue ().Set (n_read);
}}

GUMJS_DEFINE_CLASS_GETTER ({gumjs_function_prefix}_get_input, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  if (self->input != NULL)
  {{
    info.GetReturnValue ().Set (_gum_v8_instruction_new (self->input,
        {get_input_target_expression},
        module->instruction));
  }}
  else
  {{
    info.GetReturnValue ().SetNull ();
  }}
}}

GUMJS_DEFINE_CLASS_GETTER ({gumjs_function_prefix}_get_eob, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  info.GetReturnValue ().Set (!!{impl_function_prefix}_eob (self->impl));
}}

GUMJS_DEFINE_CLASS_GETTER ({gumjs_function_prefix}_get_eoi, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  info.GetReturnValue ().Set (!!{impl_function_prefix}_eoi (self->impl));
}}

static const GumV8Property {gumjs_function_prefix}_values[] =
{{
  {{ "input", {gumjs_function_prefix}_get_input, NULL }},
  {{ "eob", {gumjs_function_prefix}_get_eob, NULL }},
  {{ "eoi", {gumjs_function_prefix}_get_eoi, NULL }},

  {{ NULL, NULL, NULL }}
}};
"""

    if component.flavor == "x86":
        target = "GSIZE_TO_POINTER (self->input->address)"
    else:
        target = "self->impl->input_start + (self->input->address - (self->impl->input_pc - self->impl->inpos))"
        if component.flavor == "thumb":
            target = "GSIZE_TO_POINTER (GPOINTER_TO_SIZE ({0}) | 1)".format(target)

    base_arglist_indent_level = len(component.wrapper_function_prefix)
    params = {
        "writer_impl_struct_name": to_camel_case('gum_{0}_writer'.format(component.flavor), start_high=True),
        "get_input_target_expression": target,
        "wrapper_ctor_arglist_indent": (base_arglist_indent_level + 6) * " ",
        "wrapper_resolve_arglist_indent": (base_arglist_indent_level + 16) * " ",
        "wrapper_check_arglist_indent": (base_arglist_indent_level + 8) * " ",
    }
    params.update(component.__dict__)

    return template.format(**params).split("\n")

def generate_v8_enum_parser(name, type, prefix, values):
    common_decls, common_code = generate_enum_parser(name, type, prefix, values)

    params = {
        'name': name,
        'description': name.replace("_", " "),
        'type': type,
        'arglist_indent': (len(name) + 12) * " ",
    }

    decls = [
        "static gboolean gum_parse_{name} (Isolate * isolate, const std::string & name, {type} * value);".format(**params)
    ] + common_decls

    code = """\
static gboolean
gum_parse_{name} (Isolate * isolate,
{arglist_indent}const std::string & name,
{arglist_indent}{type} * value)
{{
  if (!gum_try_parse_{name} (name.c_str (), value))
  {{
    _gum_v8_throw_literal (isolate, "invalid {description}");
    return FALSE;
  }}

  return TRUE;
}}
""".format(**params).split("\n") + common_code

    return (decls, code)

arch_names = {
    "x86": "x86",
    "arm": "ARM",
    "arm64": "AArch64",
    "mips": "MIPS",
}

writer_enums = {
    "x86": [
        ("x86_register", "GumCpuReg", "GUM_REG_", [
            "xax", "xcx", "xdx", "xbx", "xsp", "xbp", "xsi", "xdi",
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
            "xip", "eip", "rip",
        ]),
        ("x86_instruction_id", "x86_insn", "X86_INS_", [
            "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns",
            "jp", "jnp", "jl", "jge", "jle", "jg", "jcxz", "jecxz", "jrcxz",
        ]),
        ("x86_branch_hint", "GumBranchHint", "GUM_", [
            "no-hint", "likely", "unlikely",
        ]),
        ("x86_pointer_target", "GumPtrTarget", "GUM_PTR_", [
            "byte", "dword", "qword",
        ]),
    ],
    "arm": [
        ("arm_register", "arm_reg", "ARM_REG_", [
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "sp", "lr", "sb", "sl", "fp", "ip", "pc",
        ]),
        ("arm_condition_code", "arm_cc", "ARM_CC_", [
            "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
            "hi", "ls", "ge", "lt", "gt", "le", "al",
        ]),
    ],
    "thumb": [],
    "arm64": [
        ("arm64_register", "arm64_reg", "ARM64_REG_", [
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
            "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
            "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
            "x30",
            "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9",
            "w10", "w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19",
            "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29",
            "w30",
            "sp", "lr", "fp",
            "wsp", "wzr", "xzr", "nzcv", "ip0", "ip1",
            "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9",
            "s10", "s11", "s12", "s13", "s14", "s15", "s16", "s17", "s18", "s19",
            "s20", "s21", "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29",
            "s30", "s31",
            "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9",
            "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19",
            "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29",
            "d30", "d31",
            "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9",
            "q10", "q11", "q12", "q13", "q14", "q15", "q16", "q17", "q18", "q19",
            "q20", "q21", "q22", "q23", "q24", "q25", "q26", "q27", "q28", "q29",
            "q30", "q31",
        ]),
        ("arm64_condition_code", "arm64_cc", "ARM64_CC_", [
            "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
            "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
        ]),
        ("arm64_index_mode", "GumArm64IndexMode", "GUM_INDEX_", [
            "post-adjust", "signed-offset", "pre-adjust",
        ]),
    ],
    "mips": [
        ("mips_register", "mips_reg", "MIPS_REG_", [
            "v0", "v1", "a0", "a1", "a2", "a3",
            "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
            "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
            "t8", "t9",
            "k0", "k1",
            "gp", "sp", "fp", "s8", "ra",
            "hi", "lo", "zero", "at",
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
            "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
            "30", "31",
        ]),
    ],
}

def generate_conversion_methods(component, generate_parser):
    decls = []
    code = []

    if component.name == "writer":
        for enum in writer_enums[component.flavor]:
            d, c = generate_parser(*enum)
            decls += d
            code += c

    return (decls, code)

def generate_enum_parser(name, type, prefix, values):
    decls = [
        "static gboolean gum_try_parse_{name} (const gchar * name, {type} * value);".format(name=name, type=type)
    ]

    statements = []
    for i, value in enumerate(values):
        statements.extend([
            "{0}if (strcmp (name, \"{1}\") == 0)".format("  else " if i > 0 else "", value),
            "    *value = {0}{1};".format(prefix, value.upper().replace("-", "_")),
        ])

    code = """\
static gboolean
gum_try_parse_{name} (const gchar * name,
{arglist_indent}{type} * value)
{{
  {statements}
  else
    return FALSE;
  return TRUE;
}}
""".format(
        name=name,
        type=type,
        statements="\n".join(statements),
        arglist_indent=(len(name) + 16) * " "
    )

    return (decls, code.split("\n"))

def generate_docs(name, arch, flavor, api):
    docs = {}
    docs.update(generate_class_api_reference(name, arch, flavor, api))
    docs.update(generate_enum_api_reference(name, arch, flavor, api))
    return docs

def generate_class_api_reference(name, arch, flavor, api):
    lines = []

    class_name = to_camel_case("{0}_{1}".format(flavor, name), start_high=True)
    writer_class_name = to_camel_case("{0}_writer".format(flavor, "writer"), start_high=True)

    params = {
        "arch": arch,
        "arch_name": arch_names[arch],
        "class_name": class_name,
        "writer_class_name": writer_class_name,
        "writer_class_link_indefinite": "{0} [{1}](#{2})".format(
            make_indefinite_qualifier(writer_class_name),
            writer_class_name,
            writer_class_name.lower()),
        "instruction_link": "[Instruction](#instruction)",
    }

    lines.extend([
        "## {0}".format(class_name),
        "",
    ])

    if name == "writer":
        lines.extend("""\
+   `new {class_name}(codeAddress[, {{ pc: ptr('0x1234') }}])`: create a new code
    writer for generating {arch_name} machine code written directly to memory at
    `codeAddress`, specified as a NativePointer.
    The second argument is an optional options object where the initial program
    counter may be specified, which is useful when generating code to a scratch
    buffer. This is essential when using `Memory.patchCode()` on iOS, which may
    provide you with a temporary location that later gets mapped into memory at
    the intended memory location.

-   `reset(codeAddress[, {{ pc: ptr('0x1234') }}])`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `flush()`: resolve label references and write pending data to memory. You
    should always call this once you've finished generating code. It is usually
    also desirable to do this between pieces of unrelated code, e.g. when
    generating multiple functions in one go.

-   `offset`: current offset as a JavaScript Number
""".format(**params).split("\n"))
    elif name == "relocator":
        lines.extend("""\
+   `new {class_name}(inputCode, output)`: create a new code relocator for
    copying {arch_name} instructions from one memory location to another, taking
    care to adjust position-dependent instructions accordingly.
    The source address is specified by `inputCode`, a NativePointer.
    The destination is given by `output`, {writer_class_link_indefinite} pointed
    at the desired target memory address.

-   `reset(inputCode, output)`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `input`: latest {instruction_link} read so far. Starts out `null`
    and changes on every call to `readOne()`.

-   `eob`: boolean indicating whether end-of-block has been reached, i.e. we've
    reached a branch of any kind, like CALL, JMP, BL, RET.

-   `eoi`: boolean indicating whether end-of-input has been reached, e.g. we've
    reached JMP/B/RET, an instruction after which there may or may not be valid
    code.

-   `readOne()`: read the next instruction into the relocator's internal buffer
    and return the number of bytes read so far, including previous calls.
    You may keep calling this method to keep buffering, or immediately call
    either `writeOne()` or `skipOne()`. Or, you can buffer up until the desired
    point and then call `writeAll()`.
    Returns zero when end-of-input is reached, which means the `eoi` property is
    now `true`.
""".format(**params).split("\n"))

    for method in api.instance_methods:
        arg_names = [arg.name_js for arg in method.args]

        description = ""
        if method.name.startswith("put_"):
            if method.name == "put_label":
                description = """put a label at the current position, where `id` is a string
    that may be referenced in past and future `put*Label()` calls"""
            elif method.name.startswith("put_call") and "_with_arguments" in method.name:
                description = """put code needed for calling a C
    function with the specified `args`, specified as a JavaScript array where
    each element is either a string specifying the register, or a Number or
    NativePointer specifying the immediate value."""
                arg_names[-1] = "args"
            elif method.name in ("put_push_regs", "put_pop_regs"):
                if method.name.startswith("put_push_"):
                    mnemonic = "PUSH"
                else:
                    mnemonic = "POP"
                description = """put a {mnemonic} instruction with the specified registers,
    specified as a JavaScript array where each element is a string specifying
    the register name.""".format(mnemonic=mnemonic)
                arg_names[-1] = "regs"
            elif method.name == "put_push_all_x_registers":
                description = """put code needed for pushing all X registers on the stack"""
            elif method.name == "put_push_all_q_registers":
                description = """put code needed for pushing all Q registers on the stack"""
            elif method.name == "put_pop_all_x_registers":
                description = """put code needed for popping all X registers off the stack"""
            elif method.name == "put_pop_all_q_registers":
                description = """put code needed for popping all Q registers off the stack"""
            elif method.name == "put_breakpoint":
                description = "put an OS/architecture-specific breakpoint instruction"
            elif method.name == "put_padding":
                description = "put `n` guard instruction"
            elif method.name == "put_nop_padding":
                description = "put `n` NOP instructions"
            elif method.name == "put_instruction":
                description = "put a raw instruction as a JavaScript Number"
            elif method.name == "put_u8":
                description = "put a uint8"
            elif method.name == "put_s8":
                description = "put an int8"
            elif method.name == "put_bytes":
                description = "put raw data from the provided ArrayBuffer"
            else:
                types = set(["reg", "imm", "offset", "indirect", "short", "near", "ptr", "base", "index", "scale", "address", "label", "u8", "i32", "u32", "u64"])
                opcode = " ".join(filter(lambda token: token not in types, method.name.split("_")[1:])).upper()
                description = "put {0} instruction".format(make_indefinite(opcode))
                if method.name.endswith("_label"):
                    description += """
    referencing `labelId`, defined by a past or future `putLabel()`"""
        elif method.name == "skip":
            description = "skip `nBytes`"
        elif method.name == "peek_next_write_insn":
            description = "peek at the next {instruction_link} to be\n    written or skipped".format(**params)
        elif method.name == "peek_next_write_source":
            description = "peek at the address of the next instruction to be\n    written or skipped"
        elif method.name.startswith("skip_one"):
            description = "skip the instruction that would have been written next"
            if method.name.endswith("_no_label"):
                description += """,
    but without a label for internal use. This breaks relocation of branches to
    locations inside the relocated range, and is an optimization for use-cases
    where all branches are rewritten (e.g. Frida's Stalker)."""
        elif method.name.startswith("write_one"):
            description = "write the next buffered instruction"
            if method.name.endswith("_no_label"):
                description += """, but without a
    label for internal use. This breaks relocation of branches to locations
    inside the relocated range, and is an optimization for use-cases where all
    branches are rewritten (e.g. Frida's Stalker)."""
        elif method.name.startswith("write_all"):
            description = "write all buffered instructions"

        p = {}
        p.update(params)
        p.update({
            "method_name": method.name_js,
            "method_arglist": ", ".join(arg_names),
            "method_description": description,
        })

        lines.extend("""\
-   `{method_name}({method_arglist})`: {method_description}
""".format(**p).split("\n"))

    return {
        "{0}-{1}.md".format(flavor, name): "\n".join(lines),
    }

def generate_enum_api_reference(name, arch, flavor, api):
    lines = [
        "## {0} enum types".format(arch_names[arch]),
        "",
    ]

    for name, type, prefix, values in writer_enums[arch]:
        display_name = to_camel_case("_".join(name.split("_")[1:]), start_high=True)

        lines.extend(reflow_enum_bulletpoint("-   {0}: `{1}`".format(display_name, "` `".join(values))))

    lines.append("")

    return {
        "{0}-enums.md".format(arch): "\n".join(lines),
    }

def reflow_enum_bulletpoint(bulletpoint):
    result = [bulletpoint]

    indent = 3 * " "

    while True:
        last_line = result[-1]
        if len(last_line) < 80:
            break

        cutoff_index = last_line.rindex("` `", 0, 81) + 1
        before = last_line[:cutoff_index]
        after = indent + last_line[cutoff_index:]

        result[-1] = before
        result.append(after)

    return result

def make_indefinite(noun):
    return make_indefinite_qualifier(noun) + " " + noun

def make_indefinite_qualifier(noun):
    noun_lc = noun.lower()

    exceptions = [
        "ld",
        "lf",
        "rd",
        "x",
    ]
    for prefix in exceptions:
        if noun_lc.startswith(prefix):
            return "an"

    return "an" if noun_lc[0] in ("a", "e", "i", "o", "u") else "a"

class Component(object):
    def __init__(self, name, arch, flavor, namespace):
        self.name = name
        self.arch = arch
        self.flavor = flavor
        self.wrapper_struct_name = to_camel_case("gum_{0}_{1}_{2}".format(namespace, flavor, name), start_high=True)
        self.wrapper_function_prefix = "gum_{0}_{1}_{2}".format(namespace, flavor, name)
        self.impl_struct_name = to_camel_case("gum_{0}_{1}".format(flavor, name), start_high=True)
        self.impl_function_prefix = "gum_{0}_{1}".format(flavor, name)
        self.gumjs_class_name = flavor.title() + name.title()
        self.gumjs_field_name = "{0}_{1}".format(flavor, name)
        self.gumjs_function_prefix = "gumjs_{0}_{1}".format(flavor, name)
        self.module_struct_name = to_camel_case("gum_{0}_code_{1}".format(namespace, name), start_high=True)

class Api(object):
    def __init__(self, static_methods, instance_methods):
        self.static_methods = static_methods
        self.instance_methods = instance_methods

        native_register_type = None
        for method in instance_methods:
            reg_types = [arg.type for arg in method.args if arg.type_converter == "register"]
            if len(reg_types) > 0:
                native_register_type = reg_types[0]
                break
        self.native_register_type = native_register_type

class Method(object):
    def __init__(self, name, return_type, args):
        is_put_array = name.startswith("put_") and name.endswith("_array")
        if is_put_array:
            name = name[:-6]
        is_put_call = is_put_array and name.startswith("put_call_")
        is_put_regs = is_put_array and "_regs" in name

        self.name = name
        self.name_js = to_camel_case(name, start_high=False)

        self.is_put_array = is_put_array
        if is_put_array:
            args.pop(len(args) - 2)

        self.is_put_call = is_put_call
        if is_put_call:
            self.needs_calling_convention_arg = args[0].type == "GumCallingConvention"
            if self.needs_calling_convention_arg:
                args.pop(0)
        else:
            self.needs_calling_convention_arg = False

        self.is_put_regs = is_put_regs

        self.return_type = return_type
        self.args = args

class MethodArgument(object):
    def __init__(self, type, name):
        self.type = type

        name_raw = None
        converter = None

        if type in ("GumCpuReg", "arm_reg", "arm64_reg", "mips_reg"):
            self.type_raw = "const gchar *"
            self.type_format = "s"
            converter = "register"
        elif type in ("gint", "gint8", "gint16", "gint32"):
            self.type_raw = "gint"
            self.type_format = "i"
        elif type in ("guint", "guint8", "guint16", "guint32"):
            self.type_raw = "guint"
            self.type_format = "u"
        elif type == "gint64":
            self.type_raw = type
            self.type_format = "q"
        elif type == "guint64":
            self.type_raw = type
            self.type_format = "Q"
        elif type == "gssize":
            self.type_raw = type
            self.type_format = "z"
        elif type == "gsize":
            self.type_raw = type
            self.type_format = "Z"
        elif type in ("gpointer", "gconstpointer", "gconstpointer *"):
            self.type_raw = type
            self.type_format = "p"
        elif type == "GumAddress":
            self.type_raw = "gpointer"
            self.type_format = "p"
            converter = "address"
        elif type == "$label":
            self.type_raw = "const gchar *"
            self.type_format = "s"
        elif type == "$array":
            self.type_raw = "GBytes *"
            self.type_format = "B~"
            converter = "bytes"
        elif type == "x86_insn":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            converter = "instruction_id"
        elif type == "GumCallingConvention":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            converter = "calling_convention"
        elif type in ("const GumArgument *", "const arm_reg *"):
            self.type_raw = "$array"
            self.type_format = "A"
            name = "items"
            name_raw = "items_value"
        elif type == "GumBranchHint":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            converter = "branch_hint"
        elif type == "GumPtrTarget":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            converter = "pointer_target"
        elif type in ("arm_cc", "arm64_cc"):
            self.type_raw = "const gchar *"
            self.type_format = "s"
            converter = "condition_code"
        elif type == "GumArm64IndexMode":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            converter = "index_mode"
        elif type == "GumRelocationScenario":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            converter = "relocator_scenario"
        else:
            raise ValueError("Unhandled type: {0}".format(type))

        self.type_converter = converter

        if name_raw is None:
            name_raw = name if converter is None else "raw_{0}".format(name)

        self.name = name
        self.name_js = to_camel_case(name, start_high=False)
        self.name_raw = name_raw

    def name_raw_for_cpp(self):
        if self.type == "$label":
            return "raw_{0}".format(self.name)
        return self.name_raw

    def type_raw_for_cpp(self):
        if self.type_format == "s":
            return "std::string"
        return self.type_raw

    def type_format_for_cpp(self):
        if self.type_format == "s":
            return "S"
        return self.type_format

    def type_converter_for_cpp(self):
        if self.type == "$label":
            return "label"
        return self.type_converter

def parse_api(name, flavor, api_header, options):
    static_methods = []
    instance_methods = []

    self_type = "{0} * ".format(to_camel_case("gum_{0}_{1}".format(flavor, name), start_high=True))
    ignored_methods = set(options.get('ignore', []))

    put_methods = [(m.group(2), m.group(1), m.group(3)) for m in re.finditer(r"GUM_API ([\w *]+) gum_{0}_{1}_([\w]+) \(([^)]+)\);".format(flavor, name), api_header)]
    for method_name, return_type, raw_arglist in put_methods:
        if method_name in ignored_methods:
            continue

        raw_args = [raw_arg.strip() for raw_arg in raw_arglist.replace("\n", " ").split(", ")]
        if raw_args[-1] == "...":
            continue

        is_static = not raw_args[0].startswith(self_type)

        if not is_static:
            raw_args = raw_args[1:]

        if not is_static and method_name == "put_bytes":
            args = [MethodArgument("$array", "data")]
        else:
            args = [parse_arg(raw_arg) for raw_arg in raw_args]

        method = Method(method_name, return_type, args)
        if is_static:
            static_methods.append(method)
        else:
            instance_methods.append(method)

    return Api(static_methods, instance_methods)

def parse_arg(raw_arg):
    tokens = raw_arg.split(" ")
    raw_type = " ".join(tokens[0:-1])
    name = tokens[-1]
    if raw_type == "gconstpointer":
        if name in ("id", "label_id"):
            return MethodArgument("$label", name)
        return MethodArgument(raw_type, name)
    return MethodArgument(raw_type, name)

def to_camel_case(name, start_high):
    result = ""
    uppercase_next = start_high
    for c in name:
        if c == "_":
            uppercase_next = True
        elif uppercase_next:
            result += c.upper()
            uppercase_next = False
        else:
            result += c.lower()
    return result


if __name__ == '__main__':
    source_dir = sys.argv[1]
    output_dir = sys.argv[2]

    generate_and_write_bindings(source_dir, output_dir)
