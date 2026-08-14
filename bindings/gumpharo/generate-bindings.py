#!/usr/bin/env python3
import argparse
import pathlib
import sys
import xml.etree.ElementTree as ET


CORE_NS = "http://www.gtk.org/introspection/core/1.0"
C_NS = "http://www.gtk.org/introspection/c/1.0"
GLIB_NS = "http://www.gtk.org/introspection/glib/1.0"

NS = {"g": CORE_NS, "c": C_NS, "glib": GLIB_NS}
C_TYPE = "{%s}type" % C_NS
C_IDENTIFIER = "{%s}identifier" % C_NS

MODULE_NAME = "GumPlugin"
PACKAGE_NAME = "GumPharo"
PRIMITIVES_CLASS = "GumPrimitives"

EXTRA_INCLUDES = [
    "gum/gumheapapi.h",
    "gum/gumswiftapiresolver.h",
]

HANDWRITTEN_PRIMITIVES = [
    ("primGumPharoListenerNew", "prim_gum_pharo_listener_new",
     "gumPharoListenerNewOnEnter: onEnter onLeave: onLeave"),
    ("primGumPharoPost", "prim_gum_pharo_post",
     "gumPharoPost: payload data: data"),
    ("primGumPharoTakeMessage", "prim_gum_pharo_take_message",
     "gumPharoTakeMessage"),
    ("primGumPharoMessagePayload", "prim_gum_pharo_message_payload",
     "gumPharoMessagePayload: message"),
    ("primGumPharoMessageData", "prim_gum_pharo_message_data",
     "gumPharoMessageData: message"),
    ("primGumPharoReleaseMessage", "prim_gum_pharo_release_message",
     "gumPharoReleaseMessage: message"),
    ("primGumPharoSetMessageSemaphore", "prim_gum_pharo_set_message_semaphore",
     "gumPharoSetMessageSemaphore: index"),
]
ACCESSOR_DEPTH = "\\000\\000"

POINTER_TYPES = {
    "gpointer", "gconstpointer", "va_list",
}

SIGNED_TYPES = {
    "gint", "gint8", "gint16", "gint32", "gint64", "glong", "gshort",
    "gssize", "goffset",
}

GLIB_CALLBACK_TYPES = {
    "GDestroyNotify", "GHashFunc", "GEqualFunc", "GHRFunc", "GFunc",
    "GCompareFunc", "GCompareDataFunc", "GCallback", "GSourceFunc",
}

STRING_TYPES = {
    "const gchar*", "gchar*", "const char*", "char*",
}

INTEGER_TYPES = {
    "gint", "guint", "gint8", "guint8", "gint16", "guint16",
    "gint32", "guint32", "gint64", "guint64", "glong", "gulong",
    "gshort", "gushort", "gsize", "gssize", "goffset", "gunichar",
    "gfloat", "gdouble", "GumAddress", "GumThreadId", "GumProcessId",
    "GType", "GumTlsKey",
}


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("gir")
    parser.add_argument("output_dir")
    arguments = parser.parse_args(argv[1:])

    namespace = ET.parse(arguments.gir).getroot().find("g:namespace", NS)
    pointerlike = collect_pointerlike(namespace)
    enumerations = collect_enumerations(namespace)
    bound, skipped = collect_entry_points(namespace, enumerations, pointerlike)
    collectors = collect_enumerators(namespace, bound,
                                     collect_enumerations(namespace,
                                                          aliases=False))

    output_dir = pathlib.Path(arguments.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "gumpharoprimitives.c").write_text(
        emit_primitives(bound, collectors))

    package_dir = output_dir / "pharo" / PACKAGE_NAME
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "package.st").write_text(
        "Package { #name : '%s' }\n" % PACKAGE_NAME)
    (package_dir / (PRIMITIVES_CLASS + ".class.st")).write_text(
        emit_primitives_class(bound, collectors))

    for symbol, reason in skipped:
        sys.stderr.write("skipped %s: %s\n" % (symbol, reason))
    sys.stderr.write("bound %d entry points, skipped %d\n"
                     % (len(bound), len(skipped)))


def collect_entry_points(namespace, enumerations, pointerlike):
    bound = []
    skipped = []
    seen = set()

    for owner in [namespace] + namespace.findall("g:class", NS) \
            + namespace.findall("g:interface", NS) \
            + namespace.findall("g:record", NS):
        for kind in ["constructor", "method", "function"]:
            for element in owner.findall("g:%s" % kind, NS):
                symbol = element.get(C_IDENTIFIER)
                if symbol is None or symbol in seen:
                    continue
                seen.add(symbol)
                try:
                    bound.append(describe_entry_point(element, symbol,
                                                      enumerations,
                                                      pointerlike))
                except Unbindable as reason:
                    skipped.append((symbol, str(reason)))

    bound.sort(key=lambda entry: entry.symbol)
    return bound, skipped


def describe_entry_point(element, symbol, enumerations, pointerlike):
    parameters = []
    holder = element.find("g:parameters", NS)
    if holder is not None:
        for parameter in list(holder):
            if parameter.tag != "{%s}parameter" % CORE_NS \
                    and parameter.tag != "{%s}instance-parameter" % CORE_NS:
                raise Unbindable("unsupported parameter kind")
            if parameter.get("direction", "in") != "in":
                raise Unbindable("out parameter")
            marshaller = marshaller_for(parameter, enumerations,
                                        pointerlike)
            marshaller.name = pharo_name_for(parameter, len(parameters))
            marshaller.nullable = parameter.get("nullable") == "1"
            parameters.append(marshaller)

    return EntryPoint(symbol,
                      marshaller_for(element.find("g:return-value", NS),
                                     enumerations, pointerlike),
                      parameters,
                      element.get("throws") == "1")


RESERVED_NAMES = {"self", "super", "true", "false", "nil", "thisContext"}


def pharo_name_for(parameter, index):
    if parameter.tag == "{%s}instance-parameter" % CORE_NS:
        return "handle"

    name = parameter.get("name")
    head, *rest = name.split("_")
    name = head + "".join(part.capitalize() for part in rest)

    return name + "Value" if name in RESERVED_NAMES else name


def marshaller_for(element, enumerations, pointerlike):
    type_element = element.find("g:type", NS)
    if type_element is None:
        if element.find("g:varargs", NS) is not None:
            raise Unbindable("varargs")
        raise Unbindable("non-scalar type")

    c_type = type_element.get(C_TYPE)
    if c_type is None:
        name = type_element.get("name")
        if name == "none":
            return VOID
        raise Unbindable("untyped %s" % name)

    if c_type == "void":
        return VOID
    if c_type in POINTER_TYPES or c_type in pointerlike:
        return POINTER.of(c_type)
    if c_type in STRING_TYPES:
        return STRING.of(c_type)
    if c_type.endswith("*"):
        if c_type.endswith("**"):
            raise Unbindable("pointer to pointer")
        return POINTER.of(c_type)
    if c_type == "gboolean":
        return BOOLEAN
    if c_type in INTEGER_TYPES or c_type in enumerations:
        return INTEGER.of(c_type)

    raise Unbindable("unmapped type %s" % c_type)


def collect_enumerators(namespace, entry_points, enumerations):
    callbacks = {element.get(C_TYPE): element
                 for element in namespace.findall("g:callback", NS)}
    records = {element.get(C_TYPE): element
               for element in namespace.findall("g:record", NS)}

    collectors = []
    for entry in entry_points:
        if entry.throws:
            continue
        described = describe_collector(entry, callbacks, records, enumerations)
        if described is None:
            continue
        at, declared, fields = described
        collectors.append(Collector(entry, at, declared, fields))

    return collectors


def describe_collector(entry, callbacks, records, enumerations):
    at = callback_parameter_of(entry, callbacks)
    if at is None:
        return None

    declared = callback_argument_type(callbacks[entry.parameters[at].c_type])
    if declared is None:
        return None

    record = records.get(declared.replace("const ", "").rstrip("* "))
    if record is not None:
        fields = scalar_fields_of(record, enumerations)
    elif declared.rstrip("* ") in POINTER_TYPES:
        fields = []
    else:
        fields = [("handle", "gpointer", False)]

    return (at, declared, fields) if fields else None


def callback_parameter_of(entry, callbacks):
    for index, parameter in enumerate(entry.parameters[:-1]):
        if parameter.c_type in callbacks \
                and entry.parameters[index + 1].c_type == "gpointer" \
                and answers_whether_to_continue(callbacks[parameter.c_type]):
            return index
    return None


def answers_whether_to_continue(callback):
    holder = callback.find("g:parameters", NS)
    if holder is None or len(holder.findall("g:parameter", NS)) != 2:
        return False

    returned = callback.find("g:return-value", NS)
    if returned is None:
        return False
    type_element = returned.find("g:type", NS)

    return type_element is not None \
        and type_element.get(C_TYPE) == "gboolean"


def callback_argument_type(callback):
    holder = callback.find("g:parameters", NS)
    if holder is None:
        return None
    first = holder.find("g:parameter", NS)
    if first is None:
        return None
    argument = first.find("g:type", NS)

    return argument.get(C_TYPE) if argument is not None else None


def scalar_fields_of(record, enumerations):
    fields = []
    for field in record.findall("g:field", NS):
        type_element = field.find("g:type", NS)
        if type_element is None:
            continue
        c_type = type_element.get(C_TYPE)
        if c_type in STRING_TYPES:
            fields.append((field.get("name"), c_type, True))
        elif c_type == "gboolean" or c_type in INTEGER_TYPES \
                or c_type in enumerations:
            fields.append((field.get("name"), c_type, False))
    return fields


def collect_pointerlike(namespace):
    names = set(GLIB_CALLBACK_TYPES)
    for element in namespace.findall("g:callback", NS):
        names.add(element.get(C_TYPE))
    return names


def collect_enumerations(namespace, aliases=True):
    names = set()
    for kind in ["enumeration", "bitfield"]:
        for element in namespace.findall("g:%s" % kind, NS):
            names.add(element.get(C_TYPE))
            names.add("Gum" + element.get("name"))
    if aliases:
        for element in namespace.findall("g:alias", NS):
            names.add(element.get(C_TYPE))
    return names


def emit_primitives(entry_points, collectors):
    lines = ['#include "gumpharo.h"', "", "#include <gum/gum.h>"] \
        + ["#include <%s>" % header for header in EXTRA_INCLUDES] + ["",
             "static sqInt", "setInterpreter (struct VirtualMachine * vm)",
             "{", "  return gum_pharo_set_interpreter (vm);", "}", "",
             "static const char *", "getModuleName (void)",
             "{", '  return "%s";' % MODULE_NAME, "}", ""]

    for entry in entry_points:
        lines += emit_primitive(entry)

    for collector in collectors:
        lines += emit_collector(collector)

    lines += emit_exports(entry_points, collectors)
    return "\n".join(lines) + "\n"


def emit_collector(collector):
    lines = ["typedef struct _%s %s;" % (collector.struct, collector.struct),
             "",
             "struct _%s" % collector.struct,
             "{"]
    for name, c_type, is_string in collector.fields:
        lines.append("  %s %s;" % ("gchar *" if is_string else c_type, name))
    lines += ["};", ""]

    lines += ["static gboolean",
              "%s (%s details," % (collector.function, collector.details_type),
              " " * (len(collector.function) + 2) + "gpointer user_data)",
              "{",
              "  GArray * entries = user_data;",
              "  %s entry;" % collector.struct,
              ""]
    for name, c_type, is_string in collector.fields:
        if name == "handle":
            lines.append("  entry.handle = (gpointer) details;")
        elif is_string:
            lines.append("  entry.%s = g_strdup (details->%s);" % (name, name))
        else:
            lines.append("  entry.%s = details->%s;" % (name, name))
    lines += ["",
              "  g_array_append_val (entries, entry);",
              "",
              "  return TRUE;",
              "}",
              ""]

    lines += ["static sqInt", "%s (void)" % collector.primitive_name, "{"]
    passed = collector.passed
    depth = len(passed) - 1
    names = []
    for index, parameter in enumerate(passed):
        lines.append("  %s a%d = (%s) %s (%d);"
                     % (parameter.c_type, index, parameter.c_type,
                        parameter.reader, depth - index))
        names.append("a%d" % index)
    arguments = names[:collector.at] + [collector.function, "entries"] \
        + names[collector.at:]
    lines += ["  GArray * entries;",
              "  guint i;",
              "",
              "  entries = g_array_new (FALSE, FALSE, sizeof (%s));"
              % collector.struct,
              "  %s (%s);" % (collector.entry.symbol, ", ".join(arguments)),
              "",
              "  gum_pharo_array_new (entries->len * %d);"
              % len(collector.fields),
              "  for (i = 0; i != entries->len; i++)",
              "  {",
              "    %s * entry = &g_array_index (entries, %s, i);"
              % (collector.struct, collector.struct),
              ""]
    for offset, (name, c_type, is_string) in enumerate(collector.fields):
        slot = "(i * %d) + %d" % (len(collector.fields), offset)
        if is_string:
            lines.append("    gum_pharo_array_put_utf8 (%s, entry->%s);"
                         % (slot, name))
            lines.append("    g_free (entry->%s);" % name)
        else:
            putter = "gum_pharo_array_put_signed" if c_type in SIGNED_TYPES \
                else "gum_pharo_array_put_integer"
            cast = "(gsize) " if name == "handle" else ""
            lines.append("    %s (%s, %sentry->%s);"
                         % (putter, slot, cast, name))
    lines += ["  }",
              "  g_array_free (entries, TRUE);",
              "",
              "  return gum_pharo_array_return ();",
              "}",
              ""]
    return lines


def emit_primitive(entry):
    lines = ["static sqInt", "%s (void)" % entry.primitive_name, "{"]

    depth = len(entry.parameters) - 1
    owned = []
    for index, parameter in enumerate(entry.parameters):
        lines.append("  %s a%d = (%s) %s (%d);"
                     % (parameter.c_type, index, parameter.c_type,
                        parameter.reader, depth - index))
        if parameter.owns_reading:
            owned.append("a%d" % index)

    required = ["a%d" % index
                for index, parameter in enumerate(entry.parameters)
                if parameter.is_pointer and not parameter.nullable]
    if required:
        lines.append("  if (%s)"
                     % " || ".join("%s == NULL" % name for name in required))
        lines.append("  {")
        for name in owned:
            lines.append("    g_free ((gpointer) %s);" % name)
        lines.append("    return gum_pharo_fail_bad_argument ();")
        lines.append("  }")

    call_arguments = ["a%d" % i for i in range(len(entry.parameters))]
    if entry.throws:
        call_arguments.append("NULL")
    call = "%s (%s)" % (entry.symbol, ", ".join(call_arguments))

    if entry.return_value is VOID:
        lines.append("  %s;" % call)
    else:
        lines.append("  sqInt r = %s ((%s) %s);"
                     % (entry.return_value.writer,
                        entry.return_value.writer_argument_type, call))

    for name in owned:
        lines.append("  g_free ((gpointer) %s);" % name)

    lines.append("  return %s;"
                 % ("gum_pharo_return_self ()"
                    if entry.return_value is VOID else "r"))

    lines += ["}", ""]
    return lines


def emit_exports(entry_points, collectors):
    lines = ['static char _m[] = "%s";' % MODULE_NAME,
             "",
             "void * %s_exports[][3] =" % MODULE_NAME,
             "{",
             '  { (void *) _m, "setInterpreter", (void *) setInterpreter },',
             '  { (void *) _m, "getModuleName", (void *) getModuleName },']

    exported = [(entry.primitive_name, entry.primitive_name)
                for entry in entry_points]
    exported += [(name, symbol)
                 for name, symbol, selector in HANDWRITTEN_PRIMITIVES]
    exported += [(collector.primitive_name, collector.primitive_name)
                 for collector in collectors]
    exported.sort()

    for name, symbol in exported:
        lines.append('  { (void *) _m, "%s%s", (void *) %s },'
                     % (name, ACCESSOR_DEPTH, symbol))

    lines += ["  { NULL, NULL, NULL },", "};"]
    return lines


def emit_primitives_class(entry_points, collectors):
    lines = ['Class {',
             "\t#name : '%s'," % PRIMITIVES_CLASS,
             "\t#superclass : 'Object',",
             "\t#category : '%s'," % PACKAGE_NAME,
             "\t#package : '%s'" % PACKAGE_NAME,
             "}",
             ""]

    methods = [(entry.selector, entry.primitive_name)
               for entry in entry_points]
    methods += [(selector, name)
                for name, symbol, selector in HANDWRITTEN_PRIMITIVES]
    methods += [(collector.selector, collector.primitive_name)
                for collector in collectors]

    selectors = [selector for selector, name in methods]
    if len(set(selectors)) != len(selectors):
        raise ValueError("colliding selectors: %s"
                         % sorted(s for s in selectors
                                  if selectors.count(s) > 1))

    for selector, name in methods:
        lines += emit_primitive_method(selector, name)

    for collector in collectors:
        lines += ["{ #category : 'generated' }",
                  "%s class >> %s [" % (PRIMITIVES_CLASS,
                                        collector.fields_selector),
                  "\t^ #( %s )" % " ".join("'%s'" % pharo_field_name(name)
                                           for name, _, _ in collector.fields),
                  "]",
                  ""]

    return "\n".join(lines)


def pharo_field_name(name):
    head, *rest = name.split("_")
    return head + "".join(part.capitalize() for part in rest)


class Collector:
    def __init__(self, entry, at, details_type, fields):
        self.entry = entry
        self.at = at
        self.details_type = details_type
        self.fields = fields

    @property
    def passed(self):
        return self.entry.parameters[:self.at] \
            + self.entry.parameters[self.at + 2:]

    @property
    def base(self):
        return self.entry.symbol + "_all"

    @property
    def struct(self):
        return "".join(part.capitalize()
                       for part in self.entry.symbol.split("_")) + "Entry"

    @property
    def function(self):
        return "gum_pharo_collect" + self.entry.symbol[3:]

    @property
    def primitive_name(self):
        return "prim" + "".join(part.capitalize()
                                for part in self.base.split("_"))

    @property
    def selector(self):
        leading = self.passed
        base = self.base.split("_")
        base = base[0] + "".join(part.capitalize() for part in base[1:])
        if not leading:
            return base
        keywords = ["%s: %s" % (base, leading[0].name)]
        keywords += ["%s: %s" % (p.name, p.name) for p in leading[1:]]
        return " ".join(keywords)

    @property
    def fields_selector(self):
        base = (self.base + "_fields").split("_")
        return base[0] + "".join(part.capitalize() for part in base[1:])


def emit_primitive_method(selector, primitive_name):
    return ["{ #category : 'generated' }",
            "%s class >> %s [" % (PRIMITIVES_CLASS, selector),
            "\t<primitive: '%s' module: '%s'>" % (primitive_name, MODULE_NAME),
            "\t^ self primitiveFailed",
            "]",
            ""]


class Marshaller:
    def __init__(self, c_type, reader, writer, writer_argument_type=None):
        self.c_type = c_type
        self.reader = reader
        self.writer = writer
        self.writer_argument_type = writer_argument_type

    nullable = False

    @property
    def owns_reading(self):
        return self.reader == "gum_pharo_string_at"

    @property
    def is_pointer(self):
        if self.c_type in ["gpointer", "gconstpointer"]:
            return False
        return self.reader in ["gum_pharo_pointer_at", "gum_pharo_string_at"]

    def of(self, c_type):
        return Marshaller(c_type, self.reader, self.writer,
                          self.writer_argument_type)

    name = None


VOID = Marshaller("void", None, None)
STRING = Marshaller("gchar *", "gum_pharo_string_at",
                    "gum_pharo_return_utf8", "const gchar *")
POINTER = Marshaller("gpointer", "gum_pharo_pointer_at",
                     "gum_pharo_return_pointer", "gpointer")
INTEGER = Marshaller("guint64", "gum_pharo_integer_at",
                     "gum_pharo_return_integer", "guint64")
BOOLEAN = Marshaller("gboolean", "gum_pharo_boolean_at",
                     "gum_pharo_return_boolean", "gboolean")


class EntryPoint:
    def __init__(self, symbol, return_value, parameters, throws):
        self.symbol = symbol
        self.return_value = return_value
        self.parameters = parameters
        self.throws = throws

    @property
    def selector(self):
        base = self.symbol.split("_")
        base = base[0] + "".join(part.capitalize() for part in base[1:])

        if len(self.parameters) == 0:
            return base

        keywords = ["%s: %s" % (base, self.parameters[0].name)]
        keywords += ["%s: %s" % (parameter.name, parameter.name)
                     for parameter in self.parameters[1:]]

        return " ".join(keywords)

    @property
    def primitive_name(self):
        return "prim" + "".join(part.capitalize()
                                for part in self.symbol.split("_"))


class Unbindable(Exception):
    pass


if __name__ == "__main__":
    main(sys.argv)
