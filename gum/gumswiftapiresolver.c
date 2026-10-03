/*
 * Copyright (C) 2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023-2026 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

/**
 * GumSwiftApiResolver:
 *
 * Resolves APIs by searching currently loaded Swift modules. Functions are
 * matched by demangled name, e.g. `functions:*!Swift.String.hasPrefix*`.
 * Nominal types and protocols are matched by full name, e.g.
 * `types:*!Swift.Int` and `protocols:libswiftCore.dylib!Swift.*`, where each
 * match is the address of the context descriptor. Protocol conformances are
 * matched by type and protocol name, e.g. `conformances:Swift.Int!Swift.*`,
 * where each match is the address of the conformance descriptor.
 *
 * See [iface@Gum.ApiResolver] for more information.
 */

#include "gumswiftapiresolver.h"

#include "gummodulemap.h"
#include "gumprocess.h"

#include <capstone.h>
#include <string.h>

#define GUM_DESCRIPTOR_FLAGS_KIND(flags) \
    (flags & 0x1f)
#define GUM_DESCRIPTOR_FLAGS_KIND_FLAGS(flags) \
    (flags >> 16)
#define GUM_DESCRIPTOR_FLAGS_IS_GENERIC(flags) \
    ((flags & GUM_DESCRIPTOR_IS_GENERIC) != 0)
#define GUM_DESCRIPTOR_FLAGS_IS_UNIQUE(flags) \
    ((flags & GUM_DESCRIPTOR_IS_UNIQUE) != 0)

#define GUM_ANONYMOUS_DESCRIPTOR_FLAGS_HAS_MANGLED_NAME(flags) \
    ((flags & GUM_ANONYMOUS_DESCRIPTOR_HAS_MANGLED_NAME) != 0)

#define GUM_TYPE_FLAGS_METADATA_INITIALIZATION_MASK(flags) \
    (flags & 3)
#define GUM_TYPE_FLAGS_CLASS_HAS_VTABLE(flags) \
    ((flags & GUM_CLASS_HAS_VTABLE) != 0)
#define GUM_TYPE_FLAGS_CLASS_HAS_OVERRIDE_TABLE(flags) \
    ((flags & GUM_CLASS_HAS_OVERRIDE_TABLE) != 0)
#define GUM_TYPE_FLAGS_CLASS_HAS_RESILIENT_SUPERCLASS(flags) \
    ((flags & GUM_CLASS_HAS_RESILIENT_SUPERCLASS) != 0)

#define GUM_GENERIC_DESCRIPTOR_FLAGS_HAS_TYPE_PACKS(flags) \
    ((flags & GUM_GENERIC_DESCRIPTOR_HAS_TYPE_PACKS) != 0)

#define GUM_METHOD_DESCRIPTOR_IS_ASYNC(desc) \
    (((desc)->flags & GUM_METHOD_ASYNC) != 0)

#define GUM_CONFORMANCE_FLAGS_TYPE_REFERENCE_KIND(flags) \
    (((flags) >> 3) & 7)

#define GUM_PROTOCOL_RECORD_RESERVED_BIT 2

#if defined (HAVE_WINDOWS)
# define GUM_SWIFT_CORE_MODULE "swiftCore.dll"
# define GUM_SWIFT_TYPES_SECTION ".sw5tymd"
# define GUM_SWIFT_TYPES2_SECTION ".sw5tym2"
# define GUM_SWIFT_PROTOCOLS_SECTION ".sw5prt"
# define GUM_SWIFT_CONFORMANCES_SECTION ".sw5prtc"
#elif defined (HAVE_DARWIN)
# define GUM_SWIFT_CORE_MODULE "libswiftCore.dylib"
# define GUM_SWIFT_TYPES_SECTION "__swift5_types"
# define GUM_SWIFT_TYPES2_SECTION "__swift5_types2"
# define GUM_SWIFT_PROTOCOLS_SECTION "__swift5_protos"
# define GUM_SWIFT_CONFORMANCES_SECTION "__swift5_proto"
#else
# define GUM_SWIFT_CORE_MODULE "libswiftCore.so"
# define GUM_SWIFT_TYPES_SECTION "swift5_type_metadata"
# define GUM_SWIFT_TYPES2_SECTION "swift5_type_metadata_2"
# define GUM_SWIFT_PROTOCOLS_SECTION "swift5_protocols"
# define GUM_SWIFT_CONFORMANCES_SECTION "swift5_protocol_conformances"
#endif

#define GUM_ALIGN(ptr, type) \
    GUM_ALIGN_POINTER (type *, ptr, G_ALIGNOF (type))

typedef struct _GumModuleMetadata GumModuleMetadata;
typedef struct _GumFunctionMetadata GumFunctionMetadata;
typedef struct _GumDescriptorMetadata GumDescriptorMetadata;
typedef struct _GumConformanceMetadata GumConformanceMetadata;
typedef const gchar * (* GumClassGetName) (gpointer klass);
typedef gchar * (* GumSwiftDemangle) (const gchar * mangled_name,
    gsize mangled_name_length, gchar * output_buffer,
    gsize * output_buffer_size, guint32 flags);
typedef void (* GumLibcFreeFunc) (gpointer mem);

typedef struct _GumClass GumClass;

typedef guint GumContextDescriptorKind;
typedef struct _GumContextDescriptor GumContextDescriptor;
typedef struct _GumModuleContextDescriptor GumModuleContextDescriptor;
typedef struct _GumExtensionContextDescriptor GumExtensionContextDescriptor;
typedef struct _GumTypeContextDescriptor GumTypeContextDescriptor;
typedef struct _GumProtocolDescriptor GumProtocolDescriptor;
typedef struct _GumProtocolConformanceDescriptor
    GumProtocolConformanceDescriptor;
typedef guint GumTypeReferenceKind;
typedef struct _GumClassDescriptor GumClassDescriptor;
typedef struct _GumGenericContextDescriptorHeader
    GumGenericContextDescriptorHeader;
typedef struct _GumGenericParamDescriptor GumGenericParamDescriptor;
typedef struct _GumGenericRequirementDescriptor GumGenericRequirementDescriptor;
typedef struct _GumTypeGenericContextDescriptorHeader
    GumTypeGenericContextDescriptorHeader;
typedef struct _GumGenericPackShapeHeader GumGenericPackShapeHeader;
typedef struct _GumGenericPackShapeDescriptor GumGenericPackShapeDescriptor;
typedef guint16 GumGenericPackKind;
typedef struct _GumResilientSuperclass GumResilientSuperclass;
typedef struct _GumSingletonMetadataInitialization
    GumSingletonMetadataInitialization;
typedef struct _GumForeignMetadataInitialization
    GumForeignMetadataInitialization;
typedef struct _GumVTableDescriptorHeader GumVTableDescriptorHeader;
typedef struct _GumMethodDescriptor GumMethodDescriptor;
typedef struct _GumOverrideTableHeader GumOverrideTableHeader;
typedef struct _GumMethodOverrideDescriptor GumMethodOverrideDescriptor;

typedef gint32 GumRelativeDirectPtr;
typedef gint32 GumRelativeIndirectPtr;
typedef gint32 GumRelativeIndirectablePtr;

struct _GumSwiftApiResolver
{
  GObject parent;

  GRegex * query_pattern;

  GHashTable * modules;
  GumModuleMap * all_modules;
  GHashTable * context_names;

  GumSwiftDemangle swift_demangle;
  GumLibcFreeFunc libc_free;
};

struct _GumModuleMetadata
{
  gint ref_count;

  GumModule * module;

  GArray * functions;
  GHashTable * vtables;
  GArray * types;
  GArray * protocols;
  GArray * conformances;
  GumSwiftApiResolver * resolver;
};

struct _GumFunctionMetadata
{
  gchar * name;
  GumAddress address;
};

struct _GumDescriptorMetadata
{
  const gchar * name;
  GumAddress address;
};

struct _GumConformanceMetadata
{
  const gchar * type_name;
  const gchar * protocol_name;
  GumAddress descriptor;
};

struct _GumClass
{
  gchar * name;

  const GumMethodDescriptor * methods;
  guint num_methods;

  const GumMethodOverrideDescriptor * overrides;
  guint num_overrides;
};

enum _GumContextDescriptorKind
{
  GUM_CONTEXT_DESCRIPTOR_MODULE,
  GUM_CONTEXT_DESCRIPTOR_EXTENSION,
  GUM_CONTEXT_DESCRIPTOR_ANONYMOUS,
  GUM_CONTEXT_DESCRIPTOR_PROTOCOL,
  GUM_CONTEXT_DESCRIPTOR_OPAQUE_TYPE,

  GUM_CONTEXT_DESCRIPTOR_TYPE_FIRST = 16,

  GUM_CONTEXT_DESCRIPTOR_CLASS = GUM_CONTEXT_DESCRIPTOR_TYPE_FIRST,
  GUM_CONTEXT_DESCRIPTOR_STRUCT = GUM_CONTEXT_DESCRIPTOR_TYPE_FIRST + 1,
  GUM_CONTEXT_DESCRIPTOR_ENUM = GUM_CONTEXT_DESCRIPTOR_TYPE_FIRST + 2,

  GUM_CONTEXT_DESCRIPTOR_TYPE_LAST = 31,
};

enum _GumContextDescriptorFlags
{
  GUM_DESCRIPTOR_IS_GENERIC = (1 << 7),
  GUM_DESCRIPTOR_IS_UNIQUE  = (1 << 6),
};

enum _GumAnonymousContextDescriptorFlags
{
  GUM_ANONYMOUS_DESCRIPTOR_HAS_MANGLED_NAME = (1 << 0),
};

enum _GumTypeContextDescriptorFlags
{
  GUM_CLASS_HAS_VTABLE               = (1 << 15),
  GUM_CLASS_HAS_OVERRIDE_TABLE       = (1 << 14),
  GUM_CLASS_HAS_RESILIENT_SUPERCLASS = (1 << 13),
};

enum _GumTypeMetadataInitializationKind
{
  GUM_METADATA_INITIALIZATION_NONE,
  GUM_METADATA_INITIALIZATION_SINGLETON,
  GUM_METADATA_INITIALIZATION_FOREIGN,
};

struct _GumContextDescriptor
{
  guint32 flags;
  GumRelativeIndirectablePtr parent;
};

struct _GumModuleContextDescriptor
{
  GumContextDescriptor context;
  GumRelativeDirectPtr name;
};

struct _GumExtensionContextDescriptor
{
  GumContextDescriptor context;
  GumRelativeDirectPtr extended_context;
};

struct _GumTypeContextDescriptor
{
  GumContextDescriptor context;
  GumRelativeDirectPtr name;
  GumRelativeDirectPtr access_function_ptr;
  GumRelativeDirectPtr fields;
};

struct _GumProtocolDescriptor
{
  GumContextDescriptor context;
  GumRelativeDirectPtr name;
  guint32 num_requirements_in_signature;
  guint32 num_requirements;
  GumRelativeDirectPtr associated_type_names;
};

struct _GumProtocolConformanceDescriptor
{
  GumRelativeIndirectablePtr protocol;
  GumRelativeDirectPtr type_ref;
  GumRelativeDirectPtr witness_table_pattern;
  guint32 flags;
};

enum _GumTypeReferenceKind
{
  GUM_TYPE_REFERENCE_DIRECT_TYPE_DESCRIPTOR,
  GUM_TYPE_REFERENCE_INDIRECT_TYPE_DESCRIPTOR,
  GUM_TYPE_REFERENCE_DIRECT_OBJC_CLASS_NAME,
  GUM_TYPE_REFERENCE_INDIRECT_OBJC_CLASS,
};

struct _GumClassDescriptor
{
  GumTypeContextDescriptor type_context;
  GumRelativeDirectPtr superclass_type;
  guint32 metadata_negative_size_in_words_or_resilient_metadata_bounds;
  guint32 metadata_positive_size_in_words_or_extra_class_flags;
  guint32 num_immediate_members;
  guint32 num_fields;
  guint32 field_offset_vector_offset;
};

struct _GumGenericContextDescriptorHeader
{
  guint16 num_params;
  guint16 num_requirements;
  guint16 num_key_arguments;
  guint16 flags;
};

enum _GumGenericContextDescriptorFlags
{
  GUM_GENERIC_DESCRIPTOR_HAS_TYPE_PACKS = (1 << 0),
};

struct _GumGenericParamDescriptor
{
  guint8 value;
};

struct _GumGenericRequirementDescriptor
{
  guint32 flags;
  GumRelativeDirectPtr param;
  GumRelativeDirectPtr type_or_protocol_or_conformance_or_layout;
};

struct _GumTypeGenericContextDescriptorHeader
{
  GumRelativeDirectPtr instantiation_cache;
  GumRelativeDirectPtr default_instantiation_pattern;
  GumGenericContextDescriptorHeader base;
};

struct _GumGenericPackShapeHeader
{
  guint16 num_packs;
  guint16 num_shape_classes;
};

struct _GumGenericPackShapeDescriptor
{
  GumGenericPackKind kind;
  guint16 index;
  guint16 shape_class;
  guint16 unused;
};

enum _GumGenericPackKind
{
  GUM_GENERIC_PACK_METADATA,
  GUM_GENERIC_PACK_WITNESS_TABLE,
};

struct _GumResilientSuperclass
{
  GumRelativeDirectPtr superclass;
};

struct _GumSingletonMetadataInitialization
{
  GumRelativeDirectPtr initialization_cache;
  GumRelativeDirectPtr incomplete_metadata_or_resilient_pattern;
  GumRelativeDirectPtr completion_function;
};

struct _GumForeignMetadataInitialization
{
  GumRelativeDirectPtr completion_function;
};

struct _GumVTableDescriptorHeader
{
  guint32 vtable_offset;
  guint32 vtable_size;
};

struct _GumMethodDescriptor
{
  guint32 flags;
  GumRelativeDirectPtr impl;
};

enum _GumMethodDescriptorFlags
{
  GUM_METHOD_ASYNC = (1 << 6),
};

struct _GumOverrideTableHeader
{
  guint32 num_entries;
};

struct _GumMethodOverrideDescriptor
{
  GumRelativeIndirectablePtr class;
  GumRelativeIndirectablePtr method;
  GumRelativeDirectPtr impl;
};

static void gum_swift_api_resolver_iface_init (gpointer g_iface,
    gpointer iface_data);
static GumModuleMetadata * gum_swift_api_resolver_register_module (
    GumSwiftApiResolver * self, GumModule * module);
static void gum_swift_api_resolver_dispose (GObject * object);
static void gum_swift_api_resolver_finalize (GObject * object);
static void gum_swift_api_resolver_enumerate_matches (
    GumApiResolver * resolver, const gchar * query, GumFoundApiFunc func,
    gpointer user_data, GError ** error);
static void gum_swift_api_resolver_enumerate_functions (
    GumSwiftApiResolver * self, GPatternSpec * module_spec,
    GPatternSpec * func_spec, gboolean ignore_case, GumFoundApiFunc func,
    gpointer user_data);
static void gum_swift_api_resolver_enumerate_descriptors (
    GumSwiftApiResolver * self, GArray * (* get_descriptors) (
    GumModuleMetadata * module), GPatternSpec * module_spec,
    GPatternSpec * name_spec, gboolean ignore_case, GumFoundApiFunc func,
    gpointer user_data);
static void gum_swift_api_resolver_enumerate_conformances (
    GumSwiftApiResolver * self, GPatternSpec * type_spec,
    GPatternSpec * protocol_spec, gboolean ignore_case, GumFoundApiFunc func,
    gpointer user_data);

static void gum_module_metadata_unref (GumModuleMetadata * module);
static gboolean gum_module_metadata_matches (GumModuleMetadata * self,
    GPatternSpec * spec, gboolean ignore_case);
static GArray * gum_module_metadata_get_functions (GumModuleMetadata * self);
static gboolean gum_module_metadata_collect_export (
    const GumExportDetails * details, gpointer user_data);
static gboolean gum_module_metadata_collect_section (
    const GumSectionDetails * details, gpointer user_data);
static void gum_module_metadata_collect_class (GumModuleMetadata * self,
    const GumTypeContextDescriptor * type);
static void gum_module_metadata_maybe_ingest_thunk (GumModuleMetadata * self,
    const gchar * name, GumAddress address);
#ifdef HAVE_ARM64
static gchar * gum_extract_class_name (const gchar * full_name);
static const gchar * gum_find_character_backwards (const gchar * starting_point,
    char needle, const gchar * start);
#endif

static GArray * gum_module_metadata_get_types (GumModuleMetadata * self);
static gboolean gum_module_metadata_collect_type_section (
    const GumSectionDetails * details, gpointer user_data);
static GArray * gum_module_metadata_get_protocols (GumModuleMetadata * self);
static gboolean gum_module_metadata_collect_protocol_section (
    const GumSectionDetails * details, gpointer user_data);
static void gum_module_metadata_add_descriptor (GumModuleMetadata * self,
    GArray * descriptors, const GumContextDescriptor * cd);
static GArray * gum_module_metadata_get_conformances (
    GumModuleMetadata * self);
static gboolean gum_module_metadata_collect_conformance_section (
    const GumSectionDetails * details, gpointer user_data);
static const gchar * gum_module_metadata_resolve_conforming_type_name (
    GumModuleMetadata * self, const GumProtocolConformanceDescriptor * cd);
static const gchar * gum_swift_api_resolver_get_context_name (
    GumSwiftApiResolver * self, const GumContextDescriptor * cd);
static gboolean gum_swift_api_resolver_ensure_demangler (
    GumSwiftApiResolver * self);
static gchar * gum_swift_api_resolver_demangle (GumSwiftApiResolver * self,
    const gchar * name);

static void gum_function_metadata_free (GumFunctionMetadata * function);

static void gum_class_parse (GumSwiftApiResolver * resolver, GumClass * klass,
    const GumClassDescriptor * cd);
static void gum_class_clear (GumClass * klass);

static gconstpointer gum_resolve_method_implementation (
    const GumRelativeDirectPtr * impl, const GumMethodDescriptor * method);

static gchar * gum_compute_context_descriptor_name (
    GumSwiftApiResolver * resolver, const GumContextDescriptor * cd);
static void gum_append_demangled_context_name (GumSwiftApiResolver * resolver,
    GString * result, const gchar * mangled_name);

static void gum_skip_generic_type_trailers (gconstpointer * trailer_ptr,
    const GumTypeContextDescriptor * t);
static void gum_skip_generic_parts (gconstpointer * trailer_ptr,
    const GumGenericContextDescriptorHeader * h);
static void gum_skip_resilient_superclass_trailer (gconstpointer * trailer_ptr,
    const GumTypeContextDescriptor * t);
static void gum_skip_metadata_initialization_trailers (
    gconstpointer * trailer_ptr, const GumTypeContextDescriptor * t);

static gconstpointer gum_resolve_relative_direct_ptr (
    const GumRelativeDirectPtr * delta);
static gconstpointer gum_resolve_relative_indirect_ptr (
    const GumRelativeIndirectPtr * delta);
static gconstpointer gum_resolve_relative_indirectable_ptr (
    const GumRelativeIndirectablePtr * delta);
static gconstpointer gum_resolve_protocol_record (
    const GumRelativeIndirectablePtr * record);

G_DEFINE_TYPE_EXTENDED (GumSwiftApiResolver,
                        gum_swift_api_resolver,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_API_RESOLVER,
                            gum_swift_api_resolver_iface_init))

static void
gum_swift_api_resolver_class_init (GumSwiftApiResolverClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_swift_api_resolver_dispose;
  object_class->finalize = gum_swift_api_resolver_finalize;
}

static void
gum_swift_api_resolver_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumApiResolverInterface * iface = g_iface;

  iface->enumerate_matches = gum_swift_api_resolver_enumerate_matches;
}

static void
gum_swift_api_resolver_init (GumSwiftApiResolver * self)
{
  GPtrArray * entries;
  guint i;

  self->query_pattern = g_regex_new (
      "(functions|types|protocols|conformances):(.+)!([^\\n\\r\\/]+)(\\/i)?",
      0, 0, NULL);

  self->modules = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
      (GDestroyNotify) gum_module_metadata_unref);

  self->all_modules = gum_module_map_new ();

  self->context_names = g_hash_table_new_full (NULL, NULL, NULL, g_free);

  entries = gum_module_map_get_values (self->all_modules);
  for (i = 0; i != entries->len; i++)
  {
    GumModule * m = g_ptr_array_index (entries, i);

    gum_swift_api_resolver_register_module (self, m);
  }
}

static GumModuleMetadata *
gum_swift_api_resolver_register_module (GumSwiftApiResolver * self,
                                        GumModule * module)
{
  GumModuleMetadata * meta;

  meta = g_slice_new0 (GumModuleMetadata);
  meta->ref_count = 2;
  meta->module = module;
  meta->functions = NULL;
  meta->vtables = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) g_ptr_array_unref);
  meta->types = NULL;
  meta->protocols = NULL;
  meta->conformances = NULL;
  meta->resolver = self;

  g_hash_table_insert (self->modules, (gpointer) gum_module_get_name (module),
      meta);
  g_hash_table_insert (self->modules, (gpointer) gum_module_get_path (module),
      meta);

  return meta;
}

static void
gum_swift_api_resolver_dispose (GObject * object)
{
  GumSwiftApiResolver * self = GUM_SWIFT_API_RESOLVER (object);

  g_clear_object (&self->all_modules);

  g_clear_pointer (&self->modules, g_hash_table_unref);
  g_clear_pointer (&self->context_names, g_hash_table_unref);

  G_OBJECT_CLASS (gum_swift_api_resolver_parent_class)->dispose (object);
}

static void
gum_swift_api_resolver_finalize (GObject * object)
{
  GumSwiftApiResolver * self = GUM_SWIFT_API_RESOLVER (object);

  g_regex_unref (self->query_pattern);

  G_OBJECT_CLASS (gum_swift_api_resolver_parent_class)->finalize (object);
}

/**
 * gum_swift_api_resolver_new:
 *
 * Creates a new resolver that searches exports and imports of currently loaded
 * modules.
 *
 * Returns: (transfer full): the newly created resolver instance
 */
GumApiResolver *
gum_swift_api_resolver_new (void)
{
  return g_object_new (GUM_TYPE_SWIFT_API_RESOLVER, NULL);
}

static void
gum_swift_api_resolver_enumerate_matches (GumApiResolver * resolver,
                                          const gchar * query,
                                          GumFoundApiFunc func,
                                          gpointer user_data,
                                          GError ** error)
{
  GumSwiftApiResolver * self = GUM_SWIFT_API_RESOLVER (resolver);
  GMatchInfo * query_info;
  gboolean ignore_case;
  gchar * collection, * module_query, * func_query;
  GPatternSpec * module_spec, * func_spec;

  if (!gum_swift_api_resolver_ensure_demangler (self))
    goto unsupported_runtime;

  g_regex_match (self->query_pattern, query, 0, &query_info);
  if (!g_match_info_matches (query_info))
    goto invalid_query;

  ignore_case = g_match_info_get_match_count (query_info) >= 5;

  collection = g_match_info_fetch (query_info, 1);
  module_query = g_match_info_fetch (query_info, 2);
  func_query = g_match_info_fetch (query_info, 3);

  g_match_info_free (query_info);

  if (ignore_case)
  {
    gchar * str;

    str = g_utf8_strdown (module_query, -1);
    g_free (module_query);
    module_query = str;

    str = g_utf8_strdown (func_query, -1);
    g_free (func_query);
    func_query = str;
  }

  module_spec = g_pattern_spec_new (module_query);
  func_spec = g_pattern_spec_new (func_query);

  if (strcmp (collection, "functions") == 0)
  {
    gum_swift_api_resolver_enumerate_functions (self, module_spec, func_spec,
        ignore_case, func, user_data);
  }
  else if (strcmp (collection, "types") == 0)
  {
    gum_swift_api_resolver_enumerate_descriptors (self,
        gum_module_metadata_get_types, module_spec, func_spec, ignore_case,
        func, user_data);
  }
  else if (strcmp (collection, "protocols") == 0)
  {
    gum_swift_api_resolver_enumerate_descriptors (self,
        gum_module_metadata_get_protocols, module_spec, func_spec,
        ignore_case, func, user_data);
  }
  else
  {
    gum_swift_api_resolver_enumerate_conformances (self, module_spec,
        func_spec, ignore_case, func, user_data);
  }

  g_pattern_spec_free (func_spec);
  g_pattern_spec_free (module_spec);

  g_free (func_query);
  g_free (module_query);
  g_free (collection);

  return;

unsupported_runtime:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "unsupported Swift runtime; please file a bug");
  }
invalid_query:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "invalid query; format is: "
        "functions:*someModule*!SomeClassPrefix*.*secret*(), "
        "types:*!Swift.Int, protocols:*!Swift.Hashable, "
        "or conformances:Swift.Int!Swift.*");
  }
}

static void
gum_swift_api_resolver_enumerate_functions (GumSwiftApiResolver * self,
                                            GPatternSpec * module_spec,
                                            GPatternSpec * func_spec,
                                            gboolean ignore_case,
                                            GumFoundApiFunc func,
                                            gpointer user_data)
{
  GHashTableIter module_iter;
  GHashTable * seen_modules;
  gboolean carry_on;
  GumModuleMetadata * module;

  g_hash_table_iter_init (&module_iter, self->modules);
  seen_modules = g_hash_table_new (NULL, NULL);
  carry_on = TRUE;

  while (carry_on &&
      g_hash_table_iter_next (&module_iter, NULL, (gpointer *) &module))
  {
    const gchar * module_path;

    if (g_hash_table_contains (seen_modules, module))
      continue;
    g_hash_table_add (seen_modules, module);

    module_path = gum_module_get_path (module->module);

    if (gum_module_metadata_matches (module, module_spec, ignore_case))
    {
      GArray * functions;
      guint i;

      functions = gum_module_metadata_get_functions (module);

      for (i = 0; carry_on && i != functions->len; i++)
      {
        const GumFunctionMetadata * f =
            &g_array_index (functions, GumFunctionMetadata, i);

        if (g_pattern_spec_match_string (func_spec, f->name))
        {
          GumApiDetails details;

          details.name = g_strconcat (
              module_path,
              "!",
              f->name,
              NULL);
          details.address = f->address;
          details.size = GUM_API_SIZE_NONE;

          carry_on = func (&details, user_data);

          g_free ((gpointer) details.name);
        }
      }
    }
  }

  g_hash_table_unref (seen_modules);
}

static void
gum_swift_api_resolver_enumerate_descriptors (
    GumSwiftApiResolver * self,
    GArray * (* get_descriptors) (GumModuleMetadata * module),
    GPatternSpec * module_spec,
    GPatternSpec * name_spec,
    gboolean ignore_case,
    GumFoundApiFunc func,
    gpointer user_data)
{
  GHashTableIter module_iter;
  GHashTable * seen_modules;
  gboolean carry_on;
  GumModuleMetadata * module;

  g_hash_table_iter_init (&module_iter, self->modules);
  seen_modules = g_hash_table_new (NULL, NULL);
  carry_on = TRUE;

  while (carry_on &&
      g_hash_table_iter_next (&module_iter, NULL, (gpointer *) &module))
  {
    const gchar * module_path;
    GArray * descriptors;
    guint i;

    if (g_hash_table_contains (seen_modules, module))
      continue;
    g_hash_table_add (seen_modules, module);

    if (!gum_module_metadata_matches (module, module_spec, ignore_case))
      continue;

    module_path = gum_module_get_path (module->module);

    descriptors = get_descriptors (module);

    for (i = 0; carry_on && i != descriptors->len; i++)
    {
      const GumDescriptorMetadata * d =
          &g_array_index (descriptors, GumDescriptorMetadata, i);
      const gchar * name = d->name;
      gchar * name_copy = NULL;

      if (ignore_case)
      {
        name_copy = g_utf8_strdown (name, -1);
        name = name_copy;
      }

      if (g_pattern_spec_match_string (name_spec, name))
      {
        GumApiDetails details;

        details.name = g_strconcat (module_path, "!", d->name, NULL);
        details.address = d->address;
        details.size = GUM_API_SIZE_NONE;

        carry_on = func (&details, user_data);

        g_free ((gpointer) details.name);
      }

      g_free (name_copy);
    }
  }

  g_hash_table_unref (seen_modules);
}

static void
gum_swift_api_resolver_enumerate_conformances (GumSwiftApiResolver * self,
                                               GPatternSpec * type_spec,
                                               GPatternSpec * protocol_spec,
                                               gboolean ignore_case,
                                               GumFoundApiFunc func,
                                               gpointer user_data)
{
  GHashTableIter module_iter;
  GHashTable * seen_modules;
  gboolean carry_on;
  GumModuleMetadata * module;

  g_hash_table_iter_init (&module_iter, self->modules);
  seen_modules = g_hash_table_new (NULL, NULL);
  carry_on = TRUE;

  while (carry_on &&
      g_hash_table_iter_next (&module_iter, NULL, (gpointer *) &module))
  {
    GArray * conformances;
    guint i;

    if (g_hash_table_contains (seen_modules, module))
      continue;
    g_hash_table_add (seen_modules, module);

    conformances = gum_module_metadata_get_conformances (module);

    for (i = 0; carry_on && i != conformances->len; i++)
    {
      const GumConformanceMetadata * c =
          &g_array_index (conformances, GumConformanceMetadata, i);
      const gchar * type_name = c->type_name;
      const gchar * protocol_name = c->protocol_name;
      gchar * type_name_copy = NULL;
      gchar * protocol_name_copy = NULL;

      if (ignore_case)
      {
        type_name_copy = g_utf8_strdown (type_name, -1);
        type_name = type_name_copy;

        protocol_name_copy = g_utf8_strdown (protocol_name, -1);
        protocol_name = protocol_name_copy;
      }

      if (g_pattern_spec_match_string (type_spec, type_name) &&
          g_pattern_spec_match_string (protocol_spec, protocol_name))
      {
        GumApiDetails details;

        details.name = g_strconcat (c->type_name, "!", c->protocol_name, NULL);
        details.address = c->descriptor;
        details.size = GUM_API_SIZE_NONE;

        carry_on = func (&details, user_data);

        g_free ((gpointer) details.name);
      }

      g_free (protocol_name_copy);
      g_free (type_name_copy);
    }
  }

  g_hash_table_unref (seen_modules);
}

static void
gum_module_metadata_unref (GumModuleMetadata * module)
{
  module->ref_count--;
  if (module->ref_count == 0)
  {
    if (module->vtables != NULL)
      g_hash_table_unref (module->vtables);

    if (module->functions != NULL)
      g_array_unref (module->functions);

    if (module->types != NULL)
      g_array_unref (module->types);

    if (module->protocols != NULL)
      g_array_unref (module->protocols);

    if (module->conformances != NULL)
      g_array_unref (module->conformances);

    g_slice_free (GumModuleMetadata, module);
  }
}

static gboolean
gum_module_metadata_matches (GumModuleMetadata * self,
                             GPatternSpec * spec,
                             gboolean ignore_case)
{
  const gchar * name, * path;
  gchar * name_copy = NULL;
  gchar * path_copy = NULL;
  gboolean matches;

  name = gum_module_get_name (self->module);
  path = gum_module_get_path (self->module);

  if (ignore_case)
  {
    name_copy = g_utf8_strdown (name, -1);
    name = name_copy;

    path_copy = g_utf8_strdown (path, -1);
    path = path_copy;
  }

  matches = g_pattern_spec_match_string (spec, name) ||
      g_pattern_spec_match_string (spec, path);

  g_free (path_copy);
  g_free (name_copy);

  return matches;
}

static GArray *
gum_module_metadata_get_functions (GumModuleMetadata * self)
{
  if (self->functions == NULL)
  {
    self->functions = g_array_new (FALSE, FALSE, sizeof (GumFunctionMetadata));
    g_array_set_clear_func (self->functions,
        (GDestroyNotify) gum_function_metadata_free);

    gum_module_enumerate_exports (self->module,
        gum_module_metadata_collect_export, self);
    gum_module_enumerate_sections (self->module,
        gum_module_metadata_collect_section, self);
  }

  return self->functions;
}

static gboolean
gum_module_metadata_collect_export (const GumExportDetails * details,
                                    gpointer user_data)
{
  GumModuleMetadata * self = user_data;
  gchar * name;
  GumFunctionMetadata func;

  if (details->type != GUM_EXPORT_FUNCTION)
    goto skip;

  name = gum_swift_api_resolver_demangle (self->resolver, details->name);
  if (name == NULL)
    goto skip;

  func.name = name;
  func.address = details->address;
  g_array_append_val (self->functions, func);

  gum_module_metadata_maybe_ingest_thunk (self, name,
      gum_strip_code_address (func.address));

skip:
  return TRUE;
}

static gboolean
gum_module_metadata_collect_section (const GumSectionDetails * details,
                                     gpointer user_data)
{
  GumModuleMetadata * module = user_data;
  gsize n, i;
  GumRelativeDirectPtr * types;

  if (strcmp (details->name, GUM_SWIFT_TYPES_SECTION) != 0)
    return TRUE;

  n = details->size / sizeof (gint32);

  types = GSIZE_TO_POINTER (details->address);

  for (i = 0; i != n; i++)
  {
    const GumTypeContextDescriptor * type;
    guint32 descriptor_flags;

    if (types[i] == 0)
      continue;

    type = gum_resolve_relative_indirectable_ptr (&types[i]);
    descriptor_flags = type->context.flags;

    switch (GUM_DESCRIPTOR_FLAGS_KIND (descriptor_flags))
    {
      case GUM_CONTEXT_DESCRIPTOR_CLASS:
        gum_module_metadata_collect_class (module, type);
        break;
      default:
        break;
    }
  }

  return TRUE;
}

static void
gum_module_metadata_collect_class (GumModuleMetadata * self,
                                   const GumTypeContextDescriptor * type)
{
  GumClass klass;
  guint i;

  gum_class_parse (self->resolver, &klass, (const GumClassDescriptor *) type);

  if (klass.num_methods != 0)
  {
    GPtrArray * vtable;

    vtable = g_hash_table_lookup (self->vtables, klass.name);

    for (i = 0; i != klass.num_methods; i++)
    {
      const GumMethodDescriptor * method = &klass.methods[i];
      gconstpointer impl;
      GumFunctionMetadata func;

      impl = gum_resolve_method_implementation (&method->impl, method);
      if (impl == NULL)
        continue;

      func.name = NULL;
      if (vtable != NULL && i < vtable->len)
        func.name = g_strdup (g_ptr_array_index (vtable, i));
      if (func.name == NULL)
        func.name = g_strdup_printf ("%s.vtable[%u]", klass.name, i);

      func.address = GUM_ADDRESS (impl);

      g_array_append_val (self->functions, func);
    }
  }

  for (i = 0; i != klass.num_overrides; i++)
  {
    const GumMethodOverrideDescriptor * od = &klass.overrides[i];
    GumClass parent_class;
    const GumMethodDescriptor * parent_method;
    guint vtable_index;
    gconstpointer impl;
    GPtrArray * parent_vtable;
    GumFunctionMetadata func;

    gum_class_parse (self->resolver, &parent_class,
        gum_resolve_relative_indirectable_ptr (&od->class));
    parent_method = gum_resolve_relative_indirectable_ptr (&od->method);
    vtable_index = parent_method - parent_class.methods;

    impl = gum_resolve_method_implementation (&od->impl, parent_method);
    if (impl == NULL)
      continue;

    parent_vtable = g_hash_table_lookup (self->vtables, parent_class.name);

    func.name = NULL;
    if (parent_vtable != NULL && vtable_index < parent_vtable->len)
    {
      const gchar * name = g_ptr_array_index (parent_vtable, vtable_index);
      if (name != NULL)
      {
        func.name = g_strconcat (
            klass.name,
            name + strlen (parent_class.name),
            NULL);
      }
    }
    if (func.name == NULL)
      func.name = g_strdup_printf ("%s.overrides[%u]", klass.name, i);

    func.address = GUM_ADDRESS (impl);

    g_array_append_val (self->functions, func);

    gum_class_clear (&parent_class);
  }

  gum_class_clear (&klass);
}

#ifdef HAVE_ARM64

static void
gum_module_metadata_maybe_ingest_thunk (GumModuleMetadata * self,
                                        const gchar * name,
                                        GumAddress address)
{
  csh capstone;
  const uint8_t * code;
  size_t size;
  cs_insn * insn;
  gint vtable_index, vtable_offsets[18];
  gboolean end_of_thunk;
  guint i;

  if (!g_str_has_prefix (name, "dispatch thunk of "))
    return;

  gum_cs_arch_register_native ();
  cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &capstone);
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

  code = GSIZE_TO_POINTER (address);
  size = 1024;

  insn = cs_malloc (capstone);

  vtable_index = -1;
  for (i = 0; i != G_N_ELEMENTS (vtable_offsets); i++)
    vtable_offsets[i] = -1;
  end_of_thunk = FALSE;

  while (vtable_index == -1 && !end_of_thunk &&
      cs_disasm_iter (capstone, &code, &size, &address, insn))
  {
    const cs_arm64_op * ops = insn->detail->arm64.operands;

#define GUM_REG_IS_TRACKED(reg) (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X17)
#define GUM_REG_INDEX(reg) (reg - ARM64_REG_X0)

    switch (insn->id)
    {
      case ARM64_INS_LDR:
      {
        arm64_reg dst = ops[0].reg;
        const arm64_op_mem * src = &ops[1].mem;

        if (GUM_REG_IS_TRACKED (dst))
        {
          if (!(src->base == ARM64_REG_X20 && src->disp == 0))
          {
            /*
             * ldr x3, [x16, #0xd0]!
             * ...
             * braa x3, x16
             */
            vtable_offsets[GUM_REG_INDEX (dst)] = src->disp;
          }
        }

        break;
      }
      case ARM64_INS_MOV:
      {
        arm64_reg dst = ops[0].reg;
        const cs_arm64_op * src = &ops[1];

        /*
         * mov x17, #0x3b0
         * add x16, x16, x17
         * ldr x7, [x16]
         * ...
         * braa x7, x16
         */
        if (src->type == ARM64_OP_IMM && GUM_REG_IS_TRACKED (dst))
          vtable_offsets[GUM_REG_INDEX (dst)] = src->imm;

        break;
      }
      case ARM64_INS_ADD:
      {
        arm64_reg dst = ops[0].reg;
        arm64_reg left = ops[1].reg;
        const cs_arm64_op * right = &ops[2];
        gint offset;

        if (left == dst)
        {
          if (right->type == ARM64_OP_REG &&
              GUM_REG_IS_TRACKED (right->reg) &&
              (offset = vtable_offsets[GUM_REG_INDEX (right->reg)]) != -1)
          {
            vtable_index = offset / sizeof (gpointer);
          }

          if (right->type == ARM64_OP_IMM)
          {
            vtable_index = right->imm / sizeof (gpointer);
          }
        }

        break;
      }
      case ARM64_INS_BR:
      case ARM64_INS_BRAA:
      case ARM64_INS_BRAAZ:
      case ARM64_INS_BRAB:
      case ARM64_INS_BRABZ:
      case ARM64_INS_BLR:
      case ARM64_INS_BLRAA:
      case ARM64_INS_BLRAAZ:
      case ARM64_INS_BLRAB:
      case ARM64_INS_BLRABZ:
      {
        arm64_reg target = ops[0].reg;
        gint offset;

        switch (insn->id)
        {
          case ARM64_INS_BR:
          case ARM64_INS_BRAA:
          case ARM64_INS_BRAAZ:
          case ARM64_INS_BRAB:
          case ARM64_INS_BRABZ:
            end_of_thunk = TRUE;
            break;
          default:
            break;
        }

        if (GUM_REG_IS_TRACKED (target) &&
            (offset = vtable_offsets[GUM_REG_INDEX (target)]) != -1)
        {
          vtable_index = offset / sizeof (gpointer);
        }

        break;
      }
      case ARM64_INS_RET:
      case ARM64_INS_RETAA:
      case ARM64_INS_RETAB:
        end_of_thunk = TRUE;
        break;
    }

#undef GUM_REG_IS_TRACKED
#undef GUM_REG_INDEX
  }

  cs_free (insn, 1);

  cs_close (&capstone);

  if (vtable_index != -1)
  {
    const gchar * full_name;
    gchar * class_name;
    GPtrArray * vtable;

    full_name = name + strlen ("dispatch thunk of ");
    class_name = gum_extract_class_name (full_name);
    if (class_name == NULL)
      return;

    vtable = g_hash_table_lookup (self->vtables, class_name);
    if (vtable == NULL)
    {
      vtable = g_ptr_array_new_full (64, g_free);
      g_hash_table_insert (self->vtables, g_steal_pointer (&class_name),
          vtable);
    }

    if (vtable_index >= vtable->len)
      g_ptr_array_set_size (vtable, vtable_index + 1);
    g_free (g_ptr_array_index (vtable, vtable_index));
    g_ptr_array_index (vtable, vtable_index) = g_strdup (full_name);

    g_free (class_name);
  }
}

static gchar *
gum_extract_class_name (const gchar * full_name)
{
  const gchar * ch;

  ch = strstr (full_name, " : ");
  if (ch != NULL)
  {
    ch = gum_find_character_backwards (ch, '.', full_name);
    if (ch == NULL)
      return NULL;
  }
  else
  {
    const gchar * start;

    start = g_str_has_prefix (full_name, "(extension in ")
        ? full_name + strlen ("(extension in ")
        : full_name;

    ch = strchr (start, '(');
    if (ch == NULL)
      return NULL;
  }

  ch = gum_find_character_backwards (ch, '.', full_name);
  if (ch == NULL)
    return NULL;

  return g_strndup (full_name, ch - full_name);
}

static const gchar *
gum_find_character_backwards (const gchar * starting_point,
                              char needle,
                              const gchar * start)
{
  const gchar * ch = starting_point;

  while (ch != start)
  {
    ch--;
    if (*ch == needle)
      return ch;
  }

  return NULL;
}

#else

static void
gum_module_metadata_maybe_ingest_thunk (GumModuleMetadata * self,
                                        const gchar * name,
                                        GumAddress address)
{
}

#endif

static GArray *
gum_module_metadata_get_types (GumModuleMetadata * self)
{
  if (self->types == NULL)
  {
    self->types = g_array_new (FALSE, FALSE, sizeof (GumDescriptorMetadata));

    gum_module_enumerate_sections (self->module,
        gum_module_metadata_collect_type_section, self);
  }

  return self->types;
}

static gboolean
gum_module_metadata_collect_type_section (const GumSectionDetails * details,
                                          gpointer user_data)
{
  GumModuleMetadata * self = user_data;
  gsize n, i;
  const GumRelativeIndirectablePtr * records;

  if (strcmp (details->name, GUM_SWIFT_TYPES_SECTION) != 0 &&
      strcmp (details->name, GUM_SWIFT_TYPES2_SECTION) != 0)
  {
    return TRUE;
  }

  n = details->size / sizeof (gint32);

  records = GSIZE_TO_POINTER (details->address);

  for (i = 0; i != n; i++)
  {
    if (records[i] == 0)
      continue;

    gum_module_metadata_add_descriptor (self, self->types,
        gum_resolve_relative_indirectable_ptr (&records[i]));
  }

  return TRUE;
}

static GArray *
gum_module_metadata_get_protocols (GumModuleMetadata * self)
{
  if (self->protocols == NULL)
  {
    self->protocols =
        g_array_new (FALSE, FALSE, sizeof (GumDescriptorMetadata));

    gum_module_enumerate_sections (self->module,
        gum_module_metadata_collect_protocol_section, self);
  }

  return self->protocols;
}

static gboolean
gum_module_metadata_collect_protocol_section (
    const GumSectionDetails * details,
    gpointer user_data)
{
  GumModuleMetadata * self = user_data;
  gsize n, i;
  const GumRelativeIndirectablePtr * records;

  if (strcmp (details->name, GUM_SWIFT_PROTOCOLS_SECTION) != 0)
    return TRUE;

  n = details->size / sizeof (gint32);

  records = GSIZE_TO_POINTER (details->address);

  for (i = 0; i != n; i++)
  {
    if (records[i] == 0)
      continue;

    gum_module_metadata_add_descriptor (self, self->protocols,
        gum_resolve_protocol_record (&records[i]));
  }

  return TRUE;
}

static void
gum_module_metadata_add_descriptor (GumModuleMetadata * self,
                                    GArray * descriptors,
                                    const GumContextDescriptor * cd)
{
  GumDescriptorMetadata d;

  d.name = gum_swift_api_resolver_get_context_name (self->resolver, cd);
  d.address = GUM_ADDRESS (cd);

  g_array_append_val (descriptors, d);
}

static GArray *
gum_module_metadata_get_conformances (GumModuleMetadata * self)
{
  if (self->conformances == NULL)
  {
    self->conformances =
        g_array_new (FALSE, FALSE, sizeof (GumConformanceMetadata));

    gum_module_enumerate_sections (self->module,
        gum_module_metadata_collect_conformance_section, self);
  }

  return self->conformances;
}

static gboolean
gum_module_metadata_collect_conformance_section (
    const GumSectionDetails * details,
    gpointer user_data)
{
  GumModuleMetadata * self = user_data;
  gsize n, i;
  const GumRelativeIndirectablePtr * records;

  if (strcmp (details->name, GUM_SWIFT_CONFORMANCES_SECTION) != 0)
    return TRUE;

  n = details->size / sizeof (gint32);

  records = GSIZE_TO_POINTER (details->address);

  for (i = 0; i != n; i++)
  {
    const GumProtocolConformanceDescriptor * cd;
    const GumContextDescriptor * protocol;
    GumConformanceMetadata c;

    if (records[i] == 0)
      continue;

    cd = gum_resolve_relative_indirectable_ptr (&records[i]);

    protocol = gum_resolve_relative_indirectable_ptr (&cd->protocol);
    if (protocol == NULL)
      continue;

    c.type_name = gum_module_metadata_resolve_conforming_type_name (self, cd);
    if (c.type_name == NULL)
      continue;
    c.protocol_name =
        gum_swift_api_resolver_get_context_name (self->resolver, protocol);
    c.descriptor = GUM_ADDRESS (cd);

    g_array_append_val (self->conformances, c);
  }

  return TRUE;
}

static const gchar *
gum_module_metadata_resolve_conforming_type_name (
    GumModuleMetadata * self,
    const GumProtocolConformanceDescriptor * cd)
{
  static GumClassGetName class_get_name = NULL;
  gconstpointer target;

  target = gum_resolve_relative_direct_ptr (&cd->type_ref);

  switch (GUM_CONFORMANCE_FLAGS_TYPE_REFERENCE_KIND (cd->flags))
  {
    case GUM_TYPE_REFERENCE_DIRECT_TYPE_DESCRIPTOR:
      return gum_swift_api_resolver_get_context_name (self->resolver, target);
    case GUM_TYPE_REFERENCE_INDIRECT_TYPE_DESCRIPTOR:
      target = gum_strip_code_pointer (*(gpointer *) target);
      if (target == NULL)
        return NULL;
      return gum_swift_api_resolver_get_context_name (self->resolver, target);
    case GUM_TYPE_REFERENCE_DIRECT_OBJC_CLASS_NAME:
      return target;
    case GUM_TYPE_REFERENCE_INDIRECT_OBJC_CLASS:
    {
      gpointer klass;

      if (class_get_name == NULL)
      {
        class_get_name = GUM_POINTER_TO_FUNCPTR (GumClassGetName,
            gum_module_find_global_export_by_name ("class_getName"));
      }

      klass = gum_strip_code_pointer (*(gpointer *) target);
      if (klass == NULL)
        return NULL;

      return class_get_name (klass);
    }
    default:
      g_assert_not_reached ();
  }

  return NULL;
}

static const gchar *
gum_swift_api_resolver_get_context_name (GumSwiftApiResolver * self,
                                         const GumContextDescriptor * cd)
{
  gchar * name;

  name = g_hash_table_lookup (self->context_names, cd);
  if (name == NULL)
  {
    name = gum_compute_context_descriptor_name (self, cd);
    g_hash_table_insert (self->context_names, (gpointer) cd, name);
  }

  return name;
}

static gboolean
gum_swift_api_resolver_ensure_demangler (GumSwiftApiResolver * self)
{
  GumModule * swift_core, * allocator;

  if (self->swift_demangle != NULL)
    return TRUE;

  swift_core = gum_process_find_module_by_name (GUM_SWIFT_CORE_MODULE);
  if (swift_core == NULL)
    return FALSE;

#if defined (HAVE_WINDOWS)
  allocator = gum_process_find_module_by_name ("ucrtbase.dll");
#elif defined (HAVE_DARWIN)
  allocator = gum_process_find_module_by_name (
      "/usr/lib/system/libsystem_malloc.dylib");
#else
  allocator = g_object_ref (gum_process_get_libc_module ());
#endif
  self->libc_free = GUM_POINTER_TO_FUNCPTR (GumLibcFreeFunc,
      gum_module_find_export_by_name (allocator, "free"));
  g_object_unref (allocator);

  self->swift_demangle = GUM_POINTER_TO_FUNCPTR (GumSwiftDemangle,
      gum_module_find_export_by_name (swift_core, "swift_demangle"));

  g_object_unref (swift_core);

  return self->swift_demangle != NULL;
}

static gchar *
gum_swift_api_resolver_demangle (GumSwiftApiResolver * self,
                                 const gchar * name)
{
  gchar * raw, * result;

  raw = self->swift_demangle (name, strlen (name), NULL, NULL, 0);
  if (raw == NULL)
    return NULL;

  result = g_strdup (raw);
  self->libc_free (raw);

  return result;
}

static void
gum_function_metadata_free (GumFunctionMetadata * function)
{
  g_free (function->name);
}

static void
gum_class_parse (GumSwiftApiResolver * resolver,
                 GumClass * klass,
                 const GumClassDescriptor * cd)
{
  const GumTypeContextDescriptor * type;
  gconstpointer trailer;
  guint16 type_flags;

  memset (klass, 0, sizeof (GumClass));

  type = &cd->type_context;

  klass->name = gum_compute_context_descriptor_name (resolver, &type->context);

  trailer = cd + 1;

  gum_skip_generic_type_trailers (&trailer, type);

  gum_skip_resilient_superclass_trailer (&trailer, type);

  gum_skip_metadata_initialization_trailers (&trailer, type);

  type_flags = GUM_DESCRIPTOR_FLAGS_KIND_FLAGS (type->context.flags);

  if (GUM_TYPE_FLAGS_CLASS_HAS_VTABLE (type_flags))
  {
    const GumVTableDescriptorHeader * vth;
    const GumMethodDescriptor * methods;

    vth = GUM_ALIGN (trailer, GumVTableDescriptorHeader);
    methods = GUM_ALIGN ((const GumMethodDescriptor *) (vth + 1),
        GumMethodDescriptor);

    klass->methods = methods;
    klass->num_methods = vth->vtable_size;

    trailer = methods + vth->vtable_size;
  }

  if (GUM_TYPE_FLAGS_CLASS_HAS_OVERRIDE_TABLE (type_flags))
  {
    const GumOverrideTableHeader * oth;
    const GumMethodOverrideDescriptor * overrides;

    oth = GUM_ALIGN (trailer, GumOverrideTableHeader);
    overrides = GUM_ALIGN ((const GumMethodOverrideDescriptor *) (oth + 1),
        GumMethodOverrideDescriptor);

    klass->overrides = overrides;
    klass->num_overrides = oth->num_entries;

    trailer = overrides + oth->num_entries;
  }
}

static void
gum_class_clear (GumClass * klass)
{
  g_free (klass->name);
}

static gconstpointer
gum_resolve_method_implementation (const GumRelativeDirectPtr * impl,
                                   const GumMethodDescriptor * method)
{
  gconstpointer address;

  address = gum_resolve_relative_direct_ptr (impl);
  if (address == NULL)
    return NULL;

  if (GUM_METHOD_DESCRIPTOR_IS_ASYNC (method))
    address = gum_resolve_relative_direct_ptr (address);

  return address;
}

static gchar *
gum_compute_context_descriptor_name (GumSwiftApiResolver * resolver,
                                     const GumContextDescriptor * cd)
{
  GString * name;
  const GumContextDescriptor * cur;
  gboolean reached_toplevel;

  name = g_string_sized_new (16);

  for (cur = cd, reached_toplevel = FALSE;
      cur != NULL && !reached_toplevel;
      cur = gum_resolve_relative_indirectable_ptr (&cur->parent))
  {
    GumContextDescriptorKind kind = GUM_DESCRIPTOR_FLAGS_KIND (cur->flags);

    switch (kind)
    {
      case GUM_CONTEXT_DESCRIPTOR_MODULE:
      {
        const GumModuleContextDescriptor * m =
            (const GumModuleContextDescriptor *) cur;
        if (name->len != 0)
          g_string_prepend_c (name, '.');
        g_string_prepend (name, gum_resolve_relative_direct_ptr (&m->name));
        break;
      }
      case GUM_CONTEXT_DESCRIPTOR_EXTENSION:
      {
        const GumExtensionContextDescriptor * e =
            (const GumExtensionContextDescriptor *) cur;
        GString * part;
        gchar * parent;

        part = g_string_sized_new (64);
        g_string_append (part, "(extension in ");

        parent = gum_compute_context_descriptor_name (resolver,
            gum_resolve_relative_indirectable_ptr (&cur->parent));
        g_string_append (part, parent);
        g_free (parent);

        g_string_append (part, "):");

        gum_append_demangled_context_name (resolver, part,
            gum_resolve_relative_direct_ptr (&e->extended_context));

        if (name->len != 0)
          g_string_append_c (part, '.');

        g_string_prepend (name, part->str);

        g_string_free (part, TRUE);

        reached_toplevel = TRUE;

        break;
      }
      case GUM_CONTEXT_DESCRIPTOR_ANONYMOUS:
        break;
      case GUM_CONTEXT_DESCRIPTOR_PROTOCOL:
      {
        const GumProtocolDescriptor * p = (const GumProtocolDescriptor *) cur;
        if (name->len != 0)
          g_string_prepend_c (name, '.');
        g_string_prepend (name, gum_resolve_relative_direct_ptr (&p->name));
        break;
      }
      default:
        if (kind >= GUM_CONTEXT_DESCRIPTOR_TYPE_FIRST &&
            kind <= GUM_CONTEXT_DESCRIPTOR_TYPE_LAST)
        {
          const GumTypeContextDescriptor * t =
              (const GumTypeContextDescriptor *) cur;
          if (name->len != 0)
            g_string_prepend_c (name, '.');
          g_string_prepend (name, gum_resolve_relative_direct_ptr (&t->name));
          break;
        }

        break;
    }
  }

  return g_string_free (name, FALSE);
}

static void
gum_append_demangled_context_name (GumSwiftApiResolver * resolver,
                                   GString * result,
                                   const gchar * mangled_name)
{
  switch (mangled_name[0])
  {
    case '\x01':
    {
      const GumContextDescriptor * cd;
      gchar * name;

      cd = gum_resolve_relative_direct_ptr (
          (const GumRelativeDirectPtr *) (mangled_name + 1));
      name = gum_compute_context_descriptor_name (resolver, cd);
      g_string_append (result, name);
      g_free (name);

      break;
    }
    case '\x02':
    {
      const GumContextDescriptor * cd;
      gchar * name;

      cd = gum_resolve_relative_indirect_ptr (
          (const GumRelativeIndirectPtr *) (mangled_name + 1));
      name = gum_compute_context_descriptor_name (resolver, cd);
      g_string_append (result, name);
      g_free (name);

      break;
    }
    default:
    {
      GString * buf;
      gchar * name;

      buf = g_string_sized_new (32);
      g_string_append (buf, "$s");
      g_string_append (buf, mangled_name);

      name = gum_swift_api_resolver_demangle (resolver, buf->str);
      if (name != NULL)
      {
        g_string_append (result, name);
        g_free (name);
      }
      else
      {
        g_string_append (result, "<unsupported mangled name>");
      }

      g_string_free (buf, TRUE);

      break;
    }
  }
}

static void
gum_skip_generic_type_trailers (gconstpointer * trailer_ptr,
                                const GumTypeContextDescriptor * t)
{
  gconstpointer trailer = *trailer_ptr;

  if (GUM_DESCRIPTOR_FLAGS_IS_GENERIC (t->context.flags))
  {
    const GumTypeGenericContextDescriptorHeader * th;

    th = GUM_ALIGN (trailer, GumTypeGenericContextDescriptorHeader);
    trailer = th + 1;

    gum_skip_generic_parts (&trailer, &th->base);
  }

  *trailer_ptr = trailer;
}

static void
gum_skip_generic_parts (gconstpointer * trailer_ptr,
                        const GumGenericContextDescriptorHeader * h)
{
  gconstpointer trailer = *trailer_ptr;

  if (h->num_params != 0)
  {
    const GumGenericParamDescriptor * params = trailer;
    trailer = params + h->num_params;
  }

  {
    const GumGenericRequirementDescriptor * reqs =
        GUM_ALIGN (trailer, GumGenericRequirementDescriptor);
    trailer = reqs + h->num_requirements;
  }

  if (GUM_GENERIC_DESCRIPTOR_FLAGS_HAS_TYPE_PACKS (h->flags))
  {
    const GumGenericPackShapeHeader * sh =
        GUM_ALIGN (trailer, GumGenericPackShapeHeader);
    trailer = sh + 1;

    if (sh->num_packs != 0)
    {
      const GumGenericPackShapeDescriptor * d =
          GUM_ALIGN (trailer, GumGenericPackShapeDescriptor);
      trailer = d + sh->num_packs;
    }
  }

  *trailer_ptr = trailer;
}

static void
gum_skip_resilient_superclass_trailer (gconstpointer * trailer_ptr,
                                       const GumTypeContextDescriptor * t)
{
  gconstpointer trailer = *trailer_ptr;

  if (GUM_TYPE_FLAGS_CLASS_HAS_RESILIENT_SUPERCLASS (
        GUM_DESCRIPTOR_FLAGS_KIND_FLAGS (t->context.flags)))
  {
    const GumResilientSuperclass * rs =
        GUM_ALIGN (trailer, GumResilientSuperclass);
    trailer = rs + 1;
  }

  *trailer_ptr = trailer;
}

static void
gum_skip_metadata_initialization_trailers (gconstpointer * trailer_ptr,
                                           const GumTypeContextDescriptor * t)
{
  gconstpointer trailer = *trailer_ptr;

  switch (GUM_TYPE_FLAGS_METADATA_INITIALIZATION_MASK (
        GUM_DESCRIPTOR_FLAGS_KIND_FLAGS (t->context.flags)))
  {
    case GUM_METADATA_INITIALIZATION_NONE:
      break;
    case GUM_METADATA_INITIALIZATION_SINGLETON:
    {
      const GumSingletonMetadataInitialization * smi =
          GUM_ALIGN (trailer, GumSingletonMetadataInitialization);
      trailer = smi + 1;
      break;
    }
    case GUM_METADATA_INITIALIZATION_FOREIGN:
    {
      const GumForeignMetadataInitialization * fmi =
          GUM_ALIGN (trailer, GumForeignMetadataInitialization);
      trailer = fmi + 1;
      break;
    }
  }

  *trailer_ptr = trailer;
}

static gconstpointer
gum_resolve_relative_direct_ptr (const GumRelativeDirectPtr * delta)
{
  GumRelativeDirectPtr val = *delta;

  if (val == 0)
    return NULL;

  return (const guint8 *) delta + val;
}

static gconstpointer
gum_resolve_relative_indirect_ptr (const GumRelativeIndirectPtr * delta)
{
  GumRelativeIndirectablePtr val = *delta;
  gconstpointer * target;

  target = (gconstpointer *) ((const guint8 *) delta + val);

  return gum_strip_code_pointer ((gpointer) *target);
}

static gconstpointer
gum_resolve_relative_indirectable_ptr (const GumRelativeIndirectablePtr * delta)
{
  GumRelativeIndirectablePtr val = *delta;
  gconstpointer * target;

  if ((val & 1) == 0)
    return gum_resolve_relative_direct_ptr (delta);

  target = (gconstpointer *) ((const guint8 *) delta + (val & ~1));

  return gum_strip_code_pointer ((gpointer) *target);
}

static gconstpointer
gum_resolve_protocol_record (const GumRelativeIndirectablePtr * record)
{
  GumRelativeIndirectablePtr val = *record & ~GUM_PROTOCOL_RECORD_RESERVED_BIT;
  gconstpointer * target;

  if ((val & 1) == 0)
    return (const guint8 *) record + val;

  target = (gconstpointer *) ((const guint8 *) record + (val & ~1));

  return gum_strip_code_pointer ((gpointer) *target);
}
