/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumdarwinmapper.h"

#include "gumdarwin.h"
#include "gumdarwinmodule.h"
#include "helpers/fixupchainprocessor.h"

#include <dlfcn.h>
#include <string.h>
#ifdef HAVE_I386
# include <gum/arch-x86/gumx86writer.h>
#else
# include <gum/arch-arm/gumthumbwriter.h>
# include <gum/arch-arm64/gumarm64writer.h>
#endif
#ifdef HAVE_PTRAUTH
# include <ptrauth.h>
#endif

#define GUM_MAPPER_HEADER_BASE_SIZE         64
#define GUM_MAPPER_CODE_BASE_SIZE           80
#define GUM_MAPPER_DEPENDENCY_SIZE          32
#define GUM_MAPPER_CHAINED_FIXUP_CALL_SIZE  64
#define GUM_MAPPER_RESOLVER_SIZE            40
#define GUM_MAPPER_INIT_SIZE               128
#define GUM_MAPPER_TERM_SIZE                64

#define GUM_CHECK_MACH_RESULT(n1, cmp, n2, op) \
    if (!(n1 cmp n2)) \
    { \
      failed_operation = op; \
      goto mach_failure; \
    }

typedef struct _GumDarwinMapping GumDarwinMapping;
typedef struct _GumDarwinSymbolValue GumDarwinSymbolValue;

typedef struct _GumAccumulateFootprintContext GumAccumulateFootprintContext;

typedef struct _GumMapContext GumMapContext;

struct _GumDarwinMapper
{
  GObject object;

  gchar * name;
  GumDarwinModule * module;
  GumDarwinModuleImage * image;
  GumDarwinModuleResolver * resolver;
  GumDarwinMapper * parent;

  gboolean mapped;
  GPtrArray * dependencies;
  GPtrArray * apple_parameters;

  gsize vm_size;
  gpointer runtime;
  GumAddress runtime_address;
  GumAddress empty_strv_address;
  GumAddress apple_strv_address;
  gsize runtime_vm_size;
  gsize runtime_file_size;
  gsize runtime_header_size;
  gsize constructor_offset;
  gsize destructor_offset;
  guint chained_fixups_count;

  GArray * threaded_binds;

  GSList * children;
  GHashTable * mappings;
};

enum
{
  PROP_0,
  PROP_NAME,
  PROP_MODULE,
  PROP_RESOLVER,
  PROP_PARENT
};

struct _GumDarwinMapping
{
  gint ref_count;
  GumDarwinModule * module;
  GumDarwinMapper * mapper;
};

struct _GumDarwinSymbolValue
{
  GumAddress address;
  GumAddress resolver;
};

struct _GumAccumulateFootprintContext
{
  GumDarwinMapper * mapper;
  gsize total;
  guint chained_fixups_count;
};

struct _GumMapContext
{
  GumDarwinMapper * mapper;
  gboolean success;
  GError ** error;
};

static void gum_darwin_mapper_constructed (GObject * object);
static void gum_darwin_mapper_finalize (GObject * object);
static void gum_darwin_mapper_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_darwin_mapper_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);

static GumDarwinMapper * gum_darwin_mapper_new_from_file_with_parent (
    GumDarwinMapper * parent, const gchar * path,
    GumDarwinModuleResolver * resolver, GError ** error);
static gsize gum_darwin_mapper_get_footprint_budget (GumDarwinMapper * self);
static void gum_darwin_mapper_discard_footprint_budget (GumDarwinMapper * self);
static void gum_darwin_mapper_init_footprint_budget (GumDarwinMapper * self);
static GumAddress gum_darwin_mapper_make_code_address (GumDarwinMapper * self,
    GumAddress value);

static void gum_darwin_mapper_alloc_and_emit_runtime (GumDarwinMapper * self,
    GumAddress base_address, gsize size);
static void gum_emit_runtime (GumDarwinMapper * self, gpointer output_buffer,
    GumAddress pc, gsize * size);
static gboolean gum_accumulate_chained_fixups_size (
    const GumDarwinChainedFixupsDetails * details, gpointer user_data);
static gboolean gum_accumulate_bind_footprint_size (
    const GumDarwinBindDetails * details, gpointer user_data);
static gboolean gum_accumulate_init_pointers_footprint_size (
    const GumDarwinInitPointersDetails * details, gpointer user_data);
static gboolean gum_accumulate_init_offsets_footprint_size (
    const GumDarwinInitOffsetsDetails * details, gpointer user_data);
static gboolean gum_accumulate_term_footprint_size (
    const GumDarwinTermPointersDetails * details, gpointer user_data);

static gpointer gum_darwin_mapper_data_from_offset (GumDarwinMapper * self,
    guint64 offset, guint size);
static GumDarwinMapping * gum_darwin_mapper_get_dependency_by_ordinal (
    GumDarwinMapper * self, gint ordinal, GError ** error);
static GumDarwinMapping * gum_darwin_mapper_get_dependency_by_name (
    GumDarwinMapper * self, const gchar * name, GError ** error);
static gboolean gum_darwin_mapper_resolve_symbol (GumDarwinMapper * self,
    GumDarwinModule * module, const gchar * symbol,
    GumDarwinSymbolValue * value);
static GumDarwinMapping * gum_darwin_mapper_add_existing_mapping (
    GumDarwinMapper * self, GumDarwinModule * module);
static GumDarwinMapping * gum_darwin_mapper_add_pending_mapping (
    GumDarwinMapper * self, const gchar * name, GumDarwinMapper * mapper);
static GumDarwinMapping * gum_darwin_mapper_add_alias_mapping (
    GumDarwinMapper * self, const gchar * name, const GumDarwinMapping * to);
static gboolean gum_darwin_mapper_rebase (
    const GumDarwinRebaseDetails * details, gpointer user_data);
static gboolean gum_darwin_mapper_bind (const GumDarwinBindDetails * details,
    gpointer user_data);
static gboolean gum_darwin_mapper_bind_pointer (GumDarwinMapper * self,
    const GumDarwinBindDetails * bind, GError ** error);
static gboolean gum_darwin_mapper_bind_table (GumDarwinMapper * self,
    const GumDarwinBindDetails * bind, GError ** error);
static gboolean gum_darwin_mapper_bind_items (GumDarwinMapper * self,
    const GumDarwinBindDetails * bind, GError ** error);

static void gum_darwin_mapping_free (GumDarwinMapping * self);

G_DEFINE_TYPE (GumDarwinMapper, gum_darwin_mapper, G_TYPE_OBJECT)

/* Compiled from helpers/fixupchainprocessor.c */
const guint32 gum_fixup_chain_processor_code[] = {
  0xd10283ffU, 0xa9046ffcU, 0xa90567faU, 0xa9065ff8U, 0xa90757f6U, 0xa9084ff4U,
  0xa9097bfdU, 0x910243fdU, 0xaa0303f3U, 0xaa0203f6U, 0xaa0103f5U, 0xaa0003f7U,
  0xf9400068U, 0xd63f0100U, 0xf9001fffU, 0xf90017f3U, 0xf9400668U, 0x52800033U,
  0x9100e3e1U, 0xb9000fe0U, 0x52a00022U, 0x52800023U, 0xd63f0100U, 0x52800019U,
  0xd2800014U, 0xf9401ff8U, 0x910082baU, 0x529ffd1bU, 0x72affffbU, 0x5281103cU,
  0xb94012a8U, 0x6b08033fU, 0x540002a0U, 0xb9400348U, 0x0b1b0109U, 0x71002d3fU,
  0x1ac92269U, 0x0a1c0129U, 0x7a409924U, 0x7a4c0904U, 0x54000121U, 0xb9400b48U,
  0x8b080340U, 0xf94017e8U, 0xf9400d08U, 0x52800121U, 0xd63f0100U, 0xf8347b00U,
  0x91000694U, 0xb9400748U, 0x8b08035aU, 0x11000739U, 0x17ffffeaU, 0x8b140f1aU,
  0x2941eee8U, 0x8b0802f9U, 0xb94016e8U, 0x71000d1fU, 0x54000c80U, 0x7100091fU,
  0x54000e00U, 0x7100051fU, 0x54000181U, 0xb9400ae8U, 0x8b0802f3U, 0xaa1a03f4U,
  0xb400011bU, 0xb8404668U, 0x12001d01U, 0x53097d03U, 0x940000a4U, 0xf8008680U,
  0xd100077bU, 0xb5ffff5bU, 0xd2800009U, 0xb94006e8U, 0x8b0802e8U, 0xcb1602b9U,
  0xf9000be8U, 0xb840450aU, 0xa901abe8U, 0x529ffff4U, 0xf94013e8U, 0xeb08013fU,
  0x54000780U, 0xf9001be9U, 0xf9400fe8U, 0xb8697908U, 0x340006a8U, 0xd2800017U,
  0xf9400be9U, 0x8b080133U, 0x79402a7cU, 0x91005a7bU, 0xeb1c02ffU, 0x540005c0U,
  0x78777b68U, 0xeb14011fU, 0x54000520U, 0xf9400669U, 0x8b0902a9U, 0x79400a6aU,
  0x9b0a26e9U, 0x8b080136U, 0xf94002d8U, 0xd37eff10U, 0xd360bf02U, 0xd370c303U,
  0xd371cb01U, 0xf1000e1fU, 0x9a9f9210U, 0x100009b1U, 0xd503201fU, 0xb8b07a30U,
  0x8b100230U, 0xd61f0200U, 0xd36bff08U, 0x9240ab09U, 0x936aab0aU, 0x9255314aU,
  0xb3481d09U, 0xaa0a0128U, 0x8b080320U, 0x1400000cU, 0x8b3842a0U, 0x14000003U,
  0x92403f08U, 0xf8687b40U, 0xaa1603e4U, 0x94000050U, 0x14000005U, 0x92403f08U,
  0xf8687b48U, 0xd360cb09U, 0x8b090100U, 0xf90002c0U, 0xd373f708U, 0x8b080ed6U,
  0xb5fffbc8U, 0x910006f7U, 0x17ffffd2U, 0xf9401be9U, 0x91000529U, 0x17ffffc3U,
  0xf94017e8U, 0xf9400908U, 0xf9401fe1U, 0xb9400fe0U, 0x52a00022U, 0xd63f0100U,
  0xa9497bfdU, 0xa9484ff4U, 0xa94757f6U, 0xa9465ff8U, 0xa94567faU, 0xa9446ffcU,
  0x910283ffU, 0xd65f03c0U, 0xb9400ae8U, 0x8b170108U, 0x91002113U, 0xaa1a03f4U,
  0xb4fff51bU, 0xb85fc263U, 0x785f8261U, 0x94000045U, 0xf8410668U, 0x8b080008U,
  0xf8008688U, 0xd100077bU, 0xb5ffff3bU, 0x17ffff9fU, 0xb9400ae8U, 0x8b170108U,
  0x91001113U, 0xaa1a03f4U, 0xb4fff35bU, 0xb85fc268U, 0x12001d01U, 0x53097d03U,
  0x94000036U, 0xb9800268U, 0x8b080008U, 0xf8008688U, 0x91002273U, 0xd100077bU,
  0xb5fffefbU, 0x17ffff8fU, 0xfffffee0U, 0xffffff1cU, 0xffffff00U, 0xffffff08U,
  0x71000428U, 0x540001cbU, 0xa9bf7bfdU, 0x910003fdU, 0x8b234049U, 0xaa0903eaU,
  0x3840154bU, 0x71017d7fU, 0x9a890141U, 0xf9401089U, 0xf868d800U, 0xd63f0120U,
  0xdac143e0U, 0xa8c17bfdU, 0xd65f03c0U, 0xd2800000U, 0xd65f03c0U, 0xb3503c44U,
  0x7100007fU, 0x9a840048U, 0x71000c3fU, 0x54000208U, 0xaa0103f0U, 0xf1000e1fU,
  0x9a9f9210U, 0x100001b1U, 0xd503201fU, 0xb8b07a30U, 0x8b100230U, 0xd61f0200U,
  0xdac10100U, 0xd65f03c0U, 0xdac10500U, 0xd65f03c0U, 0xdac10900U, 0xd65f03c0U,
  0xdac10d00U, 0xd65f03c0U, 0xffffffe0U, 0xffffffe8U, 0xfffffff0U, 0xfffffff8U,
  0xaa1803e0U, 0xaa1903e2U, 0xf94017e4U, 0x17ffffd3U
};

static void
gum_darwin_mapper_class_init (GumDarwinMapperClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_darwin_mapper_constructed;
  object_class->finalize = gum_darwin_mapper_finalize;
  object_class->get_property = gum_darwin_mapper_get_property;
  object_class->set_property = gum_darwin_mapper_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_MODULE,
      g_param_spec_object ("module", "Module", "Module",
      GUM_TYPE_DARWIN_MODULE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_RESOLVER,
      g_param_spec_object ("resolver", "Resolver", "Module resolver",
      GUM_DARWIN_TYPE_MODULE_RESOLVER, G_PARAM_READWRITE |
      G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PARENT,
      g_param_spec_object ("parent", "Parent", "Parent mapper",
      GUM_DARWIN_TYPE_MAPPER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_mapper_init (GumDarwinMapper * self)
{
  self->mapped = FALSE;
  self->apple_parameters = g_ptr_array_new_with_free_func (g_free);
}

static void
gum_darwin_mapper_constructed (GObject * object)
{
  GumDarwinMapper * self = GUM_DARWIN_MAPPER (object);
  GumDarwinMapper * parent = self->parent;

  g_assert (self->name != NULL);
  g_assert (self->module != NULL);
  g_assert (self->resolver != NULL);

  if (parent != NULL)
  {
    parent->children = g_slist_prepend (parent->children, self);

    gum_darwin_mapper_add_pending_mapping (parent, self->name, self);
  }
}

static void
gum_darwin_mapper_finalize (GObject * object)
{
  GumDarwinMapper * self = GUM_DARWIN_MAPPER (object);

  g_clear_pointer (&self->mappings, g_hash_table_unref);
  g_slist_free_full (self->children, g_object_unref);

  g_clear_pointer (&self->threaded_binds, g_array_unref);

  g_free (self->runtime);

  g_ptr_array_unref (self->apple_parameters);
  g_ptr_array_unref (self->dependencies);

  g_object_unref (self->resolver);
  g_object_unref (self->module);
  g_free (self->name);

  G_OBJECT_CLASS (gum_darwin_mapper_parent_class)->finalize (object);
}

static void
gum_darwin_mapper_get_property (GObject * object,
                                guint property_id,
                                GValue * value,
                                GParamSpec * pspec)
{
  GumDarwinMapper * self = GUM_DARWIN_MAPPER (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_MODULE:
      g_value_set_object (value, self->module);
      break;
    case PROP_RESOLVER:
      g_value_set_object (value, self->resolver);
      break;
    case PROP_PARENT:
      g_value_set_object (value, self->parent);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_darwin_mapper_set_property (GObject * object,
                                guint property_id,
                                const GValue * value,
                                GParamSpec * pspec)
{
  GumDarwinMapper * self = GUM_DARWIN_MAPPER (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_free (self->name);
      self->name = g_value_dup_string (value);
      break;
    case PROP_MODULE:
      g_clear_object (&self->module);
      self->module = g_value_dup_object (value);
      self->image = (self->module != NULL) ? self->module->image : NULL;
      break;
    case PROP_RESOLVER:
      g_clear_object (&self->resolver);
      self->resolver = g_value_dup_object (value);
      break;
    case PROP_PARENT:
      self->parent = g_value_get_object (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinMapper *
gum_darwin_mapper_new_from_file (const gchar * path,
                                 GumDarwinModuleResolver * resolver,
                                 GError ** error)
{
  return gum_darwin_mapper_new_from_file_with_parent (NULL, path, resolver,
      error);
}

GumDarwinMapper *
gum_darwin_mapper_new_take_blob (const gchar * name,
                                 GBytes * blob,
                                 GumDarwinModuleResolver * resolver,
                                 GError ** error)
{
  GumDarwinModule * module;
  GumDarwinMapper * mapper;

  module = gum_darwin_module_new_from_blob (blob, resolver->cpu_type,
      resolver->ptrauth_support, GUM_DARWIN_MODULE_FLAGS_NONE, error);
  if (module == NULL)
    goto malformed_blob;

  if (module->name == NULL)
    g_object_set (module, "name", name, NULL);

  mapper = g_object_new (GUM_DARWIN_TYPE_MAPPER,
      "name", name,
      "module", module,
      "resolver", resolver,
      NULL);
  if (!gum_darwin_mapper_load (mapper, error))
  {
    g_object_unref (mapper);
    mapper = NULL;
  }

  g_object_unref (module);
  g_bytes_unref (blob);

  return mapper;

malformed_blob:
  {
    g_bytes_unref (blob);

    return NULL;
  }
}

static GumDarwinMapper *
gum_darwin_mapper_new_from_file_with_parent (GumDarwinMapper * parent,
                                             const gchar * path,
                                             GumDarwinModuleResolver * resolver,
                                             GError ** error)
{
  GumDarwinMapper * mapper = NULL;
  GumDarwinModule * module;

  module = gum_darwin_module_new_from_file (path, resolver->cpu_type,
      resolver->ptrauth_support, GUM_DARWIN_MODULE_FLAGS_NONE,
      error);
  if (module == NULL)
    goto beach;

  if (module->name == NULL)
    g_object_set (module, "name", path, NULL);

  mapper = g_object_new (GUM_DARWIN_TYPE_MAPPER,
      "name", path,
      "module", module,
      "resolver", resolver,
      "parent", parent,
      NULL);
  if (!gum_darwin_mapper_load (mapper, error))
  {
    g_object_unref (mapper);
    mapper = NULL;
  }

beach:
  g_clear_object (&module);

  return mapper;
}

gboolean
gum_darwin_mapper_load (GumDarwinMapper * self,
                        GError ** error)
{
  GumDarwinModule * module = self->module;
  GPtrArray * dependencies;
  guint i;

  if (self->dependencies != NULL)
    return TRUE;

  self->dependencies = g_ptr_array_sized_new (5);

  if (self->parent == NULL)
  {
    self->mappings = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
        (GDestroyNotify) gum_darwin_mapping_free);
    gum_darwin_mapper_add_pending_mapping (self, module->name, self);
  }

  dependencies = module->dependencies;
  for (i = 0; i != dependencies->len; i++)
  {
    GumDarwinMapping * dependency;

    dependency = gum_darwin_mapper_get_dependency_by_name (self,
        g_ptr_array_index (dependencies, i), error);
    if (dependency == NULL)
      return FALSE;
    g_ptr_array_add (self->dependencies, dependency);
  }

  return TRUE;
}

void
gum_darwin_mapper_add_apple_parameter (GumDarwinMapper * self,
                                       const gchar * key,
                                       const gchar * value)
{
  g_ptr_array_add (self->apple_parameters, g_strconcat (key, "=", value, NULL));

  gum_darwin_mapper_discard_footprint_budget (self);
}

gsize
gum_darwin_mapper_size (GumDarwinMapper * self)
{
  gsize total;
  GSList * cur;

  total = 0;

  for (cur = self->children; cur != NULL; cur = cur->next)
  {
    GumDarwinMapper * child = cur->data;

    total += gum_darwin_mapper_get_footprint_budget (child);
  }

  total += gum_darwin_mapper_get_footprint_budget (self);

  return total;
}

static gsize
gum_darwin_mapper_get_footprint_budget (GumDarwinMapper * self)
{
  if (self->vm_size == 0)
    gum_darwin_mapper_init_footprint_budget (self);

  return self->vm_size;
}

static void
gum_darwin_mapper_discard_footprint_budget (GumDarwinMapper * self)
{
  self->vm_size = 0;
}

static void
gum_darwin_mapper_init_footprint_budget (GumDarwinMapper * self)
{
  GumDarwinModule * module = self->module;
  GumDarwinModuleImage * image = self->image;
  guint page_size = self->resolver->page_size;
  gsize segments_size;
  guint i;
  GumAccumulateFootprintContext runtime;
  gsize header_size;
  GPtrArray * params;

  if (image->shared_segments->len == 0)
  {
    segments_size = 0;
    for (i = 0; i != module->segments->len; i++)
    {
      GumDarwinSegment * segment =
          &g_array_index (module->segments, GumDarwinSegment, i);

      segments_size += segment->vm_size;
      if (segment->vm_size % page_size != 0)
        segments_size += page_size - (segment->vm_size % page_size);
    }
  }
  else
  {
    segments_size = image->size;
  }

  runtime.mapper = self;
  runtime.total = 0;
  runtime.chained_fixups_count = 0;

  header_size = GUM_MAPPER_HEADER_BASE_SIZE;
  params = self->apple_parameters;
  header_size += params->len * self->module->pointer_size;
  for (i = 0; i != params->len; i++)
  {
    const gchar * param = g_ptr_array_index (params, i);
    header_size += strlen (param) + 1;
  }
  header_size = GUM_ALIGN_SIZE (header_size, 16);
  runtime.total += header_size;

  gum_darwin_module_enumerate_chained_fixups (module,
      gum_accumulate_chained_fixups_size, &runtime);
  gum_darwin_module_enumerate_binds (module,
      gum_accumulate_bind_footprint_size, &runtime);
  gum_darwin_module_enumerate_lazy_binds (module,
      gum_accumulate_bind_footprint_size, &runtime);
  gum_darwin_module_enumerate_init_pointers (module,
      gum_accumulate_init_pointers_footprint_size, &runtime);
  gum_darwin_module_enumerate_init_offsets (module,
      gum_accumulate_init_offsets_footprint_size, &runtime);
  gum_darwin_module_enumerate_term_pointers (module,
      gum_accumulate_term_footprint_size, &runtime);

  runtime.total += g_slist_length (self->children) * GUM_MAPPER_DEPENDENCY_SIZE;
  runtime.total += GUM_MAPPER_CODE_BASE_SIZE;

  self->runtime_vm_size = runtime.total;
  if (runtime.total % page_size != 0)
    self->runtime_vm_size += page_size - (runtime.total % page_size);
  self->runtime_file_size = runtime.total;
  self->runtime_header_size = header_size;

  self->vm_size = segments_size + self->runtime_vm_size;

  self->chained_fixups_count = runtime.chained_fixups_count;
}

gboolean
gum_darwin_mapper_map (GumDarwinMapper * self,
                       GumAddress base_address,
                       GError ** error)
{
  GumMapContext ctx;
  gsize total_vm_size;
  GumAddress macho_base_address;
  GSList * cur;
  GumDarwinModule * module = self->module;
  mach_port_t task = self->resolver->task;
  guint i;
  mach_vm_address_t mapped_address;
  vm_prot_t cur_protection, max_protection;
  GArray * shared_segments;
  const gchar * failed_operation;
  kern_return_t kr;
  static gboolean use_memory_mapping = TRUE;

  g_assert (!self->mapped);

  ctx.mapper = self;
  ctx.success = TRUE;
  ctx.error = error;

  total_vm_size = gum_darwin_mapper_size (self);

  self->runtime_address = base_address;
  macho_base_address = base_address + self->runtime_vm_size;

  for (cur = self->children; cur != NULL; cur = cur->next)
  {
    GumDarwinMapper * child = cur->data;

    ctx.success = gum_darwin_mapper_map (child, macho_base_address, error);
    if (!ctx.success)
      goto beach;
    macho_base_address += child->vm_size;
  }

  g_object_set (module, "base-address", macho_base_address, NULL);

  gum_darwin_mapper_alloc_and_emit_runtime (self, base_address, total_vm_size);

  gum_darwin_module_enumerate_rebases (module, gum_darwin_mapper_rebase, &ctx);
  if (!ctx.success)
    goto beach;

  gum_darwin_module_enumerate_binds (module, gum_darwin_mapper_bind, &ctx);
  if (!ctx.success)
    goto beach;

  gum_darwin_module_enumerate_lazy_binds (module, gum_darwin_mapper_bind, &ctx);
  if (!ctx.success)
    goto beach;

  for (i = 0; i != module->segments->len; i++)
  {
    GumDarwinSegment * s =
        &g_array_index (module->segments, GumDarwinSegment, i);
    GumAddress segment_address;
    guint64 file_offset;

    segment_address =
        macho_base_address + s->vm_address - module->preferred_address;
    file_offset =
        (s->file_offset != 0) ? s->file_offset - self->image->source_offset : 0;

    mapped_address = segment_address;
    if (use_memory_mapping)
    {
      kr = mach_vm_remap (task, &mapped_address, s->file_size, 0,
          VM_FLAGS_OVERWRITE, mach_task_self (),
          (vm_offset_t) (self->image->data + file_offset), TRUE,
          &cur_protection, &max_protection, VM_INHERIT_COPY);
      GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_remap(segment)");

      kr = mach_vm_protect (task, segment_address, s->vm_size, FALSE,
          s->protection);
      if (kr == KERN_PROTECTION_FAILURE)
      {
        use_memory_mapping = FALSE;

        kr = mach_vm_allocate (task, &mapped_address, s->vm_size,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
        GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_allocate(oops)");

        goto fallback;
      }
      else
      {
        GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS,
            "mach_vm_protect(segment)");
      }
    }
    else
    {
fallback:
      kr = mach_vm_write (task, segment_address,
          (vm_offset_t) (self->image->data + file_offset), s->file_size);
      GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_write(segment)");

      kr = mach_vm_protect (task, segment_address, s->vm_size, FALSE,
          s->protection);
      GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_protect(segment)");
    }
  }

  shared_segments = self->image->shared_segments;
  for (i = 0; i != shared_segments->len; i++)
  {
    GumDarwinModuleImageSegment * s =
        &g_array_index (shared_segments, GumDarwinModuleImageSegment, i);

    mapped_address = macho_base_address + s->offset;
    kr = mach_vm_remap (task, &mapped_address, s->size, 0, VM_FLAGS_OVERWRITE,
        mach_task_self (), (vm_offset_t) (self->image->data + s->offset), TRUE,
        &cur_protection, &max_protection, VM_INHERIT_COPY);
    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS,
        "mach_vm_remap(shared_segment)");

    kr = mach_vm_protect (task, macho_base_address + s->offset, s->size, FALSE,
        s->protection);
    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS,
        "mach_vm_protect(shared_segment)");
  }

  if (gum_query_is_rwx_supported () || !gum_code_segment_is_supported ())
  {
    kr = mach_vm_write (task, self->runtime_address,
        (vm_offset_t) self->runtime, self->runtime_file_size);
    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_write(runtime)");

    kr = mach_vm_protect (task, self->runtime_address, self->runtime_vm_size,
        FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_protect(runtime)");
  }
  else
  {
    GumCodeSegment * segment;
    guint8 * scratch_page;

    segment = gum_code_segment_new (self->runtime_vm_size, NULL);

    scratch_page = gum_code_segment_get_address (segment);
    memcpy (scratch_page, self->runtime, self->runtime_file_size);

    gum_code_segment_realize (segment);
    gum_code_segment_map (segment, 0, self->runtime_vm_size, scratch_page);

    mapped_address = self->runtime_address;
    kr = mach_vm_remap (task, &mapped_address, self->runtime_vm_size, 0,
        VM_FLAGS_OVERWRITE, mach_task_self (), (mach_vm_address_t) scratch_page,
        FALSE, &cur_protection, &max_protection, VM_INHERIT_COPY);

    gum_code_segment_free (segment);

    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_remap(runtime)");
  }

  self->mapped = TRUE;

beach:
  return ctx.success;

mach_failure:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED,
        "Unexpected error while mapping dylib (%s returned '%s')",
        failed_operation, mach_error_string (kr));
    return FALSE;
  }
}

GumAddress
gum_darwin_mapper_constructor (GumDarwinMapper * self)
{
  g_assert (self->mapped);

  return gum_darwin_mapper_make_code_address (self, self->runtime_address +
      self->runtime_header_size + self->constructor_offset);
}

GumAddress
gum_darwin_mapper_destructor (GumDarwinMapper * self)
{
  g_assert (self->mapped);

  return gum_darwin_mapper_make_code_address (self, self->runtime_address +
      self->runtime_header_size + self->destructor_offset);
}

GumAddress
gum_darwin_mapper_resolve (GumDarwinMapper * self,
                           const gchar * symbol)
{
  GumDarwinModule * module = self->module;
  gchar * mangled_symbol;
  GumDarwinSymbolValue v;
  gboolean success;
  GumAddress unslid_address;

  g_assert (self->mapped);

  mangled_symbol = g_strconcat ("_", symbol, NULL);
  success = gum_darwin_mapper_resolve_symbol (self, module, mangled_symbol, &v);
  g_free (mangled_symbol);

  if (!success)
    return 0;

  if (v.resolver != 0)
    return 0;

  unslid_address = v.address - module->base_address;

  if (gum_darwin_module_is_address_in_text_section (module, unslid_address))
  {
    v.address = gum_darwin_mapper_make_code_address (self, v.address);
  }

  return v.address;
}

static GumAddress
gum_darwin_mapper_make_code_address (GumDarwinMapper * self,
                                     GumAddress value)
{
  GumAddress result = value;

  if (self->resolver->ptrauth_support == GUM_PTRAUTH_SUPPORTED)
    result = gum_sign_code_address (result);

  return result;
}

static void
gum_darwin_mapper_alloc_and_emit_runtime (GumDarwinMapper * self,
                                          GumAddress base_address,
                                          gsize size)
{
  GPtrArray * params = self->apple_parameters;
  gsize header_size = self->runtime_header_size;
  gsize pointer_size = self->module->pointer_size;
  gpointer runtime;
  guint strv_length, strv_size;
  gint * strv_offsets;
  GString * strv_blob;
  guint i;
  gsize code_size;

  runtime = g_malloc0 (self->runtime_file_size);

  strv_length = 1 + params->len;
  strv_size = (strv_length + 1) * pointer_size;
  strv_offsets = g_newa (gint, strv_length);
  strv_blob = g_string_new ("");

  strv_offsets[0] = 0;
  g_string_append_printf (strv_blob,
      "frida_dylib_range=0x%" G_GINT64_MODIFIER "x,0x%" G_GSIZE_MODIFIER "x",
      base_address, size);

  for (i = 0; i != params->len; i++)
  {
    g_string_append_c (strv_blob, '\0');

    strv_offsets[1 + i] = strv_blob->len;
    g_string_append (strv_blob, g_ptr_array_index (params, i));
  }

  for (i = 0; i != strv_length; i++)
  {
    gint offset = strv_offsets[i];
    GumAddress str_address;
    gpointer slot;

    str_address = base_address + strv_size + offset;

    slot = runtime + (i * pointer_size);
    if (pointer_size == 4)
      *((guint32 *) slot) = str_address;
    else
      *((guint64 *) slot) = str_address;
  }

  memcpy (runtime + strv_size, strv_blob->str, strv_blob->len);

  g_string_free (strv_blob, TRUE);

  self->empty_strv_address = base_address + strv_size - pointer_size;
  self->apple_strv_address = base_address;

  gum_emit_runtime (self, runtime + header_size,
      self->runtime_address + header_size, &code_size);
  g_assert (header_size + code_size <= self->runtime_file_size);

  g_free (self->runtime);
  self->runtime = runtime;
}

#if defined (HAVE_I386)

typedef struct _GumEmitX86Context GumEmitX86Context;

struct _GumEmitX86Context
{
  GumDarwinMapper * mapper;
  GumX86Writer * cw;
};

static void gum_emit_child_constructor_call (GumDarwinMapper * child,
    GumEmitX86Context * ctx);
static void gum_emit_child_destructor_call (GumDarwinMapper * child,
    GumEmitX86Context * ctx);
static gboolean gum_emit_resolve_if_needed (
    const GumDarwinBindDetails * details, GumEmitX86Context * ctx);
static gboolean gum_emit_init_calls (
    const GumDarwinInitPointersDetails * details, GumEmitX86Context * ctx);
static gboolean gum_emit_term_calls (
    const GumDarwinTermPointersDetails * details, GumEmitX86Context * ctx);

static void
gum_emit_runtime (GumDarwinMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  GumDarwinModule * module = self->module;
  GumX86Writer cw;
  GumEmitX86Context ctx;
  GSList * children_reversed;

  gum_x86_writer_init (&cw, output_buffer);
  cw.pc = pc;
  gum_x86_writer_set_target_cpu (&cw, self->module->cpu_type);

  ctx.mapper = self;
  ctx.cw = &cw;

  if (self->parent == NULL)
  {
    /* atexit stub */
    gum_x86_writer_put_xor_reg_reg (&cw, GUM_REG_XAX, GUM_REG_XAX);
    gum_x86_writer_put_ret (&cw);
  }

  self->constructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, self->module->pointer_size);

  g_slist_foreach (self->children, (GFunc) gum_emit_child_constructor_call,
      &ctx);
  gum_darwin_module_enumerate_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_lazy_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_init_pointers (module,
      (GumFoundDarwinInitPointersFunc) gum_emit_init_calls, &ctx);

  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, self->module->pointer_size);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_ret (&cw);

  self->destructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, self->module->pointer_size);

  gum_darwin_module_enumerate_term_pointers (module,
      (GumFoundDarwinTermPointersFunc) gum_emit_term_calls, &ctx);
  children_reversed = g_slist_reverse (g_slist_copy (self->children));
  g_slist_foreach (children_reversed, (GFunc) gum_emit_child_destructor_call,
      &ctx);
  g_slist_free (children_reversed);

  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, self->module->pointer_size);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  *size = gum_x86_writer_offset (&cw);
  gum_x86_writer_clear (&cw);
}

static void
gum_emit_child_constructor_call (GumDarwinMapper * child,
                                 GumEmitX86Context * ctx)
{
  GumX86Writer * cw = ctx->cw;

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX,
      gum_darwin_mapper_constructor (child));
  gum_x86_writer_put_call_reg (cw, GUM_REG_XCX);
}

static void
gum_emit_child_destructor_call (GumDarwinMapper * child,
                                GumEmitX86Context * ctx)
{
  GumX86Writer * cw = ctx->cw;

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX,
      gum_darwin_mapper_destructor (child));
  gum_x86_writer_put_call_reg (cw, GUM_REG_XCX);
}

static gboolean
gum_emit_resolve_if_needed (const GumDarwinBindDetails * details,
                            GumEmitX86Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumX86Writer * cw = ctx->cw;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;
  gboolean success;
  GumAddress entry;

  if (details->type != GUM_DARWIN_BIND_POINTER)
    return TRUE;

  dependency = gum_darwin_mapper_get_dependency_by_ordinal (self,
      details->library_ordinal, NULL);
  if (dependency == NULL)
    return TRUE;
  success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value);
  if (!success || value.resolver == 0)
    return TRUE;

  entry = self->module->base_address + details->segment->vm_address +
      details->offset;

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX,
      gum_darwin_mapper_make_code_address (self, value.resolver));
  gum_x86_writer_put_call_reg (cw, GUM_REG_XCX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX, details->addend);
  gum_x86_writer_put_add_reg_reg (cw, GUM_REG_XAX, GUM_REG_XCX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX, entry);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_REG_XCX, GUM_REG_XAX);

  return TRUE;
}

static gboolean
gum_emit_init_calls (const GumDarwinInitPointersDetails * details,
                     GumEmitX86Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumX86Writer * cw = ctx->cw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XBP, details->address);
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XBX, details->count);

  gum_x86_writer_put_label (cw, next_label);

  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_REG_XAX, GUM_REG_XBP);
  gum_x86_writer_put_call_reg_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_REG_XAX, 5,
      /*   argc */ GUM_ARG_ADDRESS, GUM_ADDRESS (0),
      /*   argv */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->empty_strv_address),
      /*   envp */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->empty_strv_address),
      /*  apple */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->apple_strv_address),
      /* result */ GUM_ARG_ADDRESS, GUM_ADDRESS (0));

  gum_x86_writer_put_add_reg_imm (cw, GUM_REG_XBP, self->module->pointer_size);
  gum_x86_writer_put_dec_reg (cw, GUM_REG_XBX);
  gum_x86_writer_put_jcc_short_label (cw, X86_INS_JNE, next_label, GUM_NO_HINT);

  return TRUE;
}

static gboolean
gum_emit_term_calls (const GumDarwinTermPointersDetails * details,
                     GumEmitX86Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumX86Writer * cw = ctx->cw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XBP, details->address +
      ((details->count - 1) * self->module->pointer_size));
  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XBX, details->count);

  gum_x86_writer_put_label (cw, next_label);

  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_REG_XAX, GUM_REG_XBP);
  gum_x86_writer_put_call_reg (cw, GUM_REG_XAX);

  gum_x86_writer_put_sub_reg_imm (cw, GUM_REG_XBP, self->module->pointer_size);
  gum_x86_writer_put_dec_reg (cw, GUM_REG_XBX);
  gum_x86_writer_put_jcc_short_label (cw, X86_INS_JNE, next_label, GUM_NO_HINT);

  return TRUE;
}

#elif defined (HAVE_ARM) || defined (HAVE_ARM64)

typedef struct _GumEmitArmContext GumEmitArmContext;
typedef struct _GumEmitArm64Context GumEmitArm64Context;

struct _GumEmitArmContext
{
  GumDarwinMapper * mapper;
  GumThumbWriter * tw;
};

struct _GumEmitArm64Context
{
  GumDarwinMapper * mapper;
  GumArm64Writer * aw;

  GumAddress process_chained_fixups;
  GumAddress fixup_chain_processor_api;
};

static void gum_emit_arm_runtime (GumDarwinMapper * self,
    gpointer output_buffer, GumAddress pc, gsize * size);
static void gum_emit_arm_child_constructor_call (GumDarwinMapper * child,
    GumEmitArmContext * ctx);
static void gum_emit_arm_child_destructor_call (GumDarwinMapper * child,
    GumEmitArmContext * ctx);
static gboolean gum_emit_arm_resolve_if_needed (
    const GumDarwinBindDetails * details, GumEmitArmContext * ctx);
static gboolean gum_emit_arm_init_calls (
    const GumDarwinInitPointersDetails * details, GumEmitArmContext * ctx);
static gboolean gum_emit_arm_term_calls (
    const GumDarwinTermPointersDetails * details, GumEmitArmContext * ctx);

static void gum_emit_arm64_runtime (GumDarwinMapper * self,
    gpointer output_buffer, GumAddress pc, gsize * size);
static gpointer gum_resolve_api (gpointer module, const gchar * name);
static void gum_emit_arm64_child_constructor_call (GumDarwinMapper * child,
    GumEmitArm64Context * ctx);
static void gum_emit_arm64_child_destructor_call (GumDarwinMapper * child,
    GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_chained_fixup_call (
    const GumDarwinChainedFixupsDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_resolve_if_needed (
    const GumDarwinBindDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_init_pointer_calls (
    const GumDarwinInitPointersDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_init_offset_calls (
    const GumDarwinInitOffsetsDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_term_calls (
    const GumDarwinTermPointersDetails * details, GumEmitArm64Context * ctx);

static void
gum_emit_runtime (GumDarwinMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  if (self->module->cpu_type == GUM_CPU_ARM)
    gum_emit_arm_runtime (self, output_buffer, pc, size);
  else
    gum_emit_arm64_runtime (self, output_buffer, pc, size);
}

static void
gum_emit_arm_runtime (GumDarwinMapper * self,
                      gpointer output_buffer,
                      GumAddress pc,
                      gsize * size)
{
  GumDarwinModule * module = self->module;
  GumThumbWriter tw;
  GumEmitArmContext ctx;
  GSList * children_reversed;

  gum_thumb_writer_init (&tw, output_buffer);
  tw.pc = pc;

  ctx.mapper = self;
  ctx.tw = &tw;

  if (self->parent == NULL)
  {
    /* atexit stub */
    gum_thumb_writer_put_ldr_reg_u32 (&tw, ARM_REG_R0, 0);
    gum_thumb_writer_put_bx_reg (&tw, ARM_REG_LR);
  }

  self->constructor_offset = gum_thumb_writer_offset (&tw) + 1;
  gum_thumb_writer_put_push_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_LR);

  g_slist_foreach (self->children, (GFunc) gum_emit_arm_child_constructor_call,
      &ctx);
  gum_darwin_module_enumerate_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_arm_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_lazy_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_arm_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_init_pointers (module,
      (GumFoundDarwinInitPointersFunc) gum_emit_arm_init_calls, &ctx);

  gum_thumb_writer_put_pop_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_PC);

  self->destructor_offset = gum_thumb_writer_offset (&tw) + 1;
  gum_thumb_writer_put_push_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_LR);

  gum_darwin_module_enumerate_term_pointers (module,
      (GumFoundDarwinTermPointersFunc) gum_emit_arm_term_calls, &ctx);
  children_reversed = g_slist_reverse (g_slist_copy (self->children));
  g_slist_foreach (children_reversed,
      (GFunc) gum_emit_arm_child_destructor_call, &ctx);
  g_slist_free (children_reversed);

  gum_thumb_writer_put_pop_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_PC);

  gum_thumb_writer_flush (&tw);
  *size = gum_thumb_writer_offset (&tw);
  gum_thumb_writer_clear (&tw);
}

static void
gum_emit_arm_child_constructor_call (GumDarwinMapper * child,
                                     GumEmitArmContext * ctx)
{
  GumThumbWriter * tw = ctx->tw;

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R0,
      gum_darwin_mapper_constructor (child));
  gum_thumb_writer_put_blx_reg (tw, ARM_REG_R0);
}

static void
gum_emit_arm_child_destructor_call (GumDarwinMapper * child,
                                    GumEmitArmContext * ctx)
{
  GumThumbWriter * tw = ctx->tw;

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R0,
      gum_darwin_mapper_destructor (child));
  gum_thumb_writer_put_blx_reg (tw, ARM_REG_R0);
}

static gboolean
gum_emit_arm_resolve_if_needed (const GumDarwinBindDetails * details,
                                GumEmitArmContext * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumThumbWriter * tw = ctx->tw;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;
  gboolean success;
  GumAddress entry;

  if (details->type != GUM_DARWIN_BIND_POINTER)
    return TRUE;

  dependency = gum_darwin_mapper_get_dependency_by_ordinal (self,
      details->library_ordinal, NULL);
  if (dependency == NULL)
    return TRUE;
  success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value);
  if (!success || value.resolver == 0)
    return TRUE;

  entry = self->module->base_address + details->segment->vm_address +
      details->offset;

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R1,
      gum_darwin_mapper_make_code_address (self, value.resolver));
  gum_thumb_writer_put_blx_reg (tw, ARM_REG_R1);
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R1, details->addend);
  gum_thumb_writer_put_add_reg_reg_reg (tw, ARM_REG_R0, ARM_REG_R0, ARM_REG_R1);
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R1, entry);
  gum_thumb_writer_put_str_reg_reg_offset (tw, ARM_REG_R0, ARM_REG_R1, 0);

  return TRUE;
}

static gboolean
gum_emit_arm_init_calls (const GumDarwinInitPointersDetails * details,
                         GumEmitArmContext * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumThumbWriter * tw = ctx->tw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R4, details->address);
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R5, details->count);

  gum_thumb_writer_put_label (tw, next_label);

  gum_thumb_writer_put_ldr_reg_reg (tw, ARM_REG_R6, ARM_REG_R4);
  gum_thumb_writer_put_call_reg_with_arguments (tw, ARM_REG_R6, 5,
      /*   argc */ GUM_ARG_ADDRESS, GUM_ADDRESS (0),
      /*   argv */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->empty_strv_address),
      /*   envp */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->empty_strv_address),
      /*  apple */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->apple_strv_address),
      /* result */ GUM_ARG_ADDRESS, GUM_ADDRESS (0));

  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R4, ARM_REG_R4, 4);
  gum_thumb_writer_put_sub_reg_reg_imm (tw, ARM_REG_R5, ARM_REG_R5, 1);
  gum_thumb_writer_put_cmp_reg_imm (tw, ARM_REG_R5, 0);
  gum_thumb_writer_put_bne_label (tw, next_label);

  return TRUE;
}

static gboolean
gum_emit_arm_term_calls (const GumDarwinTermPointersDetails * details,
                         GumEmitArmContext * ctx)
{
  GumThumbWriter * tw = ctx->tw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R4, details->address +
      ((details->count - 1) * 4));
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R5, details->count);

  gum_thumb_writer_put_label (tw, next_label);

  gum_thumb_writer_put_ldr_reg_reg (tw, ARM_REG_R0, ARM_REG_R4);
  gum_thumb_writer_put_blx_reg (tw, ARM_REG_R0);

  gum_thumb_writer_put_sub_reg_reg_imm (tw, ARM_REG_R4, ARM_REG_R4, 4);
  gum_thumb_writer_put_sub_reg_reg_imm (tw, ARM_REG_R5, ARM_REG_R5, 1);
  gum_thumb_writer_put_cmp_reg_imm (tw, ARM_REG_R5, 0);
  gum_thumb_writer_put_bne_label (tw, next_label);

  return TRUE;
}

static void
gum_emit_arm64_runtime (GumDarwinMapper * self,
                        gpointer output_buffer,
                        GumAddress pc,
                        gsize * size)
{
  GumDarwinModule * module = self->module;
  GumArm64Writer aw;
  GumEmitArm64Context ctx;
  GSList * children_reversed;

  gum_arm64_writer_init (&aw, output_buffer);
  aw.pc = pc;

  ctx.mapper = self;
  ctx.aw = &aw;
  ctx.process_chained_fixups = 0;
  ctx.fixup_chain_processor_api = 0;

  if (self->parent == NULL)
  {
    /* atexit stub */
    gum_arm64_writer_put_ldr_reg_u64 (&aw, ARM64_REG_X0, 0);
    gum_arm64_writer_put_ret (&aw);
  }

  if (self->chained_fixups_count > 0)
  {
    gpointer libsystem;
    GumFixupChainProcessorApi api;

    ctx.process_chained_fixups = aw.pc;
    gum_arm64_writer_put_bytes (&aw,
        (const guint8 *) gum_fixup_chain_processor_code,
        sizeof (gum_fixup_chain_processor_code));

    ctx.fixup_chain_processor_api = aw.pc;
    libsystem = dlopen ("/usr/lib/libSystem.B.dylib", RTLD_LAZY | RTLD_GLOBAL);
    api._mach_task_self = gum_resolve_api (libsystem, "mach_task_self");
    api.mach_vm_allocate = gum_resolve_api (libsystem, "mach_vm_allocate");
    api.mach_vm_deallocate = gum_resolve_api (libsystem, "mach_vm_deallocate");
    api.dlopen = gum_resolve_api (libsystem, "dlopen");
    api.dlsym = gum_resolve_api (libsystem, "dlsym");
    dlclose (libsystem);
    gum_arm64_writer_put_bytes (&aw, (const guint8 *) &api, sizeof (api));
  }

  self->constructor_offset = gum_arm64_writer_offset (&aw);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_SP);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X21, ARM64_REG_X22);

  g_slist_foreach (self->children,
      (GFunc) gum_emit_arm64_child_constructor_call, &ctx);
  gum_darwin_module_enumerate_chained_fixups (module,
      (GumFoundDarwinChainedFixupsFunc) gum_emit_arm64_chained_fixup_call,
      &ctx);
  gum_darwin_module_enumerate_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_arm64_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_lazy_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_arm64_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_init_pointers (module,
      (GumFoundDarwinInitPointersFunc) gum_emit_arm64_init_pointer_calls, &ctx);
  gum_darwin_module_enumerate_init_offsets (module,
      (GumFoundDarwinInitOffsetsFunc) gum_emit_arm64_init_offset_calls, &ctx);

  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X21, ARM64_REG_X22);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&aw);

  self->destructor_offset = gum_arm64_writer_offset (&aw);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_SP);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X21, ARM64_REG_X22);

  gum_darwin_module_enumerate_term_pointers (module,
      (GumFoundDarwinTermPointersFunc) gum_emit_arm64_term_calls, &ctx);
  children_reversed = g_slist_reverse (g_slist_copy (self->children));
  g_slist_foreach (children_reversed,
      (GFunc) gum_emit_arm64_child_destructor_call, &ctx);
  g_slist_free (children_reversed);

  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X21, ARM64_REG_X22);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&aw);

  gum_arm64_writer_flush (&aw);
  *size = gum_arm64_writer_offset (&aw);
  gum_arm64_writer_clear (&aw);
}

static gpointer
gum_resolve_api (gpointer module,
                 const gchar * name)
{
  return gum_strip_code_pointer (dlsym (module, name));
}

static void
gum_emit_arm64_child_constructor_call (GumDarwinMapper * child,
                                       GumEmitArm64Context * ctx)
{
  GumArm64Writer * aw = ctx->aw;

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X0,
      gum_darwin_mapper_constructor (child));
  gum_arm64_writer_put_blr_reg (aw, ARM64_REG_X0);
}

static void
gum_emit_arm64_child_destructor_call (GumDarwinMapper * child,
                                      GumEmitArm64Context * ctx)
{
  GumArm64Writer * aw = ctx->aw;

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X0,
      gum_darwin_mapper_destructor (child));
  gum_arm64_writer_put_blr_reg (aw, ARM64_REG_X0);
}

static gboolean
gum_emit_arm64_chained_fixup_call (
    const GumDarwinChainedFixupsDetails * details,
    GumEmitArm64Context * ctx)
{
  GumDarwinModule * module = ctx->mapper->module;

  gum_arm64_writer_put_call_address_with_arguments (ctx->aw,
      ctx->process_chained_fixups,
      4,
      GUM_ARG_ADDRESS, details->vm_address,
      GUM_ARG_ADDRESS, module->base_address,
      GUM_ARG_ADDRESS, module->preferred_address,
      GUM_ARG_ADDRESS, ctx->fixup_chain_processor_api);

  return TRUE;
}

static gboolean
gum_emit_arm64_resolve_if_needed (const GumDarwinBindDetails * details,
                                  GumEmitArm64Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumArm64Writer * aw = ctx->aw;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;
  gboolean success;
  GumAddress entry;

  if (details->type != GUM_DARWIN_BIND_POINTER)
    return TRUE;

  dependency = gum_darwin_mapper_get_dependency_by_ordinal (self,
      details->library_ordinal, NULL);
  if (dependency == NULL)
    return TRUE;
  success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value);
  if (!success || value.resolver == 0)
    return TRUE;

  entry = self->module->base_address + details->segment->vm_address +
      details->offset;

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X1,
      gum_darwin_mapper_make_code_address (self, value.resolver));
  gum_arm64_writer_put_blr_reg (aw, ARM64_REG_X1);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X1, details->addend);
  gum_arm64_writer_put_add_reg_reg_reg (aw, ARM64_REG_X0, ARM64_REG_X0,
      ARM64_REG_X1);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X1, entry);
  gum_arm64_writer_put_str_reg_reg_offset (aw, ARM64_REG_X0, ARM64_REG_X1, 0);

  return TRUE;
}

static gboolean
gum_emit_arm64_init_pointer_calls (const GumDarwinInitPointersDetails * details,
                                   GumEmitArm64Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumArm64Writer * aw = ctx->aw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X19, details->address);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X20, details->count);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X21,
      self->empty_strv_address);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X22,
      self->apple_strv_address);

  gum_arm64_writer_put_label (aw, next_label);

  /* init (argc, argv, envp, apple, result) */
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X0, ARM64_REG_XZR);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X1, ARM64_REG_X21);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X2, ARM64_REG_X21);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X3, ARM64_REG_X22);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X4, ARM64_REG_XZR);
  gum_arm64_writer_put_ldr_reg_reg_offset (aw, ARM64_REG_X5, ARM64_REG_X19, 0);
  gum_arm64_writer_put_blr_reg_no_auth (aw, ARM64_REG_X5);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X19, ARM64_REG_X19, 8);
  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_X20, ARM64_REG_X20, 1);
  gum_arm64_writer_put_cbnz_reg_label (aw, ARM64_REG_X20, next_label);

  return TRUE;
}

static gboolean
gum_emit_arm64_init_offset_calls (const GumDarwinInitOffsetsDetails * details,
                                  GumEmitArm64Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumArm64Writer * aw = ctx->aw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X19, details->address);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X20, details->count);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X21,
      self->empty_strv_address);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X22,
      self->apple_strv_address);

  gum_arm64_writer_put_label (aw, next_label);

  /* init (argc, argv, envp, apple, result) */
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X0, ARM64_REG_XZR);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X1, ARM64_REG_X21);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X2, ARM64_REG_X21);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X3, ARM64_REG_X22);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X4, ARM64_REG_XZR);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X5,
      self->module->base_address);
  gum_arm64_writer_put_ldr_reg_reg_offset (aw, ARM64_REG_W6, ARM64_REG_X19, 0);
  gum_arm64_writer_put_add_reg_reg_reg (aw, ARM64_REG_X5, ARM64_REG_X5,
      ARM64_REG_X6);
  gum_arm64_writer_put_blr_reg_no_auth (aw, ARM64_REG_X5);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X19, ARM64_REG_X19, 4);
  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_X20, ARM64_REG_X20, 1);
  gum_arm64_writer_put_cbnz_reg_label (aw, ARM64_REG_X20, next_label);

  return TRUE;
}

static gboolean
gum_emit_arm64_term_calls (const GumDarwinTermPointersDetails * details,
                           GumEmitArm64Context * ctx)
{
  GumArm64Writer * aw = ctx->aw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X19, details->address +
      ((details->count - 1) * 8));
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X20, details->count);

  gum_arm64_writer_put_label (aw, next_label);

  gum_arm64_writer_put_ldr_reg_reg_offset (aw, ARM64_REG_X0,
      ARM64_REG_X19, 0);
  gum_arm64_writer_put_blr_reg_no_auth (aw, ARM64_REG_X0);

  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_X19, ARM64_REG_X19, 8);
  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_X20, ARM64_REG_X20, 1);
  gum_arm64_writer_put_cbnz_reg_label (aw, ARM64_REG_X20, next_label);

  return TRUE;
}

#endif

static gboolean
gum_accumulate_chained_fixups_size (
    const GumDarwinChainedFixupsDetails * details,
    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;

  if (ctx->chained_fixups_count++ == 0)
  {
    ctx->total += sizeof (gum_fixup_chain_processor_code);
    ctx->total += sizeof (GumFixupChainProcessorApi);
  }

  ctx->total += GUM_MAPPER_CHAINED_FIXUP_CALL_SIZE;

  return TRUE;
}

static gboolean
gum_accumulate_bind_footprint_size (const GumDarwinBindDetails * details,
                                    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;
  GumDarwinMapper * self = ctx->mapper;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;

  if (details->type != GUM_DARWIN_BIND_POINTER)
    return TRUE;

  dependency = gum_darwin_mapper_get_dependency_by_ordinal (self,
      details->library_ordinal, NULL);
  if (dependency == NULL)
    return TRUE;

  if (gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value))
  {
    if (value.resolver != 0)
      ctx->total += GUM_MAPPER_RESOLVER_SIZE;
  }

  return TRUE;
}

static gboolean
gum_accumulate_init_pointers_footprint_size (
    const GumDarwinInitPointersDetails * details,
    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;

  ctx->total += GUM_MAPPER_INIT_SIZE;

  return TRUE;
}

static gboolean
gum_accumulate_init_offsets_footprint_size (
    const GumDarwinInitOffsetsDetails * details,
    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;

  ctx->total += GUM_MAPPER_INIT_SIZE;

  return TRUE;
}

static gboolean
gum_accumulate_term_footprint_size (
    const GumDarwinTermPointersDetails * details,
    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;

  ctx->total += GUM_MAPPER_TERM_SIZE;

  return TRUE;
}

static gpointer
gum_darwin_mapper_data_from_offset (GumDarwinMapper * self,
                                    guint64 offset,
                                    guint size)
{
  GumDarwinModuleImage * image = self->image;
  guint64 source_offset = image->source_offset;

  if (source_offset != 0)
  {
    if (offset < source_offset)
      return NULL;
    if (offset + size > source_offset + image->shared_offset +
        image->shared_size)
      return NULL;
  }
  else
  {
    if (offset + size > image->size)
      return NULL;
  }

  return image->data + (offset - source_offset);
}

static GumDarwinMapping *
gum_darwin_mapper_get_dependency_by_ordinal (GumDarwinMapper * self,
                                             gint ordinal,
                                             GError ** error)
{
  GumDarwinMapping * result;

  switch (ordinal)
  {
    case GUM_DARWIN_BIND_SELF:
      result = gum_darwin_mapper_get_dependency_by_name (self,
          self->module->name, error);
      break;
    case GUM_DARWIN_BIND_MAIN_EXECUTABLE:
    case GUM_DARWIN_BIND_FLAT_LOOKUP:
    case GUM_DARWIN_BIND_WEAK_LOOKUP:
      goto invalid_ordinal;
    default:
    {
      gint i = ordinal - 1;

      if (i >= 0 && i < self->dependencies->len)
        result = g_ptr_array_index (self->dependencies, i);
      else
        goto invalid_ordinal;

      break;
    }
  }

  return result;

invalid_ordinal:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_DATA,
        "Malformed dependency ordinal");
    return NULL;
  }
}

static GumDarwinMapping *
gum_darwin_mapper_get_dependency_by_name (GumDarwinMapper * self,
                                          const gchar * name,
                                          GError ** error)
{
  GumDarwinModuleResolver * resolver = self->resolver;
  GumDarwinMapping * mapping;

  if (self->parent != NULL)
    return gum_darwin_mapper_get_dependency_by_name (self->parent, name, error);

  mapping = g_hash_table_lookup (self->mappings, name);

  if (mapping == NULL)
  {
    GumDarwinModule * module =
        gum_darwin_module_resolver_find_module (resolver, name);
    if (module != NULL)
      mapping = gum_darwin_mapper_add_existing_mapping (self, module);
  }

  if (mapping == NULL)
  {
    gchar * full_name;
    GumDarwinMapper * mapper;

    if (resolver->sysroot != NULL)
      full_name = g_strconcat (resolver->sysroot, name, NULL);
    else
      full_name = g_strdup (name);

    mapper = gum_darwin_mapper_new_from_file_with_parent (self, full_name,
        self->resolver, error);
    if (mapper != NULL)
    {
      mapping = g_hash_table_lookup (self->mappings, full_name);
      g_assert (mapping != NULL);

      if (resolver->sysroot != NULL)
        gum_darwin_mapper_add_alias_mapping (self, name, mapping);
    }

    g_free (full_name);
  }

  return mapping;
}

static gboolean
gum_darwin_mapper_resolve_symbol (GumDarwinMapper * self,
                                  GumDarwinModule * module,
                                  const gchar * name,
                                  GumDarwinSymbolValue * value)
{
  GumDarwinExportDetails details;

  if (self->parent != NULL)
  {
    return gum_darwin_mapper_resolve_symbol (self->parent, module, name, value);
  }

  if (strcmp (name, "_atexit") == 0 ||
      strcmp (name, "_atexit_b") == 0 ||
      strcmp (name, "___cxa_atexit") == 0 ||
      strcmp (name, "___cxa_thread_atexit") == 0 ||
      strcmp (name, "__tlv_atexit") == 0)
  {
    /*
     * We pretend we install the handler by resolving to a dummy function that
     * does nothing. Memory for handlers isn't released, so we shouldn't let
     * our libraries register them. In our case atexit is only for debugging
     * purposes anyway (GLib installs a handler to print statistics when
     * debugging is enabled).
     */
    if (self->runtime_address != 0)
    {
      value->address = self->runtime_address + self->runtime_header_size;
      if (self->module->cpu_type == GUM_CPU_ARM)
        value->address |= 1;
    }
    else
    {
      /* Resolving before mapped; we will handle it later. */
      value->address = 0xdeadbeef;
    }
    value->resolver = 0;
    return TRUE;
  }

  if (!gum_darwin_module_resolve_export (module, name, &details))
  {
    if (gum_darwin_module_get_lacks_exports_for_reexports (module))
    {
      GPtrArray * reexports = module->reexports;
      guint i;

      for (i = 0; i != reexports->len; i++)
      {
        GumDarwinMapping * target;

        target = gum_darwin_mapper_get_dependency_by_name (self,
            g_ptr_array_index (reexports, i), NULL);
        if (target == NULL)
          continue;

        if (gum_darwin_mapper_resolve_symbol (self, target->module, name,
            value))
        {
          return TRUE;
        }
      }
    }

    return FALSE;
  }

  if ((details.flags & GUM_DARWIN_EXPORT_REEXPORT) != 0)
  {
    const gchar * target_name;
    GumDarwinMapping * target;

    target_name = gum_darwin_module_get_dependency_by_ordinal (module,
        details.reexport_library_ordinal);

    target = gum_darwin_mapper_get_dependency_by_name (self, target_name, NULL);
    if (target == NULL)
      return FALSE;

    return gum_darwin_mapper_resolve_symbol (self, target->module,
        details.reexport_symbol, value);
  }

  switch (details.flags & GUM_DARWIN_EXPORT_KIND_MASK)
  {
    case GUM_DARWIN_EXPORT_REGULAR:
      if ((details.flags & GUM_DARWIN_EXPORT_STUB_AND_RESOLVER) != 0)
      {
        /* XXX: we ignore interposing */
        value->address = module->base_address + details.stub;
        value->resolver = module->base_address + details.resolver;
        return TRUE;
      }
      value->address = module->base_address + details.offset;
      value->resolver = 0;
      return TRUE;
    case GUM_DARWIN_EXPORT_THREAD_LOCAL:
      value->address = module->base_address + details.offset;
      value->resolver = 0;
      return TRUE;
    case GUM_DARWIN_EXPORT_ABSOLUTE:
      value->address = details.offset;
      value->resolver = 0;
      return TRUE;
    default:
      return FALSE;
  }
}

static GumDarwinMapping *
gum_darwin_mapper_add_existing_mapping (GumDarwinMapper * self,
                                        GumDarwinModule * module)
{
  GumDarwinMapping * mapping;

  mapping = g_slice_new (GumDarwinMapping);
  mapping->module = g_object_ref (module);
  mapping->mapper = NULL;

  g_hash_table_insert (self->mappings, g_strdup (module->name), mapping);

  return mapping;
}

static GumDarwinMapping *
gum_darwin_mapper_add_pending_mapping (GumDarwinMapper * self,
                                       const gchar * name,
                                       GumDarwinMapper * mapper)
{
  GumDarwinMapping * mapping;

  mapping = g_slice_new (GumDarwinMapping);
  mapping->module = g_object_ref (mapper->module);
  mapping->mapper = mapper;

  g_hash_table_insert (self->mappings, g_strdup (name), mapping);

  return mapping;
}

static GumDarwinMapping *
gum_darwin_mapper_add_alias_mapping (GumDarwinMapper * self,
                                     const gchar * name,
                                     const GumDarwinMapping * to)
{
  GumDarwinMapping * mapping;

  mapping = g_slice_dup (GumDarwinMapping, to);
  g_object_ref (mapping->module);

  g_hash_table_insert (self->mappings, g_strdup (name), mapping);

  return mapping;
}

static gboolean
gum_darwin_mapper_rebase (const GumDarwinRebaseDetails * details,
                          gpointer user_data)
{
  GumMapContext * ctx = user_data;
  GumDarwinMapper * self = ctx->mapper;
  gsize pointer_size = self->module->pointer_size;
  gpointer entry;

  if (details->offset >= details->segment->file_size)
    goto invalid_data;

  entry = gum_darwin_mapper_data_from_offset (self,
      details->segment->file_offset + details->offset, pointer_size);
  if (entry == NULL)
    goto invalid_data;

  switch (details->type)
  {
    case GUM_DARWIN_REBASE_POINTER:
    case GUM_DARWIN_REBASE_TEXT_ABSOLUTE32:
      if (pointer_size == 4)
        *((guint32 *) entry) += (guint32) details->slide;
      else
        *((guint64 *) entry) += (guint64) details->slide;
      break;
    case GUM_DARWIN_REBASE_TEXT_PCREL32:
    default:
      goto invalid_data;
  }

  return TRUE;

invalid_data:
  {
    ctx->success = FALSE;
    g_set_error (ctx->error, GUM_ERROR, GUM_ERROR_INVALID_DATA,
        "Malformed rebase entry");
    return FALSE;
  }
}

static gboolean
gum_darwin_mapper_bind (const GumDarwinBindDetails * details,
                        gpointer user_data)
{
  GumMapContext * ctx = user_data;
  GumDarwinMapper * self = ctx->mapper;

  switch (details->type)
  {
    case GUM_DARWIN_BIND_POINTER:
      ctx->success = gum_darwin_mapper_bind_pointer (self, details, ctx->error);
      break;
    case GUM_DARWIN_BIND_THREADED_TABLE:
      ctx->success = gum_darwin_mapper_bind_table (self, details, ctx->error);
      break;
    case GUM_DARWIN_BIND_THREADED_ITEMS:
      ctx->success = gum_darwin_mapper_bind_items (self, details, ctx->error);
      break;
    default:
      goto invalid_data;
  }

  return ctx->success;

invalid_data:
  {
    ctx->success = FALSE;
    g_set_error (ctx->error, GUM_ERROR, GUM_ERROR_INVALID_DATA,
        "Malformed bind entry");
    return FALSE;
  }
}

static gboolean
gum_darwin_mapper_bind_pointer (GumDarwinMapper * self,
                                const GumDarwinBindDetails * bind,
                                GError ** error)
{
  GumDarwinSymbolValue value;
  gboolean is_weak_import, success;
  GumDarwinMapping * dependency;

  is_weak_import = (bind->symbol_flags & GUM_DARWIN_BIND_WEAK_IMPORT) != 0;

  if (bind->library_ordinal == GUM_DARWIN_BIND_FLAT_LOOKUP)
  {
    dependency = NULL;

    value.address = gum_darwin_module_resolver_find_dynamic_address (
        self->resolver, gum_symbol_name_from_darwin (bind->symbol_name));
    value.resolver = 0;

    success = value.address != 0;
  }
  else
  {
    dependency = gum_darwin_mapper_get_dependency_by_ordinal (self,
        bind->library_ordinal, error);
    if (dependency == NULL)
      goto module_not_found;

    success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
        bind->symbol_name, &value);
    if (!success && !is_weak_import && self->resolver->sysroot != NULL &&
        g_str_has_suffix (bind->symbol_name, "$INODE64"))
    {
      gchar * plain_name;

      plain_name = g_strndup (bind->symbol_name,
          strlen (bind->symbol_name) - 8);
      success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
          plain_name, &value);
      g_free (plain_name);
    }
  }

  if (!success && !is_weak_import)
    goto symbol_not_found;

  if (success)
    value.address += bind->addend;

  if (self->threaded_binds != NULL)
  {
    g_array_append_val (self->threaded_binds, value.address);
  }
  else
  {
    gsize pointer_size = self->module->pointer_size;
    gpointer entry;

    entry = gum_darwin_mapper_data_from_offset (self,
        bind->segment->file_offset + bind->offset, pointer_size);
    if (entry == NULL)
      goto invalid_data;

    if (pointer_size == 4)
      *((guint32 *) entry) = value.address;
    else
      *((guint64 *) entry) = value.address;
  }

  return TRUE;

invalid_data:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_DATA,
        "Malformed bind entry");
    return FALSE;
  }
module_not_found:
  {
    return FALSE;
  }
symbol_not_found:
  {
    if (dependency != NULL)
    {
      g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
          "Unable to bind, “%s” not found in “%s”",
          gum_symbol_name_from_darwin (bind->symbol_name),
          dependency->module->name);
    }
    else
    {
      g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
          "Unable to bind, “%s” cannot be resolved through flat lookup",
          gum_symbol_name_from_darwin (bind->symbol_name));
    }
    return FALSE;
  }
}

static gboolean
gum_darwin_mapper_bind_table (GumDarwinMapper * self,
                              const GumDarwinBindDetails * bind,
                              GError ** error)
{
  g_clear_pointer (&self->threaded_binds, g_array_unref);
  self->threaded_binds = g_array_sized_new (FALSE, FALSE, sizeof (GumAddress),
      bind->threaded_table_size);

  return TRUE;
}

static gboolean
gum_darwin_mapper_bind_items (GumDarwinMapper * self,
                              const GumDarwinBindDetails * bind,
                              GError ** error)
{
  GArray * threaded_binds = self->threaded_binds;
  const GumDarwinSegment * segment = bind->segment;
  GumAddress preferred_base_address, slide;
  guint64 cursor;
  GumDarwinThreadedItem item;

  if (threaded_binds == NULL)
    goto invalid_data;

  preferred_base_address = self->module->preferred_address;
  slide = gum_darwin_module_get_slide (self->module);

  cursor = bind->offset;

  do
  {
    guint64 * slot, bound_value;

    slot = gum_darwin_mapper_data_from_offset (self,
        segment->file_offset + cursor, sizeof (guint64));
    if (slot == NULL)
      goto invalid_data;
    gum_darwin_threaded_item_parse (*slot, &item);

    if (item.type == GUM_DARWIN_THREADED_BIND)
    {
      guint ordinal = item.bind_ordinal;

      if (ordinal >= threaded_binds->len)
        goto invalid_data;

      bound_value = g_array_index (threaded_binds, GumAddress, ordinal);
    }
    else if (item.type == GUM_DARWIN_THREADED_REBASE)
    {
      bound_value = item.rebase_address;

      if (item.is_authenticated)
        bound_value += preferred_base_address;

      bound_value += slide;
    }
    else
    {
      g_assert_not_reached ();
    }

    if (item.is_authenticated)
    {
#ifdef HAVE_PTRAUTH
      gpointer p = GSIZE_TO_POINTER (bound_value);
      uintptr_t d = item.diversity;

      if (item.has_address_diversity)
      {
        gpointer slot_location;

        slot_location = GSIZE_TO_POINTER (segment->vm_address + slide + cursor);

        d = ptrauth_blend_discriminator (slot_location, d);
      }

      switch (item.key)
      {
        case ptrauth_key_asia:
          p = ptrauth_sign_unauthenticated (p, ptrauth_key_asia, d);
          break;
        case ptrauth_key_asib:
          p = ptrauth_sign_unauthenticated (p, ptrauth_key_asib, d);
          break;
        case ptrauth_key_asda:
          p = ptrauth_sign_unauthenticated (p, ptrauth_key_asda, d);
          break;
        case ptrauth_key_asdb:
          p = ptrauth_sign_unauthenticated (p, ptrauth_key_asdb, d);
          break;
        default:
          g_assert_not_reached ();
      }

      *slot = GPOINTER_TO_SIZE (p);
#else
      goto invalid_data;
#endif
    }
    else
    {
      *slot = bound_value;
    }

    cursor += item.delta * sizeof (guint64);
  }
  while (item.delta != 0);

  return TRUE;

invalid_data:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_DATA,
        "Malformed bind items");
    return FALSE;
  }
}

static void
gum_darwin_mapping_free (GumDarwinMapping * self)
{
  g_object_unref (self->module);
  g_slice_free (GumDarwinMapping, self);
}

#endif
