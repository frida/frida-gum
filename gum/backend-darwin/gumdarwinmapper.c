/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdarwinmapper.h"

#include "gumdarwin.h"
#include "gumdarwinmodule.h"

#include <fcntl.h>
#ifdef HAVE_I386
# include <gum/arch-x86/gumx86writer.h>
#else
# include <gum/arch-arm/gumthumbwriter.h>
# include <gum/arch-arm64/gumarm64writer.h>
#endif
#include <mach-o/loader.h>
#include <unistd.h>

#if defined (HAVE_I386)
# define BASE_FOOTPRINT_SIZE_32 25
# define BASE_FOOTPRINT_SIZE_64 30
# define DEPENDENCY_FOOTPRINT_SIZE_32 14
# define DEPENDENCY_FOOTPRINT_SIZE_64 24
# define RESOLVER_FOOTPRINT_SIZE_32 21
# define RESOLVER_FOOTPRINT_SIZE_64 38
# define INIT_FOOTPRINT_SIZE_32 22
# define INIT_FOOTPRINT_SIZE_64 35
# define TERM_FOOTPRINT_SIZE_32 22
# define TERM_FOOTPRINT_SIZE_64 35
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
# define BASE_FOOTPRINT_SIZE_32 16
# define BASE_FOOTPRINT_SIZE_64 80
# define DEPENDENCY_FOOTPRINT_SIZE_32 20
# define DEPENDENCY_FOOTPRINT_SIZE_64 32
# define RESOLVER_FOOTPRINT_SIZE_32 24
# define RESOLVER_FOOTPRINT_SIZE_64 40
# define INIT_FOOTPRINT_SIZE_32 24
# define INIT_FOOTPRINT_SIZE_64 44
# define TERM_FOOTPRINT_SIZE_32 24
# define TERM_FOOTPRINT_SIZE_64 44
#endif

enum
{
  PROP_0,
  PROP_NAME,
  PROP_MODULE,
  PROP_RESOLVER,
  PROP_CACHE_FILE,
  PROP_PARENT
};

typedef struct _GumDarwinMapping GumDarwinMapping;
typedef struct _GumDarwinSymbolValue GumDarwinSymbolValue;

typedef struct _GumAccumulateFootprintContext GumAccumulateFootprintContext;

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

  gsize vm_size;
  gpointer runtime;
  GumAddress runtime_address;
  gsize runtime_vm_size;
  gsize runtime_file_size;
  gsize constructor_offset;
  gsize destructor_offset;

  GMappedFile * cache_file;
  gboolean cache_file_load_attempted;
  GSList * children;
  GHashTable * mappings;
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
};

static void gum_darwin_mapper_constructed (GObject * object);
static void gum_darwin_mapper_finalize (GObject * object);
static void gum_darwin_mapper_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_darwin_mapper_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);

static GumDarwinMapper * gum_darwin_mapper_new_from_file_with_parent (
    GumDarwinMapper * parent, const gchar * path,
    GumDarwinModuleResolver * resolver);
static GMappedFile * gum_darwin_mapper_try_load_cache_file (
    GumCpuType cpu_type);
static void gum_darwin_mapper_init_dependencies (GumDarwinMapper * self);
static void gum_darwin_mapper_init_footprint_budget (GumDarwinMapper * self);

static void gum_emit_runtime (GumDarwinMapper * self);
static gboolean gum_accumulate_bind_footprint_size (
    const GumDarwinBindDetails * details, gpointer user_data);
static gboolean gum_accumulate_init_footprint_size (
    const GumDarwinInitPointersDetails * details, gpointer user_data);
static gboolean gum_accumulate_term_footprint_size (
    const GumDarwinTermPointersDetails * details, gpointer user_data);

static gpointer gum_darwin_mapper_data_from_offset (GumDarwinMapper * self,
    guint64 offset);
static GumDarwinMapping * gum_darwin_mapper_dependency (GumDarwinMapper * self,
    gint ordinal);
static GumDarwinMapping * gum_darwin_mapper_resolve_dependency (
    GumDarwinMapper * self, const gchar * name);
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

static void gum_darwin_mapping_free (GumDarwinMapping * self);

G_DEFINE_TYPE (GumDarwinMapper, gum_darwin_mapper, G_TYPE_OBJECT)

static const gchar * gum_darwin_cache_file_arch_candidates_ia32[] =
    { "i386", NULL };
static const gchar * gum_darwin_cache_file_arch_candidates_amd64[] =
    { "x86_64", NULL };
static const gchar * gum_darwin_cache_file_arch_candidates_arm[] =
    { "armv7s", "armv7", "armv6", NULL };
static const gchar * gum_darwin_cache_file_arch_candidates_arm64[] =
    { "arm64", NULL };

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
      GUM_DARWIN_TYPE_MODULE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_RESOLVER,
      g_param_spec_object ("resolver", "Resolver", "Module resolver",
      GUM_DARWIN_TYPE_MODULE_RESOLVER, G_PARAM_READWRITE |
      G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_CACHE_FILE,
      g_param_spec_boxed ("cache-file", "CacheFile", "Shared cache file",
      G_TYPE_MAPPED_FILE, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PARENT,
      g_param_spec_object ("parent", "Parent", "Parent mapper",
      GUM_DARWIN_TYPE_MAPPER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_mapper_init (GumDarwinMapper * self)
{
  self->mapped = FALSE;
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

  gum_darwin_mapper_init_dependencies (self);
  gum_darwin_mapper_init_footprint_budget (self);
}

static void
gum_darwin_mapper_finalize (GObject * object)
{
  GumDarwinMapper * self = GUM_DARWIN_MAPPER (object);

  g_clear_pointer (&self->mappings, g_hash_table_unref);
  g_clear_pointer (&self->cache_file, g_mapped_file_unref);

  g_slist_free_full (self->children, g_object_unref);

  g_free (self->runtime);

  g_ptr_array_unref (self->dependencies);

  g_object_unref (self->module);

  g_object_unref (self->resolver);
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
    case PROP_CACHE_FILE:
      g_value_set_boxed (value, self->cache_file);
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
    case PROP_CACHE_FILE:
      g_clear_pointer (&self->cache_file, g_mapped_file_unref);
      self->cache_file = g_value_dup_boxed (value);
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
                                 GumDarwinModuleResolver * resolver)
{
  return gum_darwin_mapper_new_from_file_with_parent (NULL, path, resolver);
}

GumDarwinMapper *
gum_darwin_mapper_new_take_blob (const gchar * name,
                                 GBytes * blob,
                                 GumDarwinModuleResolver * resolver)
{
  GumDarwinModule * module;
  GumDarwinMapper * mapper;

  module = gum_darwin_module_new_from_blob (name, blob, resolver->task,
      resolver->cpu_type, resolver->page_size);

  mapper = g_object_new (GUM_DARWIN_TYPE_MAPPER,
      "name", name,
      "module", module,
      "resolver", resolver,
      NULL);

  g_object_unref (module);
  g_bytes_unref (blob);

  return mapper;
}

static GumDarwinMapper *
gum_darwin_mapper_new_from_file_with_parent (GumDarwinMapper * parent,
                                             const gchar * path,
                                             GumDarwinModuleResolver * resolver)
{
  GMappedFile * cache_file;
  GumDarwinModule * module;
  GumDarwinMapper * mapper;

  if (parent == NULL)
  {
    cache_file = gum_darwin_mapper_try_load_cache_file (resolver->cpu_type);
  }
  else
  {
    if (parent->cache_file == NULL && !parent->cache_file_load_attempted)
    {
      parent->cache_file =
          gum_darwin_mapper_try_load_cache_file (resolver->cpu_type);
      parent->cache_file_load_attempted = TRUE;
    }

    if (parent->cache_file != NULL)
      cache_file = g_mapped_file_ref (parent->cache_file);
    else
      cache_file = NULL;
  }

  module = gum_darwin_module_new_from_file (path, resolver->task,
      resolver->cpu_type, resolver->page_size, cache_file);

  mapper = g_object_new (GUM_DARWIN_TYPE_MAPPER,
      "name", path,
      "module", module,
      "resolver", resolver,
      "cache-file", cache_file,
      "parent", parent,
      NULL);

  if (parent == NULL)
  {
    mapper->cache_file_load_attempted = TRUE;
  }

  g_object_unref (module);
  if (cache_file != NULL)
    g_mapped_file_unref (cache_file);

  return mapper;
}

static GMappedFile *
gum_darwin_mapper_try_load_cache_file (GumCpuType cpu_type)
{
  GMappedFile * file;
  const gchar ** candidates, ** candidate;
  gint fd, result;

  switch (cpu_type)
  {
    case GUM_CPU_IA32:
      candidates = gum_darwin_cache_file_arch_candidates_ia32;
      break;
    case GUM_CPU_AMD64:
      candidates = gum_darwin_cache_file_arch_candidates_amd64;
      break;
    case GUM_CPU_ARM:
      candidates = gum_darwin_cache_file_arch_candidates_arm;
      break;
    case GUM_CPU_ARM64:
      candidates = gum_darwin_cache_file_arch_candidates_arm64;
      break;
    default:
      g_assert_not_reached ();
  }

  fd = -1;
  for (candidate = candidates; *candidate != NULL && fd == -1; candidate++)
  {
    gchar * path;

    path = g_strconcat (
        "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_",
        *candidate,
        NULL);
    fd = open (path, 0);
    g_free (path);
  }
  if (fd == -1)
    return NULL;

  result = fcntl (fd, F_NOCACHE, TRUE);
  g_assert (result == 0);

  file = g_mapped_file_new_from_fd (fd, TRUE, NULL);
  g_assert (file != NULL);

  close (fd);

  return file;
}

static void
gum_darwin_mapper_init_dependencies (GumDarwinMapper * self)
{
  GumDarwinModule * module = self->module;
  GPtrArray * dependencies;
  guint i;

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

    dependency = gum_darwin_mapper_resolve_dependency (self,
        g_ptr_array_index (dependencies, i));
    g_ptr_array_add (self->dependencies, dependency);
  }
}

static void
gum_darwin_mapper_init_footprint_budget (GumDarwinMapper * self)
{
  GumDarwinModule * module = self->module;
  gsize segments_size;
  GumAccumulateFootprintContext runtime;
  GArray * shared_segments;
  guint i;

  shared_segments = self->image->shared_segments;
  if (shared_segments->len == 0)
  {
    segments_size = 0;
    for (i = 0; i != module->segments->len; i++)
    {
      GumDarwinSegment * segment =
          &g_array_index (module->segments, GumDarwinSegment, i);

      segments_size += segment->vm_size;
      if (segment->vm_size % module->page_size != 0)
      {
        segments_size +=
            module->page_size - (segment->vm_size % module->page_size);
      }
    }
  }
  else
  {
    segments_size = self->image->size;
  }

  runtime.mapper = self;
  runtime.total = 0;
  gum_darwin_module_enumerate_binds (module,
      gum_accumulate_bind_footprint_size, &runtime);
  gum_darwin_module_enumerate_lazy_binds (module,
      gum_accumulate_bind_footprint_size, &runtime);
  gum_darwin_module_enumerate_init_pointers (module,
      gum_accumulate_init_footprint_size, &runtime);
  gum_darwin_module_enumerate_term_pointers (module,
      gum_accumulate_term_footprint_size, &runtime);
  if (module->pointer_size == 4)
  {
    runtime.total +=
        g_slist_length (self->children) * DEPENDENCY_FOOTPRINT_SIZE_32;
    runtime.total += BASE_FOOTPRINT_SIZE_32;
  }
  else
  {
    runtime.total +=
        g_slist_length (self->children) * DEPENDENCY_FOOTPRINT_SIZE_64;
    runtime.total += BASE_FOOTPRINT_SIZE_64;
  }

  self->runtime_vm_size = runtime.total;
  if (runtime.total % module->page_size != 0)
  {
    self->runtime_vm_size +=
        module->page_size - (runtime.total % module->page_size);
  }
  self->runtime_file_size = runtime.total;

  self->vm_size = segments_size + self->runtime_vm_size;
}

gsize
gum_darwin_mapper_size (GumDarwinMapper * self)
{
  gsize result;
  GSList * cur;

  result = self->vm_size;

  for (cur = self->children; cur != NULL; cur = cur->next)
  {
    GumDarwinMapper * child = cur->data;

    result += child->vm_size;
  }

  return result;
}

void
gum_darwin_mapper_map (GumDarwinMapper * self,
                       GumAddress base_address)
{
  GSList * cur;
  GumDarwinModule * module = self->module;
  guint i;
  mach_vm_address_t mapped_address;
  vm_prot_t cur_protection, max_protection;
  GArray * shared_segments;

  g_assert (!self->mapped);

  self->runtime_address = base_address;
  base_address += self->runtime_vm_size;

  for (cur = self->children; cur != NULL; cur = cur->next)
  {
    GumDarwinMapper * child = cur->data;

    gum_darwin_mapper_map (child, base_address);
    base_address += child->vm_size;
  }

  g_object_set (module, "base-address", base_address, NULL);

  gum_emit_runtime (self);

  gum_darwin_module_enumerate_rebases (module, gum_darwin_mapper_rebase, self);
  gum_darwin_module_enumerate_binds (module, gum_darwin_mapper_bind, self);
  gum_darwin_module_enumerate_lazy_binds (module, gum_darwin_mapper_bind, self);

  for (i = 0; i != module->segments->len; i++)
  {
    GumDarwinSegment * s =
        &g_array_index (module->segments, GumDarwinSegment, i);
    GumAddress segment_address;
    guint64 file_offset;

    segment_address = base_address + s->vm_address - module->preferred_address;
    file_offset =
        (s->file_offset != 0) ? s->file_offset - self->image->source_offset : 0;

    mapped_address = segment_address;
    mach_vm_remap (module->task, &mapped_address, s->file_size, 0,
        VM_FLAGS_OVERWRITE, mach_task_self (),
        (vm_offset_t) (self->image->data + file_offset), TRUE, &cur_protection,
        &max_protection, VM_INHERIT_COPY);
    mach_vm_protect (module->task, segment_address, s->vm_size, FALSE,
        s->protection);
  }

  shared_segments = self->image->shared_segments;
  for (i = 0; i != shared_segments->len; i++)
  {
    GumDarwinModuleImageSegment * s =
        &g_array_index (shared_segments, GumDarwinModuleImageSegment, i);

    mapped_address = base_address + s->offset;
    mach_vm_remap (module->task, &mapped_address, s->size, 0,
        VM_FLAGS_OVERWRITE, mach_task_self (),
        (vm_offset_t) (self->image->data + s->offset), TRUE, &cur_protection,
        &max_protection, VM_INHERIT_COPY);
    mach_vm_protect (module->task, base_address + s->offset, s->size, FALSE,
        s->protection);
  }

  if (gum_query_is_rwx_supported () || !gum_code_segment_is_supported ())
  {
    mach_vm_write (module->task, self->runtime_address,
        (vm_offset_t) self->runtime, self->runtime_file_size);
    mach_vm_protect (module->task, self->runtime_address, self->runtime_vm_size,
        FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
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
    mach_vm_remap (module->task, &mapped_address, self->runtime_vm_size, 0,
        VM_FLAGS_OVERWRITE, mach_task_self (), (mach_vm_address_t) scratch_page,
        FALSE, &cur_protection, &max_protection, VM_INHERIT_COPY);

    gum_code_segment_free (segment);
  }

  self->mapped = TRUE;
}

GumAddress
gum_darwin_mapper_constructor (GumDarwinMapper * self)
{
  g_assert (self->mapped);

  return self->runtime_address + self->constructor_offset;
}

GumAddress
gum_darwin_mapper_destructor (GumDarwinMapper * self)
{
  g_assert (self->mapped);

  return self->runtime_address + self->destructor_offset;
}

GumAddress
gum_darwin_mapper_resolve (GumDarwinMapper * self,
                           const gchar * symbol)
{
  gchar * mangled_symbol;
  GumDarwinSymbolValue value;
  gboolean success;

  g_assert (self->mapped);

  mangled_symbol = g_strconcat ("_", symbol, NULL);
  success = gum_darwin_mapper_resolve_symbol (self, self->module,
      mangled_symbol, &value);
  g_free (mangled_symbol);
  if (!success)
    return 0;
  else if (value.resolver != 0)
    return 0;

  return value.address;
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
gum_emit_runtime (GumDarwinMapper * self)
{
  GumDarwinModule * module = self->module;
  GumX86Writer cw;
  GumEmitX86Context ctx;
  GSList * children_reversed;

  self->runtime = g_malloc (self->runtime_file_size);

  gum_x86_writer_init (&cw, self->runtime);
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
      (GumDarwinFoundBindFunc) gum_emit_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_lazy_binds (module,
      (GumDarwinFoundBindFunc) gum_emit_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_init_pointers (module,
      (GumDarwinFoundInitPointersFunc) gum_emit_init_calls, &ctx);

  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, self->module->pointer_size);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_ret (&cw);

  self->destructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_REG_XSP, self->module->pointer_size);

  gum_darwin_module_enumerate_term_pointers (module,
      (GumDarwinFoundTermPointersFunc) gum_emit_term_calls, &ctx);
  children_reversed = g_slist_reverse (g_slist_copy (self->children));
  g_slist_foreach (children_reversed, (GFunc) gum_emit_child_destructor_call,
      &ctx);
  g_slist_free (children_reversed);

  gum_x86_writer_put_add_reg_imm (&cw, GUM_REG_XSP, self->module->pointer_size);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBP);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  g_assert_cmpint (gum_x86_writer_offset (&cw), <=, self->runtime_file_size);
  gum_x86_writer_free (&cw);
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

  dependency = gum_darwin_mapper_dependency (self, details->library_ordinal);
  success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value);
  if (!success || value.resolver == 0)
    return TRUE;

  entry = self->module->base_address + details->segment->vm_address +
      details->offset;

  gum_x86_writer_put_mov_reg_address (cw, GUM_REG_XCX, value.resolver);
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
  /* TODO: pass argc, argv, envp, apple, program vars */
  gum_x86_writer_put_call_reg (cw, GUM_REG_XAX);

  gum_x86_writer_put_add_reg_imm (cw, GUM_REG_XBP, self->module->pointer_size);
  gum_x86_writer_put_dec_reg (cw, GUM_REG_XBX);
  gum_x86_writer_put_jcc_short_label (cw, GUM_X86_JNZ, next_label, GUM_NO_HINT);

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
  gum_x86_writer_put_jcc_short_label (cw, GUM_X86_JNZ, next_label, GUM_NO_HINT);

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
};

static void gum_emit_arm_runtime (GumDarwinMapper * self);
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

static void gum_emit_arm64_runtime (GumDarwinMapper * self);
static void gum_emit_arm64_child_constructor_call (GumDarwinMapper * child,
    GumEmitArm64Context * ctx);
static void gum_emit_arm64_child_destructor_call (GumDarwinMapper * child,
    GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_resolve_if_needed (
    const GumDarwinBindDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_init_calls (
    const GumDarwinInitPointersDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_term_calls (
    const GumDarwinTermPointersDetails * details, GumEmitArm64Context * ctx);

static void
gum_emit_runtime (GumDarwinMapper * self)
{
  self->runtime = g_malloc (self->runtime_file_size);

  if (self->module->cpu_type == GUM_CPU_ARM)
    gum_emit_arm_runtime (self);
  else
    gum_emit_arm64_runtime (self);
}

static void
gum_emit_arm_runtime (GumDarwinMapper * self)
{
  GumDarwinModule * module = self->module;
  GumThumbWriter tw;
  GumEmitArmContext ctx;
  GSList * children_reversed;

  gum_thumb_writer_init (&tw, self->runtime);

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
      (GumDarwinFoundBindFunc) gum_emit_arm_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_lazy_binds (module,
      (GumDarwinFoundBindFunc) gum_emit_arm_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_init_pointers (module,
      (GumDarwinFoundInitPointersFunc) gum_emit_arm_init_calls, &ctx);

  gum_thumb_writer_put_pop_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_PC);

  self->destructor_offset = gum_thumb_writer_offset (&tw) + 1;
  gum_thumb_writer_put_push_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_LR);

  gum_darwin_module_enumerate_term_pointers (module,
      (GumDarwinFoundTermPointersFunc) gum_emit_arm_term_calls, &ctx);
  children_reversed = g_slist_reverse (g_slist_copy (self->children));
  g_slist_foreach (children_reversed,
      (GFunc) gum_emit_arm_child_destructor_call, &ctx);
  g_slist_free (children_reversed);

  gum_thumb_writer_put_pop_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_PC);

  gum_thumb_writer_flush (&tw);
  g_assert_cmpint (gum_thumb_writer_offset (&tw), <=, self->runtime_file_size);
  gum_thumb_writer_free (&tw);
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

  dependency = gum_darwin_mapper_dependency (self, details->library_ordinal);
  success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value);
  if (!success || value.resolver == 0)
    return TRUE;

  entry = self->module->base_address + details->segment->vm_address +
      details->offset;

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R1, value.resolver);
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
  GumThumbWriter * tw = ctx->tw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R4, details->address);
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R5, details->count);

  gum_thumb_writer_put_label (tw, next_label);

  gum_thumb_writer_put_ldr_reg_reg (tw, ARM_REG_R0, ARM_REG_R4);
  /* TODO: pass argc, argv, envp, apple, program vars */
  gum_thumb_writer_put_blx_reg (tw, ARM_REG_R0);

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
gum_emit_arm64_runtime (GumDarwinMapper * self)
{
  GumDarwinModule * module = self->module;
  GumArm64Writer aw;
  GumEmitArm64Context ctx;
  GSList * children_reversed;

  gum_arm64_writer_init (&aw, self->runtime);

  ctx.mapper = self;
  ctx.aw = &aw;

  if (self->parent == NULL)
  {
    /* atexit stub */
    gum_arm64_writer_put_ldr_reg_u64 (&aw, ARM64_REG_X0, 0);
    gum_arm64_writer_put_ret (&aw);
  }

  self->constructor_offset = gum_arm64_writer_offset (&aw);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_SP);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X21, ARM64_REG_X22);

  g_slist_foreach (self->children,
      (GFunc) gum_emit_arm64_child_constructor_call, &ctx);
  gum_darwin_module_enumerate_binds (module,
      (GumDarwinFoundBindFunc) gum_emit_arm64_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_lazy_binds (module,
      (GumDarwinFoundBindFunc) gum_emit_arm64_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_init_pointers (module,
      (GumDarwinFoundInitPointersFunc) gum_emit_arm64_init_calls, &ctx);

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
      (GumDarwinFoundTermPointersFunc) gum_emit_arm64_term_calls, &ctx);
  children_reversed = g_slist_reverse (g_slist_copy (self->children));
  g_slist_foreach (children_reversed,
      (GFunc) gum_emit_arm64_child_destructor_call, &ctx);
  g_slist_free (children_reversed);

  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X21, ARM64_REG_X22);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&aw);

  gum_arm64_writer_flush (&aw);
  g_assert_cmpint (gum_arm64_writer_offset (&aw), <=, self->runtime_file_size);
  gum_arm64_writer_free (&aw);
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
gum_emit_arm64_resolve_if_needed (const GumDarwinBindDetails * details,
                                  GumEmitArm64Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumArm64Writer * aw = ctx->aw;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;
  gboolean success;
  GumAddress entry;

  dependency = gum_darwin_mapper_dependency (self, details->library_ordinal);
  success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value);
  if (!success || value.resolver == 0)
    return TRUE;

  entry = self->module->base_address + details->segment->vm_address +
      details->offset;

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X1, value.resolver);
  gum_arm64_writer_put_blr_reg (aw, ARM64_REG_X1);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X1, details->addend);
  gum_arm64_writer_put_add_reg_reg_reg (aw, ARM64_REG_X0, ARM64_REG_X0,
      ARM64_REG_X1);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X1, entry);
  gum_arm64_writer_put_str_reg_reg_offset (aw, ARM64_REG_X0, ARM64_REG_X1, 0);

  return TRUE;
}

static gboolean
gum_emit_arm64_init_calls (const GumDarwinInitPointersDetails * details,
                           GumEmitArm64Context * ctx)
{
  GumArm64Writer * aw = ctx->aw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X19, details->address);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X20, details->count);

  gum_arm64_writer_put_label (aw, next_label);

  gum_arm64_writer_put_ldr_reg_reg_offset (aw, ARM64_REG_X0, ARM64_REG_X19, 0);
  /* TODO: pass argc, argv, envp, apple, program vars */
  gum_arm64_writer_put_blr_reg (aw, ARM64_REG_X0);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X19, ARM64_REG_X19, 8);
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
  gum_arm64_writer_put_blr_reg (aw, ARM64_REG_X0);

  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_X19, ARM64_REG_X19, 8);
  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_X20, ARM64_REG_X20, 1);
  gum_arm64_writer_put_cbnz_reg_label (aw, ARM64_REG_X20, next_label);

  return TRUE;
}

#endif

static gboolean
gum_accumulate_bind_footprint_size (const GumDarwinBindDetails * details,
                                    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;
  GumDarwinMapper * self = ctx->mapper;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;

  dependency = gum_darwin_mapper_dependency (self, details->library_ordinal);
  if (gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value))
  {
    if (value.resolver != 0)
    {
      ctx->total += (self->module->pointer_size == 4)
          ? RESOLVER_FOOTPRINT_SIZE_32
          : RESOLVER_FOOTPRINT_SIZE_64;
    }
  }

  return TRUE;
}

static gboolean
gum_accumulate_init_footprint_size (
    const GumDarwinInitPointersDetails * details,
    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;

  ctx->total += (ctx->mapper->module->pointer_size == 4)
      ? INIT_FOOTPRINT_SIZE_32
      : INIT_FOOTPRINT_SIZE_64;

  return TRUE;
}

static gboolean
gum_accumulate_term_footprint_size (
    const GumDarwinTermPointersDetails * details,
    gpointer user_data)
{
  GumAccumulateFootprintContext * ctx = user_data;

  ctx->total += (ctx->mapper->module->pointer_size == 4)
      ? TERM_FOOTPRINT_SIZE_32
      : TERM_FOOTPRINT_SIZE_64;

  return TRUE;
}

static gpointer
gum_darwin_mapper_data_from_offset (GumDarwinMapper * self,
                                    guint64 offset)
{
  GumDarwinModuleImage * image = self->image;
  guint64 source_offset = image->source_offset;

  if (source_offset != 0)
  {
    g_assert_cmpint (offset, >=, source_offset);
    g_assert_cmpint (offset, <, source_offset + image->shared_offset +
        image->shared_size);
  }
  else
  {
    g_assert_cmpint (offset, <, image->size);
  }

  return image->data + (offset - source_offset);
}

static GumDarwinMapping *
gum_darwin_mapper_dependency (GumDarwinMapper * self,
                              gint ordinal)
{
  GumDarwinMapping * result;

  switch (ordinal)
  {
    case BIND_SPECIAL_DYLIB_SELF:
      result = gum_darwin_mapper_resolve_dependency (self, self->module->name);
      break;
    case BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
    case BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
      g_assert_not_reached ();
      break;
    default:
      result = g_ptr_array_index (self->dependencies, ordinal - 1);
      g_assert (result != NULL);
      break;
  }

  return result;
}

static GumDarwinMapping *
gum_darwin_mapper_resolve_dependency (GumDarwinMapper * self,
                                      const gchar * name)
{
  GumDarwinModuleResolver * resolver = self->resolver;
  GumDarwinMapping * mapping;

  if (self->parent != NULL)
    return gum_darwin_mapper_resolve_dependency (self->parent, name);

  mapping = g_hash_table_lookup (self->mappings, name);

  if (mapping == NULL)
  {
    GumDarwinModule * module = NULL;
    gchar * candidate;

    if (resolver->sysroot != NULL)
    {
      candidate = g_strconcat (resolver->sysroot, "/", name, NULL);
      module = gum_darwin_module_resolver_find_module (resolver, candidate);
      g_free (candidate);

      if (module == NULL && strcmp (name, "/usr/lib/libSystem.B.dylib") == 0)
      {
        candidate = g_strconcat (resolver->sysroot, "/usr/lib/libSystem.dylib",
            NULL);
        module = gum_darwin_module_resolver_find_module (resolver, candidate);
        g_free (candidate);
      }

      if (module == NULL && g_str_has_prefix (name, "/usr/lib/system/"))
      {
        candidate = g_strconcat (resolver->sysroot,
            "/usr/lib/system/introspection/", name + 16, NULL);
        module = gum_darwin_module_resolver_find_module (resolver, candidate);
        g_free (candidate);
      }
    }

    if (module == NULL)
    {
      module = gum_darwin_module_resolver_find_module (resolver, name);
    }

    if (module == NULL && g_str_has_prefix (name, "/usr/lib/system/"))
    {
      candidate = g_strconcat ("/usr/lib/system/introspection/", name + 16,
          NULL);
      module = gum_darwin_module_resolver_find_module (resolver, candidate);
      g_free (candidate);
    }

    if (module != NULL)
    {
      mapping = gum_darwin_mapper_add_existing_mapping (self, module);
    }
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
        self->resolver);

    mapping = g_hash_table_lookup (self->mappings, full_name);
    g_assert (mapping != NULL);

    if (resolver->sysroot != NULL)
      gum_darwin_mapper_add_alias_mapping (self, name, mapping);

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
      value->address = self->runtime_address;
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
    if (gum_darwin_module_lacks_exports_for_reexports (module))
    {
      GPtrArray * reexports = module->reexports;
      guint i;

      for (i = 0; i != reexports->len; i++)
      {
        GumDarwinMapping * target;

        target = gum_darwin_mapper_resolve_dependency (self,
            g_ptr_array_index (reexports, i));
        if (gum_darwin_mapper_resolve_symbol (self, target->module, name,
            value))
        {
          return TRUE;
        }
      }
    }

    return FALSE;
  }

  if ((details.flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0)
  {
    const gchar * target_name;
    GumDarwinMapping * target;

    target_name = gum_darwin_module_dependency (module,
        details.reexport_library_ordinal);
    target = gum_darwin_mapper_resolve_dependency (self, target_name);
    return gum_darwin_mapper_resolve_symbol (self, target->module,
        details.reexport_symbol, value);
  }

  switch (details.flags & EXPORT_SYMBOL_FLAGS_KIND_MASK)
  {
    case EXPORT_SYMBOL_FLAGS_KIND_REGULAR:
      if ((details.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0)
      {
        /* XXX: we ignore interposing */
        value->address = module->base_address + details.stub;
        value->resolver = module->base_address + details.resolver;
        return TRUE;
      }
      value->address = module->base_address + details.offset;
      value->resolver = 0;
      return TRUE;
    case EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL:
      value->address = module->base_address + details.offset;
      value->resolver = 0;
      return TRUE;
    case GUM_DARWIN_EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE:
      value->address = details.offset;
      value->resolver = 0;
      return TRUE;
    default:
      g_assert_not_reached ();
      break;
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
  GumDarwinMapper * self = user_data;
  gpointer entry;

  g_assert_cmpint (details->offset, <, details->segment->file_size);

  entry = gum_darwin_mapper_data_from_offset (self,
      details->segment->file_offset + details->offset);

  switch (details->type)
  {
    case REBASE_TYPE_POINTER:
    case REBASE_TYPE_TEXT_ABSOLUTE32:
      if (self->module->pointer_size == 4)
        *((guint32 *) entry) += (guint32) details->slide;
      else
        *((guint64 *) entry) += (guint64) details->slide;
      break;
    case REBASE_TYPE_TEXT_PCREL32:
    default:
      g_assert_not_reached ();
  }

  return TRUE;
}

static gboolean
gum_darwin_mapper_bind (const GumDarwinBindDetails * details,
                        gpointer user_data)
{
  GumDarwinMapper * self = user_data;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;
  gboolean success, is_weak_import;
  gpointer entry;

  g_assert_cmpint (details->type, ==, BIND_TYPE_POINTER);

  dependency = gum_darwin_mapper_dependency (self, details->library_ordinal);
  success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value);
  is_weak_import = (details->symbol_flags & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0;
  if (!success && !is_weak_import && self->resolver->sysroot != NULL &&
      g_str_has_suffix (details->symbol_name, "$INODE64"))
  {
    gchar * plain_name;

    plain_name = g_strndup (details->symbol_name,
        strlen (details->symbol_name) - 8);
    success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
        plain_name, &value);
    g_free (plain_name);
  }
  g_assert (success || is_weak_import);

  if (success)
    value.address += details->addend;

  entry = gum_darwin_mapper_data_from_offset (self,
      details->segment->file_offset + details->offset);
  if (self->module->pointer_size == 4)
    *((guint32 *) entry) = value.address;
  else
    *((guint64 *) entry) = value.address;

  return TRUE;
}

static void
gum_darwin_mapping_free (GumDarwinMapping * self)
{
  g_object_unref (self->module);
  g_slice_free (GumDarwinMapping, self);
}
