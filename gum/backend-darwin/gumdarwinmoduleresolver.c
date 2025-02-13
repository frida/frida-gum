/*
 * Copyright (C) 2015-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gumdarwinmoduleresolver.h"

#include "gumdarwin-priv.h"
#include "gummodule-darwin.h"
#include "gum/gumdarwin.h"

#include <stdlib.h>
#include <mach-o/loader.h>

#define MAX_MACH_HEADER_SIZE (64 * 1024)

#define GUM_DARWIN_MODULE_RESOLVER_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_DARWIN_MODULE_RESOLVER_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

typedef struct _GumCollectModulesContext GumCollectModulesContext;

enum
{
  PROP_0,
  PROP_TASK
};

struct _GumCollectModulesContext
{
  GumDarwinModuleResolver * resolver;
  GPtrArray * modules;
};

static void gum_darwin_module_resolver_dispose (GObject * object);
static void gum_darwin_module_resolver_finalize (GObject * object);
static void gum_darwin_module_resolver_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_darwin_module_resolver_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);
static void gum_darwin_module_resolver_rebuild_indexes (
    GumDarwinModuleResolver * self, GPtrArray * latest_modules);

static void gum_collect_modules (GumCollectModulesContext * ctx);
static void gum_collect_modules_forensically (GumCollectModulesContext * ctx);
static gboolean gum_collect_range_of_potential_modules (
    const GumRangeDetails * details, gpointer user_data);
static gboolean gum_collect_modules_in_range (const GumMemoryRange * range,
    GumCollectModulesContext * ctx);

static gint gum_darwin_module_compare_base (GumDarwinModule ** lhs_module,
    GumDarwinModule ** rhs_module);
static gint gum_darwin_module_compare_to_key (const GumAddress * key_ptr,
    GumDarwinModule ** member);

G_DEFINE_TYPE (GumDarwinModuleResolver,
               gum_darwin_module_resolver,
               G_TYPE_OBJECT)

static void
gum_darwin_module_resolver_class_init (GumDarwinModuleResolverClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_darwin_module_resolver_dispose;
  object_class->finalize = gum_darwin_module_resolver_finalize;
  object_class->get_property = gum_darwin_module_resolver_get_property;
  object_class->set_property = gum_darwin_module_resolver_set_property;

  g_object_class_install_property (object_class, PROP_TASK,
      g_param_spec_uint ("task", "task", "Mach task", 0, G_MAXUINT,
      MACH_PORT_NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_module_resolver_init (GumDarwinModuleResolver * self)
{
  g_mutex_init (&self->mutex);

  self->state = GUM_DARWIN_MODULE_RESOLVER_CREATED;
}

static void
gum_darwin_module_resolver_dispose (GObject * object)
{
  GumDarwinModuleResolver * self = GUM_DARWIN_MODULE_RESOLVER (object);

  gum_darwin_module_resolver_set_dynamic_lookup_handler (self, NULL, NULL,
      NULL);

  if (self->load_data_destroy != NULL)
    self->load_data_destroy (self->load_data);
  self->load_func = NULL;
  self->load_data = NULL;
  self->load_data_destroy = NULL;

  G_OBJECT_CLASS (gum_darwin_module_resolver_parent_class)->dispose (object);
}

static void
gum_darwin_module_resolver_finalize (GObject * object)
{
  GumDarwinModuleResolver * self = GUM_DARWIN_MODULE_RESOLVER (object);

  g_free (self->sysroot);

  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_darwin_module_resolver_parent_class)->finalize (object);
}

static void
gum_darwin_module_resolver_get_property (GObject * object,
                                         guint property_id,
                                         GValue * value,
                                         GParamSpec * pspec)
{
  GumDarwinModuleResolver * self = GUM_DARWIN_MODULE_RESOLVER (object);

  switch (property_id)
  {
    case PROP_TASK:
      g_value_set_uint (value, self->task);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_darwin_module_resolver_set_property (GObject * object,
                                         guint property_id,
                                         const GValue * value,
                                         GParamSpec * pspec)
{
  GumDarwinModuleResolver * self = GUM_DARWIN_MODULE_RESOLVER (object);

  switch (property_id)
  {
    case PROP_TASK:
      self->task = g_value_get_uint (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinModuleResolver *
gum_darwin_module_resolver_new (mach_port_t task,
                                GError ** error)
{
  GumDarwinModuleResolver * resolver;

  resolver = g_object_new (GUM_DARWIN_TYPE_MODULE_RESOLVER,
      "task", task,
      NULL);

  if (!gum_darwin_module_resolver_load (resolver, error))
  {
    g_object_unref (resolver);
    resolver = NULL;
  }

  return resolver;
}

GumDarwinModuleResolver *
gum_darwin_module_resolver_new_with_loader (
    mach_port_t task,
    GumDarwinModuleResolverLoadFunc func,
    gpointer data,
    GDestroyNotify data_destroy,
    GError ** error)
{
  GumDarwinModuleResolver * resolver;

  resolver = g_object_new (GUM_DARWIN_TYPE_MODULE_RESOLVER,
      "task", task,
      NULL);
  resolver->load_func = func;
  resolver->load_data = data;
  resolver->load_data_destroy = data_destroy;

  if (!gum_darwin_module_resolver_load (resolver, error))
  {
    g_object_unref (resolver);
    resolver = NULL;
  }

  return resolver;
}

gboolean
gum_darwin_module_resolver_load (GumDarwinModuleResolver * self,
                                 GError ** error)
{
  gboolean success = FALSE;
  GumCollectModulesContext ctx;
  int pid;

  GUM_DARWIN_MODULE_RESOLVER_LOCK (self);

  if (self->state != GUM_DARWIN_MODULE_RESOLVER_CREATED)
    goto beach;

  ctx.resolver = self;
  ctx.modules = g_ptr_array_new_full (64, g_object_unref);

  if (!gum_darwin_query_ptrauth_support (self->task, &self->ptrauth_support))
    goto invalid_task;

  if (!gum_darwin_query_page_size (self->task, &self->page_size))
    goto invalid_task;

  if (pid_for_task (self->task, &pid) != KERN_SUCCESS)
    goto invalid_task;

  if (!gum_darwin_cpu_type_from_pid (pid, &self->cpu_type))
    goto invalid_task;

  if (self->load_func == NULL)
  {
    gum_collect_modules (&ctx);
    if (ctx.modules->len == 0)
      goto invalid_task;

    self->load_func = (GumDarwinModuleResolverLoadFunc) g_ptr_array_ref;
    self->load_data = g_ptr_array_ref (ctx.modules);
    self->load_data_destroy = (GDestroyNotify) g_ptr_array_unref;
  }

  self->state = GUM_DARWIN_MODULE_RESOLVER_LOADED;

  success = TRUE;
  goto beach;

invalid_task:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Process is dead");
    goto beach;
  }
beach:
  {
    g_ptr_array_unref (ctx.modules);

    GUM_DARWIN_MODULE_RESOLVER_UNLOCK (self);

    return success;
  }
}

void
gum_darwin_module_resolver_set_dynamic_lookup_handler (
    GumDarwinModuleResolver * self,
    GumDarwinModuleResolverLookupFunc func,
    gpointer data,
    GDestroyNotify data_destroy)
{
  if (self->lookup_dynamic_data_destroy != NULL)
    self->lookup_dynamic_data_destroy (self->lookup_dynamic_data);

  self->lookup_dynamic_func = func;
  self->lookup_dynamic_data = data;
  self->lookup_dynamic_data_destroy = data_destroy;
}

void
gum_darwin_module_resolver_fetch_modules (GumDarwinModuleResolver * self,
                                          GPtrArray ** sorted_modules,
                                          GHashTable ** module_by_name)
{
  GPtrArray * latest;

  latest = self->load_func (self->load_data);

  GUM_DARWIN_MODULE_RESOLVER_LOCK (self);

  if (latest == self->last_modules)
  {
    g_ptr_array_unref (latest);
  }
  else
  {
    gum_darwin_module_resolver_rebuild_indexes (self, latest);
    g_clear_pointer (&self->last_modules, g_ptr_array_unref);
    self->last_modules = latest;
  }

  if (sorted_modules != NULL)
    *sorted_modules = g_ptr_array_ref (self->sorted_modules);

  if (module_by_name != NULL)
    *module_by_name = g_hash_table_ref (self->module_by_name);

  GUM_DARWIN_MODULE_RESOLVER_UNLOCK (self);
}

static void
gum_darwin_module_resolver_rebuild_indexes (GumDarwinModuleResolver * self,
                                            GPtrArray * latest_modules)
{
  GPtrArray * sorted;
  GHashTable * by_name;
  gsize sysroot_length;
  guint i;

  sorted = g_ptr_array_new_full (latest_modules->len, g_object_unref);
  by_name = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  sysroot_length = 0;
  for (i = 0; i != latest_modules->len; i++)
  {
    GumModule * mod;
    const gchar * path;

    mod = g_ptr_array_index (latest_modules, i);
    path = gum_module_get_path (mod);

    if (g_str_has_suffix (path, "/usr/lib/dyld_sim"))
    {
      sysroot_length = strlen (path) - 17;
      g_free (self->sysroot);
      self->sysroot = g_strndup (path, sysroot_length);
      break;
    }
  }

  for (i = 0; i != latest_modules->len; i++)
  {
    GumModule * mod;
    const gchar * path;

    mod = g_ptr_array_index (latest_modules, i);
    g_ptr_array_add (sorted, g_object_ref (mod));

    path = gum_module_get_path (mod);

    g_hash_table_insert (by_name, g_strdup (gum_module_get_name (mod)), mod);
    g_hash_table_insert (by_name, g_strdup (path), mod);
    if (self->sysroot != NULL && g_str_has_prefix (path, self->sysroot))
      g_hash_table_insert (by_name, g_strdup (path + sysroot_length), mod);
  }

  g_ptr_array_sort (sorted, (GCompareFunc) gum_darwin_module_compare_base);

  g_clear_pointer (&self->sorted_modules, g_ptr_array_unref);
  self->sorted_modules = sorted;

  g_clear_pointer (&self->module_by_name, g_hash_table_unref);
  self->module_by_name = by_name;
}

GumDarwinModule *
gum_darwin_module_resolver_find_module_by_name (GumDarwinModuleResolver * self,
                                                const gchar * name)
{
  GumDarwinModule * result;
  GHashTable * module_by_name;
  GumNativeModule * module;

  gum_darwin_module_resolver_fetch_modules (self, NULL, &module_by_name);

  module = g_hash_table_lookup (module_by_name, name);
  if (module == NULL && g_str_has_prefix (name, "/usr/lib/system/"))
  {
    gchar * alias =
        g_strconcat ("/usr/lib/system/introspection/", name + 16, NULL);

    module = g_hash_table_lookup (module_by_name, alias);

    g_free (alias);
  }

  result = (module != NULL)
      ? g_object_ref (_gum_native_module_get_darwin_module (module))
      : NULL;

  g_hash_table_unref (module_by_name);

  return result;
}

GumDarwinModule *
gum_darwin_module_resolver_find_module_by_address (
    GumDarwinModuleResolver * self,
    GumAddress address)
{
  GumDarwinModule * result;
  GPtrArray * modules;
  GumAddress bare_address;
  GumDarwinModule ** entry;

  gum_darwin_module_resolver_fetch_modules (self, &modules, NULL);
  g_ptr_array_unref (modules);

  bare_address = gum_strip_code_address (address);

  entry = bsearch (&bare_address, modules->pdata, modules->len,
      sizeof (GumModule *), (GCompareFunc) gum_darwin_module_compare_to_key);
  result = (entry != NULL) ? g_object_ref (*entry) : NULL;

  g_ptr_array_unref (modules);

  return result;
}

gboolean
gum_darwin_module_resolver_find_export (GumDarwinModuleResolver * self,
                                        GumDarwinModule * module,
                                        const gchar * symbol,
                                        GumExportDetails * details)
{
  gchar * mangled_symbol;
  gboolean success;

  mangled_symbol = g_strconcat ("_", symbol, NULL);
  success = gum_darwin_module_resolver_find_export_by_mangled_name (self,
      module, mangled_symbol, details);
  g_free (mangled_symbol);

  return success;
}

GumAddress
gum_darwin_module_resolver_find_export_address (GumDarwinModuleResolver * self,
                                                GumDarwinModule * module,
                                                const gchar * symbol)
{
  GumExportDetails details;

  if (!gum_darwin_module_resolver_find_export (self, module, symbol, &details))
    return 0;

  return details.address;
}

gboolean
gum_darwin_module_resolver_find_export_by_mangled_name (
    GumDarwinModuleResolver * self,
    GumDarwinModule * module,
    const gchar * symbol,
    GumExportDetails * details)
{
  GumDarwinModule * m;
  GumDarwinExportDetails d;
  gboolean found;

  found = gum_darwin_module_resolve_export (module, symbol, &d);
  if (found)
  {
    m = module;
  }
  else if (gum_darwin_module_get_lacks_exports_for_reexports (module))
  {
    GPtrArray * reexports = module->reexports;
    guint i;

    for (i = 0; !found && i != reexports->len; i++)
    {
      GumDarwinModule * reexport;

      reexport = gum_darwin_module_resolver_find_module_by_name (self,
          g_ptr_array_index (reexports, i));
      if (reexport != NULL)
      {
        found = gum_darwin_module_resolve_export (reexport, symbol, &d);
        if (found)
          m = reexport;

        g_object_unref (reexport);
      }
    }

    if (!found)
      return FALSE;
  }
  else
  {
    return FALSE;
  }

  return gum_darwin_module_resolver_resolve_export (self, m, &d, details);
}

gboolean
gum_darwin_module_resolver_resolve_export (
    GumDarwinModuleResolver * self,
    GumDarwinModule * module,
    const GumDarwinExportDetails * export,
    GumExportDetails * result)
{
  if ((export->flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0)
  {
    const gchar * target_module_name;
    GumDarwinModule * target_module;
    gboolean is_reexporting_itself, success;

    target_module_name = gum_darwin_module_get_dependency_by_ordinal (module,
        export->reexport_library_ordinal);
    target_module = gum_darwin_module_resolver_find_module_by_name (self,
        target_module_name);
    if (target_module == NULL)
      return FALSE;

    is_reexporting_itself = (target_module == module &&
        strcmp (export->reexport_symbol, export->name) == 0);
    if (is_reexporting_itself)
    {
      /*
       * Happens with a few of the Security.framework exports on High Sierra
       * beta 4, and seems like a bug given that dlsym() crashes with a
       * stack-overflow when asked to resolve these.
       */
      success = FALSE;
    }
    else
    {
      success = gum_darwin_module_resolver_find_export_by_mangled_name (self,
          target_module, export->reexport_symbol, result);
    }

    g_object_unref (target_module);

    return success;
  }

  result->name = gum_symbol_name_from_darwin (export->name);

  switch (export->flags & GUM_DARWIN_EXPORT_KIND_MASK)
  {
    case GUM_DARWIN_EXPORT_REGULAR:
      if ((export->flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0)
      {
        /* XXX: we ignore resolver and interposing */
        result->address = module->base_address + export->stub;
      }
      else
      {
        result->address = module->base_address + export->offset;
      }
      break;
    case GUM_DARWIN_EXPORT_THREAD_LOCAL:
      result->address = module->base_address + export->offset;
      break;
    case GUM_DARWIN_EXPORT_ABSOLUTE:
      result->address = export->offset;
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  result->type =
      gum_darwin_module_is_address_in_text_section (module, result->address)
      ? GUM_EXPORT_FUNCTION
      : GUM_EXPORT_VARIABLE;

  if (result->type == GUM_EXPORT_FUNCTION &&
      self->ptrauth_support == GUM_PTRAUTH_SUPPORTED)
  {
    result->address = gum_sign_code_address (result->address);
  }

  return TRUE;
}

GumAddress
gum_darwin_module_resolver_find_dynamic_address (GumDarwinModuleResolver * self,
                                                 const gchar * symbol)
{
  if (self->lookup_dynamic_func != NULL)
    return self->lookup_dynamic_func (symbol, self->lookup_dynamic_data);

  return 0;
}

static void
gum_collect_modules (GumCollectModulesContext * ctx)
{
  mach_port_t task = ctx->resolver->task;
  GumDarwinAllImageInfos infos;
  gboolean inprocess;
  const gchar * sysroot;
  guint sysroot_size;
  gsize i;
  gpointer info_array, info_array_malloc_data = NULL;
  gpointer header_data, header_data_end, header_malloc_data = NULL;
  const guint header_data_initial_size = 4096;
  gchar * file_path, * file_path_malloc_data = NULL;
  gboolean carry_on = TRUE;

  if (!gum_darwin_query_all_image_infos (task, &infos))
    goto beach;

  if (infos.info_array_address == 0)
    goto fallback;

  inprocess = task == mach_task_self ();

  sysroot = inprocess ? gum_darwin_query_sysroot () : NULL;
  sysroot_size = (sysroot != NULL) ? strlen (sysroot) : 0;

  if (inprocess)
  {
    info_array = GSIZE_TO_POINTER (infos.info_array_address);
  }
  else
  {
    info_array = gum_darwin_read (task, infos.info_array_address,
        infos.info_array_size, NULL);
    info_array_malloc_data = info_array;
  }

  for (i = 0; i != infos.info_array_count + 1 && carry_on; i++)
  {
    GumAddress load_address;
    struct mach_header * header;
    gpointer first_command, p;
    guint cmd_index;
    GumMemoryRange dylib_range;
    const gchar * path;

    if (i != infos.info_array_count)
    {
      GumAddress file_path_address;

      if (infos.format == TASK_DYLD_ALL_IMAGE_INFO_64)
      {
        DyldImageInfo64 * info = info_array + (i * DYLD_IMAGE_INFO_64_SIZE);
        load_address = info->image_load_address;
        file_path_address = info->image_file_path;
      }
      else
      {
        DyldImageInfo32 * info = info_array + (i * DYLD_IMAGE_INFO_32_SIZE);
        load_address = info->image_load_address;
        file_path_address = info->image_file_path;
      }

      if (inprocess)
      {
        header_data = GSIZE_TO_POINTER (load_address);

        file_path = GSIZE_TO_POINTER (file_path_address);
      }
      else
      {
        header_data = gum_darwin_read (task, load_address,
            header_data_initial_size, NULL);
        header_malloc_data = header_data;

        if (((file_path_address + MAXPATHLEN + 1) & ~((GumAddress) 4095))
            == load_address)
        {
          file_path = header_data + (file_path_address - load_address);
        }
        else
        {
          file_path = (gchar *) gum_darwin_read (task, file_path_address,
              MAXPATHLEN + 1, NULL);
          file_path_malloc_data = file_path;
        }
      }
      if (header_data == NULL || file_path == NULL)
        goto beach;
    }
    else
    {
      load_address = infos.dyld_image_load_address;

      if (inprocess)
      {
        header_data = GSIZE_TO_POINTER (load_address);
      }
      else
      {
        header_data = gum_darwin_read (task, load_address,
            header_data_initial_size, NULL);
        header_malloc_data = header_data;
      }
      if (header_data == NULL)
        goto beach;

      file_path = "/usr/lib/dyld";
    }

    header_data_end = header_data + header_data_initial_size;

    header = (struct mach_header *) header_data;
    if (infos.format == TASK_DYLD_ALL_IMAGE_INFO_64)
      first_command = header_data + sizeof (struct mach_header_64);
    else
      first_command = header_data + sizeof (struct mach_header);

    dylib_range.base_address = load_address;
    dylib_range.size = 4096;

    p = first_command;
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = p;

      if (!inprocess)
      {
        while (p + sizeof (struct load_command) > header_data_end ||
            p + lc->cmdsize > header_data_end)
        {
          gsize current_offset, new_size;

          if (file_path_malloc_data == NULL)
          {
            file_path_malloc_data = g_strdup (file_path);
            file_path = file_path_malloc_data;
          }

          current_offset = p - header_data;
          new_size = (header_data_end - header_data) + 4096;

          g_free (header_malloc_data);
          header_data = gum_darwin_read (task, load_address, new_size, NULL);
          header_malloc_data = header_data;
          if (header_data == NULL)
            goto beach;
          header_data_end = header_data + new_size;

          header = (struct mach_header *) header_data;

          p = header_data + current_offset;
          lc = (struct load_command *) p;

          first_command = NULL;
        }
      }

      if (lc->cmd == LC_SEGMENT)
      {
        struct segment_command * sc = p;
        if (strcmp (sc->segname, "__TEXT") == 0)
        {
          dylib_range.size = sc->vmsize;
          break;
        }
      }
      else if (lc->cmd == LC_SEGMENT_64)
      {
        struct segment_command_64 * sc = p;
        if (strcmp (sc->segname, "__TEXT") == 0)
        {
          dylib_range.size = sc->vmsize;
          break;
        }
      }

      p += lc->cmdsize;
    }

    path = file_path;
    if (sysroot != NULL && g_str_has_prefix (path, sysroot))
      path += sysroot_size;

    g_ptr_array_add (ctx->modules,
        _gum_native_module_make (path, &dylib_range, ctx->resolver));

    g_free (file_path_malloc_data);
    file_path_malloc_data = NULL;
    g_free (header_malloc_data);
    header_malloc_data = NULL;
  }

  goto beach;

fallback:
  gum_collect_modules_forensically (ctx);

beach:
  g_free (file_path_malloc_data);
  g_free (header_malloc_data);
  g_free (info_array_malloc_data);

  return;
}

static void
gum_collect_modules_forensically (GumCollectModulesContext * ctx)
{
  GArray * ranges;
  guint i;

  ranges = g_array_sized_new (FALSE, FALSE, sizeof (GumMemoryRange), 64);

  gum_darwin_enumerate_ranges (ctx->resolver->task, GUM_PAGE_RX,
      gum_collect_range_of_potential_modules, ranges);

  for (i = 0; i != ranges->len; i++)
  {
    GumMemoryRange * r = &g_array_index (ranges, GumMemoryRange, i);
    if (!gum_collect_modules_in_range (r, ctx))
      break;
  }

  g_array_unref (ranges);
}

static gboolean
gum_collect_range_of_potential_modules (const GumRangeDetails * details,
                                        gpointer user_data)
{
  GArray * ranges = user_data;

  g_array_append_val (ranges, *(details->range));

  return TRUE;
}

static gboolean
gum_collect_modules_in_range (const GumMemoryRange * range,
                              GumCollectModulesContext * ctx)
{
  GumAddress address = range->base_address;
  gsize remaining = range->size;
  mach_port_t task = ctx->resolver->task;
  gboolean carry_on = TRUE;
  const guint alignment = 4096;

  do
  {
    struct mach_header * header;
    gboolean is_dylib;
    guint8 * chunk;
    gsize chunk_size;
    guint8 * first_command, * p;
    guint cmd_index;
    GumMemoryRange dylib_range;

    header = (struct mach_header *) gum_darwin_read (task,
        address, sizeof (struct mach_header), NULL);
    if (header == NULL)
      return TRUE;
    is_dylib = (header->magic == MH_MAGIC || header->magic == MH_MAGIC_64) &&
        header->filetype == MH_DYLIB;
    g_free (header);

    if (!is_dylib)
    {
      address += alignment;
      remaining -= alignment;
      continue;
    }

    chunk = gum_darwin_read (task,
        address, MIN (MAX_MACH_HEADER_SIZE, remaining), &chunk_size);
    if (chunk == NULL)
      return TRUE;

    header = (struct mach_header *) chunk;
    if (header->magic == MH_MAGIC)
      first_command = chunk + sizeof (struct mach_header);
    else
      first_command = chunk + sizeof (struct mach_header_64);

    dylib_range.base_address = address;
    dylib_range.size = alignment;

    p = first_command;
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = (struct load_command *) p;

      if (lc->cmd == GUM_LC_SEGMENT)
      {
        gum_segment_command_t * sc = (gum_segment_command_t *) lc;
        if (strcmp (sc->segname, "__TEXT") == 0)
        {
          dylib_range.size = sc->vmsize;
          break;
        }
      }

      p += lc->cmdsize;
    }

    p = first_command;
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = (struct load_command *) p;

      if (lc->cmd == LC_ID_DYLIB)
      {
        const struct dylib * dl = &((struct dylib_command *) lc)->dylib;
        const gchar * raw_path;
        guint raw_path_len;
        gchar * path;

        raw_path = (gchar *) p + dl->name.offset;
        raw_path_len = lc->cmdsize - sizeof (struct dylib_command);
        path = g_strndup (raw_path, raw_path_len);

        g_ptr_array_add (ctx->modules,
            _gum_native_module_make (path, &dylib_range, ctx->resolver));

        g_free (path);

        break;
      }

      p += lc->cmdsize;
    }

    g_free (chunk);

    address += dylib_range.size;
    remaining -= dylib_range.size;

    if (!carry_on)
      break;
  }
  while (remaining != 0);

  return carry_on;
}

static gint
gum_darwin_module_compare_base (GumDarwinModule ** lhs_module,
                                GumDarwinModule ** rhs_module)
{
  GumAddress lhs;
  GumAddress rhs;

  lhs = (*lhs_module)->base_address;
  rhs = (*rhs_module)->base_address;

  if (lhs < rhs)
    return -1;

  if (lhs > rhs)
    return 1;

  return 0;
}

static gint
gum_darwin_module_compare_to_key (const GumAddress * key_ptr,
                                  GumDarwinModule ** member)
{
  GumAddress key = *key_ptr;
  GumDarwinModule * module = *member;

  if (key < module->base_address)
    return -1;

  if (key >= module->base_address + module->text_size)
    return 1;

  return 0;
}
