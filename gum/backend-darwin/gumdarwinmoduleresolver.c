/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumdarwinmoduleresolver.h"

#include "gumdarwin.h"

#include <mach-o/loader.h>

typedef struct _GumCollectModulesContext GumCollectModulesContext;

enum
{
  PROP_0,
  PROP_TASK
};

struct _GumCollectModulesContext
{
  GumDarwinModuleResolver * self;
  guint index;
  gchar * sysroot;
  guint sysroot_length;
};

static void gum_darwin_module_resolver_constructed (GObject * object);
static void gum_darwin_module_resolver_finalize (GObject * object);
static void gum_darwin_module_resolver_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_darwin_module_resolver_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gboolean gum_store_module (const GumModuleDetails * details,
    gpointer user_data);

G_DEFINE_TYPE (GumDarwinModuleResolver,
               gum_darwin_module_resolver,
               G_TYPE_OBJECT)

static void
gum_darwin_module_resolver_class_init (GumDarwinModuleResolverClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_darwin_module_resolver_constructed;
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
  self->modules = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      g_object_unref);
}

static void
gum_darwin_module_resolver_constructed (GObject * object)
{
}

static void
gum_darwin_module_resolver_finalize (GObject * object)
{
  GumDarwinModuleResolver * self = GUM_DARWIN_MODULE_RESOLVER (object);

  gum_darwin_module_resolver_set_dynamic_lookup_handler (self, NULL, NULL,
      NULL);

  g_free (self->sysroot);
  g_hash_table_unref (self->modules);

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

gboolean
gum_darwin_module_resolver_load (GumDarwinModuleResolver * self,
                                 GError ** error)
{
  int pid;
  GumCollectModulesContext ctx;

  if (g_hash_table_size (self->modules) != 0)
    return TRUE;

  if (!gum_darwin_query_ptrauth_support (self->task, &self->ptrauth_support))
    goto invalid_task;

  if (!gum_darwin_query_page_size (self->task, &self->page_size))
    goto invalid_task;

  if (pid_for_task (self->task, &pid) != KERN_SUCCESS)
    goto invalid_task;

  if (!gum_darwin_cpu_type_from_pid (pid, &self->cpu_type))
    goto invalid_task;

  ctx.self = self;
  ctx.index = 0;
  ctx.sysroot = NULL;
  ctx.sysroot_length = 0;

  gum_darwin_enumerate_modules (self->task, gum_store_module, &ctx);
  if (ctx.index == 0)
    goto invalid_task;

  self->sysroot = ctx.sysroot;

  return TRUE;

invalid_task:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Process is dead");
    return FALSE;
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

GumDarwinModule *
gum_darwin_module_resolver_find_module (GumDarwinModuleResolver * self,
                                        const gchar * module_name)
{
  GumDarwinModule * module;

  module = g_hash_table_lookup (self->modules, module_name);
  if (module != NULL)
    return module;

  if (g_str_has_prefix (module_name, "/usr/lib/system/"))
  {
    gchar * alias =
        g_strconcat ("/usr/lib/system/introspection/", module_name + 16, NULL);

    module = g_hash_table_lookup (self->modules, alias);

    g_free (alias);
  }

  return module;
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

      reexport = gum_darwin_module_resolver_find_module (self,
          g_ptr_array_index (reexports, i));
      if (reexport != NULL)
      {
        found = gum_darwin_module_resolve_export (reexport, symbol, &d);
        if (found)
          m = reexport;
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
    gboolean is_reexporting_itself;

    target_module_name = gum_darwin_module_get_dependency_by_ordinal (module,
        export->reexport_library_ordinal);
    target_module = gum_darwin_module_resolver_find_module (self,
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
      return FALSE;
    }

    return gum_darwin_module_resolver_find_export_by_mangled_name (self,
        target_module, export->reexport_symbol, result);
  }

  result->name = gum_symbol_name_from_darwin (export->name);

  switch (export->flags & EXPORT_SYMBOL_FLAGS_KIND_MASK)
  {
    case EXPORT_SYMBOL_FLAGS_KIND_REGULAR:
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
    case EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL:
      result->address = module->base_address + export->offset;
      break;
    case GUM_DARWIN_EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE:
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

static gboolean
gum_store_module (const GumModuleDetails * details,
                  gpointer user_data)
{
  GumCollectModulesContext * ctx = user_data;
  GumDarwinModuleResolver * self = ctx->self;
  GumDarwinModule * module;

  if (ctx->index == 0 && g_str_has_suffix (details->path, "/usr/lib/dyld_sim"))
  {
    ctx->sysroot_length = strlen (details->path) - 17;
    ctx->sysroot = g_strndup (details->path, ctx->sysroot_length);
  }

  module = gum_darwin_module_new_from_memory (details->path, self->task,
      details->range->base_address, GUM_DARWIN_MODULE_FLAGS_NONE, NULL);
  g_hash_table_insert (self->modules, g_strdup (details->name),
      module);
  g_hash_table_insert (self->modules, g_strdup (details->path),
      g_object_ref (module));
  if (ctx->sysroot != NULL && g_str_has_prefix (details->path, ctx->sysroot))
  {
    g_hash_table_insert (self->modules,
        g_strdup (details->path + ctx->sysroot_length), g_object_ref (module));
  }

  ctx->index++;

  return TRUE;
}

#endif
