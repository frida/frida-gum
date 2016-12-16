/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdarwinmoduleresolver.h"

#include "gumdarwin.h"

#include <mach-o/loader.h>

enum
{
  PROP_0,
  PROP_TASK
};

typedef struct _GumCollectModulesContext GumCollectModulesContext;

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
  GumDarwinModuleResolver * self = GUM_DARWIN_MODULE_RESOLVER (object);
  int pid;

  g_assert (self->task != MACH_PORT_NULL);

  if (self->task == mach_task_self ())
    self->page_size = gum_query_page_size ();
  else
    gum_darwin_query_page_size (self->task, &self->page_size);

  if (pid_for_task (self->task, &pid) == KERN_SUCCESS &&
      gum_darwin_cpu_type_from_pid (pid, &self->cpu_type))
  {
    GumCollectModulesContext ctx;

    ctx.self = self;
    ctx.index = 0;
    ctx.sysroot = NULL;
    ctx.sysroot_length = 0;

    gum_darwin_enumerate_modules (self->task, gum_store_module, &ctx);

    self->sysroot = ctx.sysroot;
  }
  else
  {
    self->cpu_type = GUM_NATIVE_CPU;
  }
}

static void
gum_darwin_module_resolver_finalize (GObject * object)
{
  GumDarwinModuleResolver * self = GUM_DARWIN_MODULE_RESOLVER (object);

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
gum_darwin_module_resolver_new (mach_port_t task)
{
  return g_object_new (GUM_DARWIN_TYPE_MODULE_RESOLVER, "task", task, NULL);
}

GumDarwinModule *
gum_darwin_module_resolver_find_module (GumDarwinModuleResolver * self,
                                        const gchar * module_name)
{
  return g_hash_table_lookup (self->modules, module_name);
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
  else if (gum_darwin_module_lacks_exports_for_reexports (module))
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

    target_module_name = gum_darwin_module_dependency (module,
        export->reexport_library_ordinal);
    target_module = gum_darwin_module_resolver_find_module (self,
        target_module_name);
    if (target_module == NULL)
      return FALSE;

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

  return TRUE;
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
      self->cpu_type, self->page_size, details->range->base_address);
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
