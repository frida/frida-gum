/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleapiresolver.h"

#include "gumprocess.h"

#include <gio/gio.h>

typedef struct _GumModuleMetadata GumModuleMetadata;
typedef struct _GumFunctionMetadata GumFunctionMetadata;

struct _GumModuleApiResolver
{
  GObject parent;

  GRegex * query_pattern;

  GHashTable * module_by_name;
};

struct _GumModuleMetadata
{
  gint ref_count;

  gchar * name;
  gchar * path;

  GHashTable * import_by_name;
  GHashTable * export_by_name;
};

struct _GumFunctionMetadata
{
  gchar * name;
  GumAddress address;
  gchar * module;
};

static void gum_module_api_resolver_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_module_api_resolver_finalize (GObject * object);
static void gum_module_api_resolver_enumerate_matches (
    GumApiResolver * resolver, const gchar * query, GumFoundApiFunc func,
    gpointer user_data, GError ** error);

static GPatternSpec * gum_pattern_spec_from_match_info (GMatchInfo * match_info,
    gint match_num);

static GHashTable * gum_module_api_resolver_create_snapshot (void);
static gboolean gum_module_api_resolver_collect_module (
    const GumModuleDetails * details, gpointer user_data);

static void gum_module_metadata_unref (GumModuleMetadata * module);
static GHashTable * gum_module_metadata_get_imports (GumModuleMetadata * self);
static GHashTable * gum_module_metadata_get_exports (GumModuleMetadata * self);
static gboolean gum_module_metadata_collect_import (
    const GumImportDetails * details, gpointer user_data);
static gboolean gum_module_metadata_collect_export (
    const GumExportDetails * details, gpointer user_data);

static GumFunctionMetadata * gum_function_metadata_new (const gchar * name,
    GumAddress address, const gchar * module);
static void gum_function_metadata_free (GumFunctionMetadata * function);

G_DEFINE_TYPE_EXTENDED (GumModuleApiResolver,
                        gum_module_api_resolver,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_API_RESOLVER,
                            gum_module_api_resolver_iface_init))

static void
gum_module_api_resolver_class_init (GumModuleApiResolverClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_module_api_resolver_finalize;
}

static void
gum_module_api_resolver_iface_init (gpointer g_iface,
                                    gpointer iface_data)
{
  GumApiResolverIface * iface = (GumApiResolverIface *) g_iface;

  (void) iface_data;

  iface->enumerate_matches = gum_module_api_resolver_enumerate_matches;
}

static void
gum_module_api_resolver_init (GumModuleApiResolver * self)
{
  self->query_pattern = g_regex_new ("(imports|exports):(.+)!(.+)", 0, 0, NULL);

  self->module_by_name = gum_module_api_resolver_create_snapshot ();
}

static void
gum_module_api_resolver_finalize (GObject * object)
{
  GumModuleApiResolver * self = GUM_MODULE_API_RESOLVER (object);

  g_hash_table_unref (self->module_by_name);

  g_regex_unref (self->query_pattern);

  G_OBJECT_CLASS (gum_module_api_resolver_parent_class)->finalize (object);
}

GumApiResolver *
gum_module_api_resolver_new (void)
{
  return g_object_new (GUM_TYPE_MODULE_API_RESOLVER, NULL);
}

static void
gum_module_api_resolver_enumerate_matches (GumApiResolver * resolver,
                                           const gchar * query,
                                           GumFoundApiFunc func,
                                           gpointer user_data,
                                           GError ** error)
{
  GumModuleApiResolver * self = GUM_MODULE_API_RESOLVER (resolver);
  GMatchInfo * query_info;
  gchar * collection;
  GPatternSpec * module_spec, * function_spec;
  GHashTableIter module_iter;
  gboolean carry_on;
  GumModuleMetadata * module;

  g_regex_match (self->query_pattern, query, 0, &query_info);
  if (!g_match_info_matches (query_info))
    goto invalid_query;

  collection = g_match_info_fetch (query_info, 1);
  module_spec = gum_pattern_spec_from_match_info (query_info, 2);
  function_spec = gum_pattern_spec_from_match_info (query_info, 3);

  g_hash_table_iter_init (&module_iter, self->module_by_name);
  carry_on = TRUE;
  while (carry_on &&
      g_hash_table_iter_next (&module_iter, NULL, (gpointer *) &module))
  {
    if (g_pattern_match_string (module_spec, module->name) ||
        g_pattern_match_string (module_spec, module->path))
    {
      GHashTable * functions;
      GHashTableIter function_iter;
      GumFunctionMetadata * function;

      functions = (collection[0] == 'i')
          ? gum_module_metadata_get_imports (module)
          : gum_module_metadata_get_exports (module);

      g_hash_table_iter_init (&function_iter, functions);
      while (carry_on &&
          g_hash_table_iter_next (&function_iter, NULL, (gpointer *) &function))
      {
        if (g_pattern_match_string (function_spec, function->name))
        {
          GumApiDetails details;

          details.name = g_strconcat (
              (function->module != NULL) ? function->module : module->path,
              "!",
              function->name,
              NULL);
          details.address = function->address;

          carry_on = func (&details, user_data);

          g_free ((gpointer) details.name);
        }
      }
    }
  }

  g_pattern_spec_free (function_spec);
  g_pattern_spec_free (module_spec);
  g_free (collection);

  return;

invalid_query:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "invalid query; format is: "
        "exports:*!open*, exports:libc.so!* or imports:notepad.exe!*");
  }
}

static GPatternSpec *
gum_pattern_spec_from_match_info (GMatchInfo * match_info,
                                  gint match_num)
{
  gchar * pattern;
  GPatternSpec * spec;

  pattern = g_match_info_fetch (match_info, match_num);
  spec = g_pattern_spec_new (pattern);
  g_free (pattern);

  return spec;
}

static GHashTable *
gum_module_api_resolver_create_snapshot (void)
{
  GHashTable * module_by_name;

  module_by_name = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      (GDestroyNotify) gum_module_metadata_unref);

  gum_process_enumerate_modules (gum_module_api_resolver_collect_module,
      module_by_name);

  return module_by_name;
}

static gboolean
gum_module_api_resolver_collect_module (const GumModuleDetails * details,
                                        gpointer user_data)
{
  GHashTable * module_by_name = user_data;
  GumModuleMetadata * module;

  module = g_slice_new (GumModuleMetadata);
  module->ref_count = 2;
  module->name = g_strdup (details->name);
  module->path = g_strdup (details->path);
  module->import_by_name = NULL;
  module->export_by_name = NULL;

  g_hash_table_insert (module_by_name, g_strdup (module->name), module);
  g_hash_table_insert (module_by_name, g_strdup (module->path), module);

  return TRUE;
}

static void
gum_module_metadata_unref (GumModuleMetadata * module)
{
  module->ref_count--;
  if (module->ref_count == 0)
  {
    if (module->export_by_name != NULL)
      g_hash_table_unref (module->export_by_name);

    if (module->import_by_name != NULL)
      g_hash_table_unref (module->import_by_name);

    g_free (module->path);
    g_free (module->name);

    g_slice_free (GumModuleMetadata, module);
  }
}

static GHashTable *
gum_module_metadata_get_imports (GumModuleMetadata * self)
{
  if (self->import_by_name == NULL)
  {
    self->import_by_name = g_hash_table_new_full (g_str_hash, g_str_equal,
        g_free, (GDestroyNotify) gum_function_metadata_free);
    gum_module_enumerate_imports (self->path,
        gum_module_metadata_collect_import, self->import_by_name);
  }

  return self->import_by_name;
}

static GHashTable *
gum_module_metadata_get_exports (GumModuleMetadata * self)
{
  if (self->export_by_name == NULL)
  {
    self->export_by_name = g_hash_table_new_full (g_str_hash, g_str_equal,
        g_free, (GDestroyNotify) gum_function_metadata_free);
    gum_module_enumerate_exports (self->path,
        gum_module_metadata_collect_export, self->export_by_name);
  }

  return self->export_by_name;
}

static gboolean
gum_module_metadata_collect_import (const GumImportDetails * details,
                                    gpointer user_data)
{
  GHashTable * import_by_name = user_data;

  if (details->type == GUM_IMPORT_FUNCTION && details->address != 0)
  {
    GumFunctionMetadata * function;

    function = gum_function_metadata_new (details->name, details->address,
        details->module);
    g_hash_table_insert (import_by_name, g_strdup (function->name), function);
  }

  return TRUE;
}

static gboolean
gum_module_metadata_collect_export (const GumExportDetails * details,
                                    gpointer user_data)
{
  GHashTable * export_by_name = user_data;

  if (details->type == GUM_EXPORT_FUNCTION)
  {
    GumFunctionMetadata * function;

    function = gum_function_metadata_new (details->name, details->address,
        NULL);
    g_hash_table_insert (export_by_name, g_strdup (function->name), function);
  }

  return TRUE;
}

static GumFunctionMetadata *
gum_function_metadata_new (const gchar * name,
                           GumAddress address,
                           const gchar * module)
{
  GumFunctionMetadata * function;

  function = g_slice_new (GumFunctionMetadata);
  function->name = g_strdup (name);
  function->address = address;
  function->module = g_strdup (module);

  return function;
}

static void
gum_function_metadata_free (GumFunctionMetadata * function)
{
  g_free (function->module);
  g_free (function->name);

  g_slice_free (GumFunctionMetadata, function);
}
