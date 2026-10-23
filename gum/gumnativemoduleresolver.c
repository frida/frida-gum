/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumnativemoduleresolver.h"

struct _GumNativeModuleResolver
{
  GObject parent;

  GHashTable * module_by_name;

  GumNativeModuleResolverLookupFunc lookup_func;
  gpointer lookup_data;
  GDestroyNotify lookup_data_destroy;
};

static void gum_native_module_resolver_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_native_module_resolver_dispose (GObject * object);
static GumModule * gum_native_module_resolver_find_module_by_name (
    GumModuleResolver * resolver, const gchar * name);
static GumAddress gum_native_module_resolver_find_dynamic_address (
    GumModuleResolver * resolver, const gchar * symbol);

G_DEFINE_TYPE_WITH_CODE (GumNativeModuleResolver,
                         gum_native_module_resolver,
                         G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GUM_TYPE_MODULE_RESOLVER,
                             gum_native_module_resolver_iface_init))

static void
gum_native_module_resolver_class_init (GumNativeModuleResolverClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_native_module_resolver_dispose;
}

static void
gum_native_module_resolver_iface_init (gpointer g_iface,
                                       gpointer iface_data)
{
  GumModuleResolverInterface * iface = g_iface;

  iface->find_module_by_name = gum_native_module_resolver_find_module_by_name;
  iface->find_dynamic_address =
      gum_native_module_resolver_find_dynamic_address;
}

static void
gum_native_module_resolver_init (GumNativeModuleResolver * self)
{
  self->module_by_name = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      g_object_unref);
}

static void
gum_native_module_resolver_dispose (GObject * object)
{
  GumNativeModuleResolver * self = GUM_NATIVE_MODULE_RESOLVER (object);

  if (self->lookup_data_destroy != NULL)
    self->lookup_data_destroy (self->lookup_data);
  self->lookup_func = NULL;
  self->lookup_data = NULL;
  self->lookup_data_destroy = NULL;

  g_clear_pointer (&self->module_by_name, g_hash_table_unref);

  G_OBJECT_CLASS (gum_native_module_resolver_parent_class)->dispose (object);
}

GumNativeModuleResolver *
gum_native_module_resolver_new (void)
{
  return g_object_new (GUM_TYPE_NATIVE_MODULE_RESOLVER, NULL);
}

void
gum_native_module_resolver_set_dynamic_lookup_handler (
    GumNativeModuleResolver * self,
    GumNativeModuleResolverLookupFunc func,
    gpointer data,
    GDestroyNotify data_destroy)
{
  if (self->lookup_data_destroy != NULL)
    self->lookup_data_destroy (self->lookup_data);

  self->lookup_func = func;
  self->lookup_data = data;
  self->lookup_data_destroy = data_destroy;
}

static GumModule *
gum_native_module_resolver_find_module_by_name (GumModuleResolver * resolver,
                                                const gchar * name)
{
  GumNativeModuleResolver * self = GUM_NATIVE_MODULE_RESOLVER (resolver);
  GumModule * module;

  module = g_hash_table_lookup (self->module_by_name, name);
  if (module == NULL)
  {
    module = gum_module_load (name, NULL);
    if (module == NULL)
      return NULL;
    g_hash_table_insert (self->module_by_name, g_strdup (name), module);
  }

  return g_object_ref (module);
}

static GumAddress
gum_native_module_resolver_find_dynamic_address (GumModuleResolver * resolver,
                                                 const gchar * symbol)
{
  GumNativeModuleResolver * self = GUM_NATIVE_MODULE_RESOLVER (resolver);

  if (self->lookup_func != NULL)
  {
    GumAddress address = self->lookup_func (symbol, self->lookup_data);
    if (address != 0)
      return address;
  }

  return gum_module_find_global_export_by_name (symbol);
}
