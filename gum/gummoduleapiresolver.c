/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleapiresolver.h"

#include <gio/gio.h>

struct _GumModuleApiResolver
{
  GObject parent;

  GRegex * query_pattern;
};

static void gum_module_api_resolver_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_module_api_resolver_finalize (GObject * object);
static void gum_module_api_resolver_enumerate_matches (
    GumApiResolver * resolver, const gchar * query, GumFoundApiFunc func,
    gpointer user_data, GError ** error);

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

  iface->enumerate_matches = gum_module_api_resolver_enumerate_matches;
}

static void
gum_module_api_resolver_init (GumModuleApiResolver * self)
{
  self->query_pattern = g_regex_new ("TODO", 0, 0, NULL);
}

static void
gum_module_api_resolver_finalize (GObject * object)
{
  GumModuleApiResolver * self = GUM_MODULE_API_RESOLVER (object);

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
}
