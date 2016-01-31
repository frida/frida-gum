/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumobjcapiresolver.h"

struct _GumObjcApiResolver
{
  GObject parent;
};

static void gum_objc_api_resolver_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_objc_api_resolver_enumerate_matches (GumApiResolver * self,
    const gchar ** globs, GumFoundApiFunc func, gpointer user_data);

G_DEFINE_TYPE_EXTENDED (GumObjcApiResolver,
                        gum_objc_api_resolver,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_API_RESOLVER,
                            gum_objc_api_resolver_iface_init))

static void
gum_objc_api_resolver_class_init (GumObjcApiResolverClass * klass)
{
}

static void
gum_objc_api_resolver_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  GumApiResolverIface * iface = (GumApiResolverIface *) g_iface;

  iface->enumerate_matches = gum_objc_api_resolver_enumerate_matches;
}

static void
gum_objc_api_resolver_init (GumObjcApiResolver * self)
{
}

GumApiResolver *
gum_objc_api_resolver_new (void)
{
  return g_object_new (GUM_TYPE_OBJC_API_RESOLVER, NULL);
}

static void
gum_objc_api_resolver_enumerate_matches (GumApiResolver * resolver,
                                         const gchar * query,
                                         GumFoundApiFunc func,
                                         gpointer user_data,
                                         GError ** error)
{
  /* TODO: implement */
}
