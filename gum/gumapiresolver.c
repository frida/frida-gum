/*
 * Copyright (C) 2016-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumapiresolver.h"

#include "gummoduleapiresolver.h"
#ifdef HAVE_DARWIN
# include "backend-darwin/gumobjcapiresolver.h"
#endif

#include <string.h>

G_DEFINE_INTERFACE (GumApiResolver, gum_api_resolver, G_TYPE_OBJECT)

static void
gum_api_resolver_default_init (GumApiResolverInterface * iface)
{
}

GumApiResolver *
gum_api_resolver_make (const gchar * type)
{
  if (strcmp (type, "module") == 0)
    return gum_module_api_resolver_new ();

#ifdef HAVE_DARWIN
  if (strcmp (type, "objc") == 0)
    return gum_objc_api_resolver_new ();
#endif

  return NULL;
}

void
gum_api_resolver_enumerate_matches (GumApiResolver * self,
                                    const gchar * query,
                                    GumFoundApiFunc func,
                                    gpointer user_data,
                                    GError ** error)
{
  GUM_API_RESOLVER_GET_IFACE (self)->enumerate_matches (self, query, func,
      user_data, error);
}
