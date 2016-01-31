/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumapiresolver.h"

#ifdef HAVE_DARWIN
# include "backend-darwin/gumobjcapiresolver.h"
#endif

#include <string.h>

GType
gum_api_resolver_get_type (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GType gtype;

    gtype = g_type_register_static_simple (G_TYPE_INTERFACE,
        "GumApiResolver", sizeof (GumApiResolverIface),
        NULL, 0, NULL, 0);
    g_type_interface_add_prerequisite (gtype, G_TYPE_OBJECT);

    g_once_init_leave (&gonce_value, gtype);
  }

  return (GType) gonce_value;
}

GumApiResolver *
gum_api_resolver_make (const gchar * type)
{
#ifdef HAVE_DARWIN
  if (strcmp (type, "objc") == 0)
    return gum_objc_api_resolver_new ();
#endif

  return NULL;
}

void
gum_api_resolver_enumerate_matches (GumApiResolver * self,
                                    const gchar ** globs,
                                    GumFoundApiFunc func,
                                    gpointer user_data)
{
  GUM_API_RESOLVER_GET_INTERFACE (self)->enumerate_matches (self, globs, func,
      user_data);
}
