/*
 * Copyright (C) 2016-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_API_RESOLVER_H__
#define __GUM_API_RESOLVER_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

#define GUM_TYPE_API_RESOLVER (gum_api_resolver_get_type ())
GUM_DECLARE_INTERFACE (GumApiResolver, gum_api_resolver, GUM, API_RESOLVER,
                       GObject)

typedef struct _GumApiDetails GumApiDetails;

typedef gboolean (* GumFoundApiFunc) (const GumApiDetails * details,
    gpointer user_data);

#ifndef GUM_DIET

struct _GumApiResolverInterface
{
  GTypeInterface parent;

  void (* enumerate_matches) (GumApiResolver * self, const gchar * query,
      GumFoundApiFunc func, gpointer user_data, GError ** error);
};

#endif

struct _GumApiDetails
{
  const gchar * name;
  GumAddress address;
};

GUM_API GumApiResolver * gum_api_resolver_make (const gchar * type);

GUM_API void gum_api_resolver_enumerate_matches (GumApiResolver * self,
    const gchar * query, GumFoundApiFunc func, gpointer user_data,
    GError ** error);

G_END_DECLS

#endif
