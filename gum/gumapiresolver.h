/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_API_RESOLVER_H__
#define __GUM_API_RESOLVER_H__

#include <glib-object.h>
#include <gum/gumdefs.h>

#define GUM_TYPE_API_RESOLVER (gum_api_resolver_get_type ())
#define GUM_API_RESOLVER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_API_RESOLVER, GumApiResolver))
#define GUM_API_RESOLVER_CAST(obj) ((GumApiResolver *) (obj))
#define GUM_IS_API_RESOLVER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_API_RESOLVER))
#define GUM_API_RESOLVER_GET_INTERFACE(inst) (G_TYPE_INSTANCE_GET_INTERFACE (\
    (inst), GUM_TYPE_API_RESOLVER, GumApiResolverIface))

typedef struct _GumApiResolver GumApiResolver;
typedef struct _GumApiResolverIface GumApiResolverIface;

typedef struct _GumApiDetails GumApiDetails;

typedef gboolean (* GumFoundApiFunc) (const GumApiDetails * details,
    gpointer user_data);

struct _GumApiResolverIface
{
  GTypeInterface parent;

  void (* enumerate_matches) (GumApiResolver * self, const gchar ** globs,
      GumFoundApiFunc func, gpointer user_data);
};

struct _GumApiDetails
{
  const gchar * name;
  GumAddress address;
};

G_BEGIN_DECLS

GUM_API GType gum_api_resolver_get_type (void);

GUM_API GumApiResolver * gum_api_resolver_make (const gchar * type);

GUM_API void gum_api_resolver_enumerate_matches (GumApiResolver * self,
    const gchar ** globs, GumFoundApiFunc func, gpointer user_data);

G_END_DECLS

#endif
