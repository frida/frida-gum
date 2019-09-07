/*
 * Copyright (C) 2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_CMODULE_H__
#define __GUM_CMODULE_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

typedef struct _GumCModule GumCModule;
typedef struct _GumCSymbolDetails GumCSymbolDetails;

struct _GumCSymbolDetails
{
  const gchar * name;
  gpointer address;
};

typedef gboolean (* GumFoundCSymbolFunc) (const GumCSymbolDetails * details,
    gpointer user_data);

GUM_API GumCModule * gum_cmodule_new (const gchar * source, GError ** error);
GUM_API void gum_cmodule_free (GumCModule * cmodule);

GUM_API void gum_cmodule_add_symbol (GumCModule * self, const gchar * name,
    gconstpointer value);

GUM_API gboolean gum_cmodule_link (GumCModule * self, GError ** error);

GUM_API void gum_cmodule_enumerate_symbols (GumCModule * self,
    GumFoundCSymbolFunc func, gpointer user_data);
GUM_API gpointer gum_cmodule_find_symbol_by_name (GumCModule * self,
    const gchar * name);

GUM_API void gum_cmodule_drop_metadata (GumCModule * self);

G_END_DECLS

#endif
