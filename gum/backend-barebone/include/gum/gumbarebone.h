/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_BAREBONE_H__
#define __GUM_BAREBONE_H__

#include <gum/gummemory.h>
#include <gum/gummoduleregistry.h>

G_BEGIN_DECLS

GUM_API guint gum_barebone_query_page_size (void);
GUM_API gpointer gum_barebone_try_remap_writable_pages (gconstpointer * addrs,
    guint n_addrs);

GUM_API void gum_barebone_on_registry_activating (GumModuleRegistry * registry);
GUM_API void gum_barebone_register_module (GumModuleRegistry * registry,
    GumModule * module);

G_END_DECLS

#endif
