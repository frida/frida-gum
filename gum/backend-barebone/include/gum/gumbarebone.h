/*
 * Copyright (C) 2025-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_BAREBONE_H__
#define __GUM_BAREBONE_H__

#include <gum/gumexceptor.h>
#include <gum/gummemory.h>
#include <gum/gummoduleregistry.h>
#include <gum/gumprocess.h>

G_BEGIN_DECLS

GUM_API guint gum_barebone_query_page_size (void);
GUM_API gpointer gum_barebone_try_remap_writable_pages (gconstpointer * addrs,
    guint n_addrs);

GUM_API gboolean gum_barebone_handle_exception (GumExceptionType type,
    gpointer pc, gpointer accessed_address, GumCpuContext * cpu_context);

GUM_API void gum_barebone_on_registry_activating (GumModuleRegistry * registry);
GUM_API void gum_barebone_register_module (GumModuleRegistry * registry,
    GumModule * module);

GUM_API void gum_barebone_enumerate_threads (GumFoundThreadFunc func,
    gpointer user_data);

G_END_DECLS

#endif
