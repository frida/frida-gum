/*
 * Copyright (C) 2025-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_THREAD_REGISTRY_H__
#define __GUM_THREAD_REGISTRY_H__

#include <gum/gumprocess.h>

G_BEGIN_DECLS

#define GUM_TYPE_THREAD_REGISTRY (gum_thread_registry_get_type ())
G_DECLARE_FINAL_TYPE (GumThreadRegistry, gum_thread_registry, GUM,
                      THREAD_REGISTRY, GObject)

#define GUM_TYPE_THREAD_PROVIDER (gum_thread_provider_get_type ())
G_DECLARE_INTERFACE (GumThreadProvider, gum_thread_provider, GUM,
                     THREAD_PROVIDER, GObject)

struct _GumThreadProviderInterface
{
  GTypeInterface parent;

  void (* activate) (GumThreadProvider * self, GumThreadRegistry * registry);
  void (* deactivate) (GumThreadProvider * self);
};

GUM_API void gum_thread_registry_set_provider (GumThreadProvider * provider);

GUM_API GumThreadRegistry * gum_thread_registry_obtain (void);

GUM_API void gum_thread_registry_enumerate_threads (GumThreadRegistry * self,
    GumFoundThreadFunc func, gpointer user_data);

GUM_API void gum_thread_registry_lock (GumThreadRegistry * self);
GUM_API void gum_thread_registry_unlock (GumThreadRegistry * self);

GUM_API void gum_thread_registry_register (GumThreadRegistry * self,
    const GumThreadDetails * thread);
GUM_API void gum_thread_registry_unregister (GumThreadRegistry * self,
    GumThreadId id);
GUM_API void gum_thread_registry_rename (GumThreadRegistry * self,
    GumThreadId id, const gchar * name);

GUM_API void gum_thread_provider_activate (GumThreadProvider * self,
    GumThreadRegistry * registry);
GUM_API void gum_thread_provider_deactivate (GumThreadProvider * self);

G_END_DECLS

#endif
