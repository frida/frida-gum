/*
 * Copyright (C) 2017-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2024 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_CLOAK_H__
#define __GUM_CLOAK_H__

#include <gum/gummemory.h>
#include <gum/gumprocess.h>

G_BEGIN_DECLS

typedef struct _GumCloak GumCloak;

#define GUM_TYPE_CLOAK_OBSERVER (gum_cloak_observer_get_type ())
G_DECLARE_INTERFACE (GumCloakObserver, gum_cloak_observer, GUM,
                     CLOAK_OBSERVER, GObject)

struct _GumCloakObserverInterface
{
  GTypeInterface parent;

  void (* thread_added) (GumCloakObserver * self, GumThreadId id);
  void (* thread_removed) (GumCloakObserver * self, GumThreadId id);
};

typedef gboolean (* GumCloakFoundThreadFunc) (GumThreadId id,
    gpointer user_data);
typedef gboolean (* GumCloakFoundRangeFunc) (const GumMemoryRange * range,
    gpointer user_data);
typedef gboolean (* GumCloakFoundFDFunc) (gint fd, gpointer user_data);
typedef void (* GumCloakLockedFunc) (gpointer user_data);

GUM_API void gum_cloak_add_thread (GumThreadId id);
GUM_API void gum_cloak_remove_thread (GumThreadId id);
GUM_API gboolean gum_cloak_has_thread (GumThreadId id);
GUM_API void gum_cloak_enumerate_threads (GumCloakFoundThreadFunc func,
    gpointer user_data);

GUM_API void gum_cloak_add_range (const GumMemoryRange * range);
GUM_API void gum_cloak_remove_range (const GumMemoryRange * range);
GUM_API gboolean gum_cloak_has_range_containing (GumAddress address);
GUM_API GArray * gum_cloak_clip_range (const GumMemoryRange * range);
GUM_API void gum_cloak_enumerate_ranges (GumCloakFoundRangeFunc func,
    gpointer user_data);

GUM_API void gum_cloak_add_file_descriptor (gint fd);
GUM_API void gum_cloak_remove_file_descriptor (gint fd);
GUM_API gboolean gum_cloak_has_file_descriptor (gint fd);
GUM_API void gum_cloak_enumerate_file_descriptors (GumCloakFoundFDFunc func,
    gpointer user_data);

GUM_API void gum_cloak_with_lock_held (GumCloakLockedFunc func,
    gpointer user_data);
GUM_API gboolean gum_cloak_is_locked (void);

GUM_API void gum_cloak_add_observer (GumCloakObserver * observer);
GUM_API void gum_cloak_remove_observer (GumCloakObserver * observer);

GUM_API void gum_cloak_observer_thread_added (GumCloakObserver * self,
    GumThreadId id);
GUM_API void gum_cloak_observer_thread_removed (GumCloakObserver * self,
    GumThreadId id);

G_END_DECLS

#endif
