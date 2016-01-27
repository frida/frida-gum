/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_ALLOCATION_TRACKER_H__
#define __GUM_ALLOCATION_TRACKER_H__

#include <glib-object.h>
#include <gum/gumdefs.h>
#include <gum/gumbacktracer.h>

#define GUM_TYPE_ALLOCATION_TRACKER (gum_allocation_tracker_get_type ())
#define GUM_ALLOCATION_TRACKER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_ALLOCATION_TRACKER, GumAllocationTracker))
#define GUM_ALLOCATION_TRACKER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_ALLOCATION_TRACKER, GumAllocationTrackerClass))
#define GUM_IS_ALLOCATION_TRACKER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_ALLOCATION_TRACKER))
#define GUM_IS_ALLOCATION_TRACKER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_ALLOCATION_TRACKER))
#define GUM_ALLOCATION_TRACKER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_ALLOCATION_TRACKER, GumAllocationTrackerClass))

typedef struct _GumAllocationTracker GumAllocationTracker;
typedef struct _GumAllocationTrackerClass GumAllocationTrackerClass;

typedef struct _GumAllocationTrackerPrivate GumAllocationTrackerPrivate;

struct _GumAllocationTracker
{
  GObject parent;

  GumAllocationTrackerPrivate * priv;
};

struct _GumAllocationTrackerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

typedef gboolean (* GumAllocationTrackerFilterFunction) (
    GumAllocationTracker * tracker, gpointer address, guint size,
    gpointer user_data);

GUM_API GType gum_allocation_tracker_get_type (void) G_GNUC_CONST;

GUM_API GumAllocationTracker * gum_allocation_tracker_new (void);
GUM_API GumAllocationTracker * gum_allocation_tracker_new_with_backtracer (
    GumBacktracer * backtracer);

GUM_API void gum_allocation_tracker_set_filter_function (
    GumAllocationTracker * self, GumAllocationTrackerFilterFunction filter,
    gpointer user_data);

GUM_API void gum_allocation_tracker_begin (GumAllocationTracker * self);
GUM_API void gum_allocation_tracker_end (GumAllocationTracker * self);

GUM_API guint gum_allocation_tracker_peek_block_count (
    GumAllocationTracker * self);
GUM_API guint gum_allocation_tracker_peek_block_total_size (
    GumAllocationTracker * self);
GUM_API GList * gum_allocation_tracker_peek_block_list (
    GumAllocationTracker * self);
GUM_API GList * gum_allocation_tracker_peek_block_groups (
    GumAllocationTracker * self);

/*< Internal API */
void gum_allocation_tracker_on_malloc (GumAllocationTracker * self,
    gpointer address, guint size);
void gum_allocation_tracker_on_free (GumAllocationTracker * self,
    gpointer address);
void gum_allocation_tracker_on_realloc (GumAllocationTracker * self,
    gpointer old_address, gpointer new_address, guint new_size);

void gum_allocation_tracker_on_malloc_full (
    GumAllocationTracker * self, gpointer address, guint size,
    const GumCpuContext * cpu_context);
void gum_allocation_tracker_on_free_full (GumAllocationTracker * self,
    gpointer address, const GumCpuContext * cpu_context);
void gum_allocation_tracker_on_realloc_full (
    GumAllocationTracker * self, gpointer old_address, gpointer new_address,
    guint new_size, const GumCpuContext * cpu_context);

G_END_DECLS

#endif
