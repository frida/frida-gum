/*
 * Copyright (C) 2010, 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MEMORY_ACCESS_MONITOR_H__
#define __GUM_MEMORY_ACCESS_MONITOR_H__

#include <glib-object.h>
#include <gum/gummemory.h>

#define GUM_TYPE_MEMORY_ACCESS_MONITOR (gum_memory_access_monitor_get_type ())
#define GUM_MEMORY_ACCESS_MONITOR(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_MEMORY_ACCESS_MONITOR, GumMemoryAccessMonitor))
#define GUM_MEMORY_ACCESS_MONITOR_CAST(obj) ((GumMemoryAccessMonitor *) (obj))
#define GUM_MEMORY_ACCESS_MONITOR_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST ((klass), GUM_TYPE_MEMORY_ACCESS_MONITOR,\
    GumMemoryAccessMonitorClass))
#define GUM_IS_MEMORY_ACCESS_MONITOR(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_MEMORY_ACCESS_MONITOR))
#define GUM_IS_MEMORY_ACCESS_MONITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_MEMORY_ACCESS_MONITOR))
#define GUM_MEMORY_ACCESS_MONITOR_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_MEMORY_ACCESS_MONITOR, GumMemoryAccessMonitorClass))

G_BEGIN_DECLS

typedef struct _GumMemoryAccessMonitor        GumMemoryAccessMonitor;
typedef struct _GumMemoryAccessMonitorClass   GumMemoryAccessMonitorClass;
typedef struct _GumMemoryAccessMonitorPrivate GumMemoryAccessMonitorPrivate;
typedef struct _GumMemoryAccessDetails        GumMemoryAccessDetails;

typedef void (* GumMemoryAccessNotify) (GumMemoryAccessMonitor * monitor,
    const GumMemoryAccessDetails * details, gpointer user_data);

struct _GumMemoryAccessMonitor
{
  GObject parent;

  GumMemoryAccessMonitorPrivate * priv;
};

struct _GumMemoryAccessMonitorClass
{
  GObjectClass parent_class;
};

struct _GumMemoryAccessDetails
{
  GumMemoryOperation operation;
  gpointer from;
  gpointer address;

  guint range_index;
  guint page_index;
  guint pages_completed;
  guint pages_total;
};

GUM_API GType gum_memory_access_monitor_get_type (void) G_GNUC_CONST;

GUM_API GumMemoryAccessMonitor * gum_memory_access_monitor_new (
    const GumMemoryRange * ranges, guint num_ranges, 
    GumPageProtection access_mask, gboolean auto_reset, 
    GumMemoryAccessNotify func, gpointer data, 
    GDestroyNotify data_destroy);

GUM_API gboolean gum_memory_access_monitor_enable (
    GumMemoryAccessMonitor * self, GError ** error);
GUM_API void gum_memory_access_monitor_disable (GumMemoryAccessMonitor * self);

G_END_DECLS

#endif
