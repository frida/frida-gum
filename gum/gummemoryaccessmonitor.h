/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
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
typedef enum _GumMemoryOperation              GumMemoryOperation;

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

enum _GumMemoryOperation
{
  GUM_MEMOP_READ,
  GUM_MEMOP_WRITE,
  GUM_MEMOP_EXECUTE
};

struct _GumMemoryAccessDetails
{
  GumMemoryOperation operation;
  gpointer from;
  gpointer address;

  guint page_index;
  guint pages_completed;
  guint pages_remaining;
};

GUM_API GType gum_memory_access_monitor_get_type (void) G_GNUC_CONST;

GUM_API GumMemoryAccessMonitor * gum_memory_access_monitor_new (void);

GUM_API void gum_memory_access_monitor_enable (GumMemoryAccessMonitor * self,
    const GumMemoryRange * range, GumMemoryAccessNotify func, gpointer data);
GUM_API void gum_memory_access_monitor_disable (GumMemoryAccessMonitor * self);

G_END_DECLS

#endif
