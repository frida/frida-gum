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

#include "gummemoryaccessmonitor.h"

#ifdef G_OS_WIN32
# include "backend-windows/gumwinexceptionhook.h"
#else
# error PORTME
#endif

struct _GumMemoryAccessMonitorPrivate
{
  gboolean enabled;
  GumMemoryRange range;
  GumMemoryAccessNotify notify_func;
  gpointer notify_data;

  DWORD old_protect;
};

static void gum_memory_access_monitor_finalize (GObject * object);

static gboolean gum_memory_access_monitor_handle_exception_if_ours (
    EXCEPTION_RECORD * exception_record, CONTEXT * context,
    gpointer user_data);

G_DEFINE_TYPE (GumMemoryAccessMonitor, gum_memory_access_monitor,
    G_TYPE_OBJECT);

static void
gum_memory_access_monitor_class_init (GumMemoryAccessMonitorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumMemoryAccessMonitorPrivate));

  object_class->finalize = gum_memory_access_monitor_finalize;
}

static void
gum_memory_access_monitor_init (GumMemoryAccessMonitor * self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_MEMORY_ACCESS_MONITOR, GumMemoryAccessMonitorPrivate);
}

static void
gum_memory_access_monitor_finalize (GObject * object)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR_CAST (object);

  if (self->priv->enabled)
    gum_memory_access_monitor_disable (self);

  G_OBJECT_CLASS (gum_memory_access_monitor_parent_class)->finalize (object);
}

GumMemoryAccessMonitor *
gum_memory_access_monitor_new (void)
{
  return GUM_MEMORY_ACCESS_MONITOR_CAST (
      g_object_new (GUM_TYPE_MEMORY_ACCESS_MONITOR, NULL));
}

void
gum_memory_access_monitor_enable (GumMemoryAccessMonitor * self,
                                  const GumMemoryRange * range,
                                  GumMemoryAccessNotify func,
                                  gpointer data)
{
  GumMemoryAccessMonitorPrivate * priv = self->priv;
  guint page_size;
  MEMORY_BASIC_INFORMATION mbi;
  SIZE_T ret;
  BOOL success;

  g_assert (!priv->enabled);

  page_size = gum_query_page_size ();
  g_assert (range->size % page_size == 0);

  ret = VirtualQuery (range->base_address, &mbi, sizeof (mbi));
  g_assert (ret != 0);
  g_assert (range->base_address == mbi.BaseAddress);
  g_assert_cmpuint (range->size, ==, mbi.RegionSize);

  priv->enabled = TRUE;
  priv->range = *range;
  priv->notify_func = func;
  priv->notify_data = data;

  gum_win_exception_hook_add (
      gum_memory_access_monitor_handle_exception_if_ours, self);

  success = VirtualProtect (range->base_address, range->size,
      mbi.Protect | PAGE_GUARD, &priv->old_protect);
  g_assert (success);
}

void
gum_memory_access_monitor_disable (GumMemoryAccessMonitor * self)
{
  GumMemoryAccessMonitorPrivate * priv = self->priv;
  DWORD old_protect;
  BOOL success;

  g_assert (priv->enabled);

  priv->enabled = FALSE;

  success = VirtualProtect (priv->range.base_address, priv->range.size,
      priv->old_protect, &old_protect);
  g_assert (success);

  gum_win_exception_hook_remove (
      gum_memory_access_monitor_handle_exception_if_ours);
}

static gboolean
gum_memory_access_monitor_handle_exception_if_ours (
    EXCEPTION_RECORD * exception_record,
    CONTEXT * context,
    gpointer user_data)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR_CAST (user_data);
  GumMemoryAccessMonitorPrivate * priv = self->priv;
  GumMemoryAccessDetails details;

  (void) context;

  if (exception_record->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
    return FALSE;

  switch (exception_record->ExceptionInformation[0])
  {
    case 0: details.operation = GUM_MEMOP_READ; break;
    case 1: details.operation = GUM_MEMOP_WRITE; break;
    case 8: details.operation = GUM_MEMOP_EXECUTE; break;
    default:
      g_assert_not_reached ();
  }
  details.from = exception_record->ExceptionAddress;
  details.address = (gpointer) exception_record->ExceptionInformation[1];

  if (!GUM_MEMORY_RANGE_INCLUDES (&priv->range, details.address))
    return FALSE;

  priv->notify_func (self, &details, priv->notify_data);

  return TRUE;
}