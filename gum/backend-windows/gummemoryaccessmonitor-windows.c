/*
 * Copyright (C) 2010, 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemoryaccessmonitor.h"

#include "gumwinexceptionhook.h"

#include <gio/gio.h>

typedef struct _GumLiveRangeDetails GumLiveRangeDetails;
typedef struct _GumRangeStats GumRangeStats;

typedef gboolean (* GumFoundLiveRangeFunc) (
    const GumLiveRangeDetails * details, gpointer user_data);

struct _GumMemoryAccessMonitorPrivate
{
  guint page_size;

  gboolean enabled;

  GumMemoryRange * ranges;
  guint num_ranges;
  volatile gint pages_remaining;
  gint pages_total;

  GumMemoryAccessNotify notify_func;
  gpointer notify_data;
  GDestroyNotify notify_data_destroy;
};

struct _GumLiveRangeDetails
{
  const GumMemoryRange * range;
  DWORD prot;
};

struct _GumRangeStats
{
  guint live_size;
  guint guarded_size;
};

static void gum_memory_access_monitor_dispose (GObject * object);
static void gum_memory_access_monitor_finalize (GObject * object);

static gboolean gum_collect_range_stats (const GumLiveRangeDetails * details,
    gpointer user_data);
static gboolean gum_set_guard_flag (const GumLiveRangeDetails * details,
    gpointer user_data);
static gboolean gum_clear_guard_flag (const GumLiveRangeDetails * details,
    gpointer user_data);

static void gum_memory_access_monitor_enumerate_live_ranges (
    GumMemoryAccessMonitor * self, GumFoundLiveRangeFunc func,
    gpointer user_data);

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

  object_class->dispose = gum_memory_access_monitor_dispose;
  object_class->finalize = gum_memory_access_monitor_finalize;
}

static void
gum_memory_access_monitor_init (GumMemoryAccessMonitor * self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_MEMORY_ACCESS_MONITOR, GumMemoryAccessMonitorPrivate);

  self->priv->page_size = gum_query_page_size ();
}

static void
gum_memory_access_monitor_dispose (GObject * object)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR_CAST (object);
  GumMemoryAccessMonitorPrivate * priv = self->priv;

  gum_memory_access_monitor_disable (self);

  if (priv->notify_data_destroy != NULL)
  {
    priv->notify_data_destroy (priv->notify_data);
    priv->notify_data_destroy = NULL;
  }
  priv->notify_data = NULL;
  priv->notify_func = NULL;

  G_OBJECT_CLASS (gum_memory_access_monitor_parent_class)->dispose (object);
}

static void
gum_memory_access_monitor_finalize (GObject * object)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR_CAST (object);
  GumMemoryAccessMonitorPrivate * priv = self->priv;

  g_free (priv->ranges);

  G_OBJECT_CLASS (gum_memory_access_monitor_parent_class)->finalize (object);
}

GumMemoryAccessMonitor *
gum_memory_access_monitor_new (const GumMemoryRange * ranges,
                               guint num_ranges,
                               GumMemoryAccessNotify func,
                               gpointer data,
                               GDestroyNotify data_destroy)
{
  GumMemoryAccessMonitor * monitor;
  GumMemoryAccessMonitorPrivate * priv;
  guint i;

  monitor = GUM_MEMORY_ACCESS_MONITOR_CAST (
      g_object_new (GUM_TYPE_MEMORY_ACCESS_MONITOR, NULL));
  priv = monitor->priv;

  priv->ranges = g_memdup (ranges, num_ranges * sizeof (GumMemoryRange));
  priv->num_ranges = num_ranges;
  for (i = 0; i != num_ranges; i++)
  {
    GumMemoryRange * r = &priv->ranges[i];
    gsize aligned_start, aligned_end;
    guint num_pages;

    aligned_start = r->base_address & ~(priv->page_size - 1);
    aligned_end = (r->base_address + r->size + priv->page_size - 1) &
        ~(priv->page_size - 1);
    r->base_address = aligned_start;
    r->size = aligned_end - aligned_start;

    num_pages = r->size / priv->page_size;
    g_atomic_int_add (&priv->pages_remaining, num_pages);
    priv->pages_total += num_pages;
  }

  priv->notify_func = func;
  priv->notify_data = data;
  priv->notify_data_destroy = data_destroy;

  return monitor;
}

gboolean
gum_memory_access_monitor_enable (GumMemoryAccessMonitor * self,
                                  GError ** error)
{
  GumMemoryAccessMonitorPrivate * priv = self->priv;
  GumRangeStats stats;

  if (priv->enabled)
    return TRUE;

  stats.live_size = 0;
  stats.guarded_size = 0;
  gum_memory_access_monitor_enumerate_live_ranges (self,
      gum_collect_range_stats, &stats);

  if (stats.live_size != priv->pages_total * priv->page_size)
    goto error_invalid_pages;
  else if (stats.guarded_size != 0)
    goto error_guarded_pages;

  gum_win_exception_hook_add (
      gum_memory_access_monitor_handle_exception_if_ours, self);

  gum_memory_access_monitor_enumerate_live_ranges (self,
      gum_set_guard_flag, self);

  priv->enabled = TRUE;

  return TRUE;

error_invalid_pages:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "one or more pages are unallocated");
    return FALSE;
  }
error_guarded_pages:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "one or more pages already have the guard bit set");
    return FALSE;
  }
}

void
gum_memory_access_monitor_disable (GumMemoryAccessMonitor * self)
{
  GumMemoryAccessMonitorPrivate * priv = self->priv;

  if (!priv->enabled)
    return;

  gum_memory_access_monitor_enumerate_live_ranges (self,
      gum_clear_guard_flag, self);

  gum_win_exception_hook_remove (
      gum_memory_access_monitor_handle_exception_if_ours, self);

  priv->enabled = FALSE;
}

static gboolean
gum_collect_range_stats (const GumLiveRangeDetails * details,
                         gpointer user_data)
{
  GumRangeStats * stats = (GumRangeStats *) user_data;

  stats->live_size += details->range->size;
  if ((details->prot & PAGE_GUARD) == PAGE_GUARD)
    stats->guarded_size += details->range->size;

  return TRUE;
}

static gboolean
gum_set_guard_flag (const GumLiveRangeDetails * details,
                    gpointer user_data)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR (user_data);
  DWORD old_prot;
  BOOL success;

  success = VirtualProtect (GSIZE_TO_POINTER (details->range->base_address),
      details->range->size, details->prot | PAGE_GUARD, &old_prot);
  if (!success)
    g_atomic_int_add (&self->priv->pages_remaining, -1);

  return TRUE;
}

static gboolean
gum_clear_guard_flag (const GumLiveRangeDetails * details,
                      gpointer user_data)
{
  DWORD old_prot;

  (void) user_data;

  VirtualProtect (GSIZE_TO_POINTER (details->range->base_address),
      details->range->size, details->prot & ~PAGE_GUARD, &old_prot);

  return TRUE;
}

static void
gum_memory_access_monitor_enumerate_live_ranges (GumMemoryAccessMonitor * self,
                                                 GumFoundLiveRangeFunc func,
                                                 gpointer user_data)
{
  GumMemoryAccessMonitorPrivate * priv = self->priv;
  guint i;
  gboolean carry_on = TRUE;

  for (i = 0; i != priv->num_ranges && carry_on; i++)
  {
    GumMemoryRange * r = &priv->ranges[i];
    gpointer cur = GSIZE_TO_POINTER (r->base_address);
    gpointer end = GSIZE_TO_POINTER (r->base_address + r->size);

    do
    {
      MEMORY_BASIC_INFORMATION mbi;
      SIZE_T size;
      GumLiveRangeDetails details;
      GumMemoryRange range;

      size = VirtualQuery (cur, &mbi, sizeof (mbi));
      if (size == 0)
        break;

      details.range = &range;
      details.prot = mbi.Protect;

      range.base_address = GUM_ADDRESS (cur);
      range.size = MIN ((gsize) ((guint8 *) end - (guint8 *) cur),
          mbi.RegionSize - ((guint8 *) cur - (guint8 *) mbi.BaseAddress));

      carry_on = func (&details, user_data);

      cur = (guint8 *) mbi.BaseAddress + mbi.RegionSize;
    }
    while (cur < end && carry_on);
  }
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
  guint i;

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

  for (i = 0; i != priv->num_ranges; i++)
  {
    const GumMemoryRange * r = &priv->ranges[i];

    if (GUM_MEMORY_RANGE_INCLUDES (r, GUM_ADDRESS (details.address)))
    {
      details.range_index = i;
      details.page_index = ((guint8 *) details.address -
          (guint8 *) r->base_address) / priv->page_size;
      details.pages_completed = priv->pages_total -
          (g_atomic_int_add (&priv->pages_remaining, -1) - 1);
      details.pages_total = priv->pages_total;

      priv->notify_func (self, &details, priv->notify_data);

      return TRUE;
    }
  }

  return FALSE;
}
