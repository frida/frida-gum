/*
 * Copyright (C) 2010, 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2015 Eloi Vanderbeken <eloi.vanderbeken@synacktiv.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemoryaccessmonitor.h"

#include "gumexceptor.h"
#include "gumwindows.h"

#include <gio/gio.h>
#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

typedef struct _GumPageDetails GumPageDetails;
typedef struct _GumLiveRangeDetails GumLiveRangeDetails;
typedef struct _GumRangeStats GumRangeStats;

typedef gboolean (* GumFoundLiveRangeFunc) (
    const GumLiveRangeDetails * details, gpointer user_data);

struct _GumMemoryAccessMonitorPrivate
{
  guint page_size;

  gboolean enabled;
  GumExceptor * exceptor;

  GumMemoryRange * ranges;
  guint num_ranges;
  volatile gint pages_remaining;
  gint pages_total;

  GumPageProtection access_mask;
  GumPageDetails * pages_details;
  guint num_pages;
  gboolean auto_reset;

  GumMemoryAccessNotify notify_func;
  gpointer notify_data;
  GDestroyNotify notify_data_destroy;
};

struct _GumPageDetails
{
  guint range_index;
  gpointer address;
  gboolean is_guarded;
  DWORD original_protection;
  volatile guint completed;
};

struct _GumLiveRangeDetails
{
  const GumMemoryRange * range;
  guint range_index;
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

static gboolean gum_memory_access_monitor_on_exception (
    GumExceptionDetails * details, gpointer user_data);

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
                               GumPageProtection access_mask,
                               gboolean auto_reset,
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
  priv->access_mask = access_mask;
  priv->auto_reset = auto_reset;
  for (i = 0; i != num_ranges; i++)
  {
    GumMemoryRange * r = &priv->ranges[i];
    gsize aligned_start, aligned_end;
    guint num_pages;

    aligned_start = r->base_address & ~((gsize) priv->page_size - 1);
    aligned_end = (r->base_address + r->size + priv->page_size - 1) &
        ~((gsize) priv->page_size - 1);
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

  priv->exceptor = gum_exceptor_obtain ();
  gum_exceptor_add (priv->exceptor, gum_memory_access_monitor_on_exception,
      self);

  priv->num_pages = 0;
  priv->pages_details = NULL;
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

  gum_exceptor_remove (priv->exceptor, gum_memory_access_monitor_on_exception,
      self);
  g_object_unref (priv->exceptor);
  priv->exceptor = NULL;

  g_free (priv->pages_details);
  priv->num_pages = 0;
  priv->pages_details = NULL;
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
  GumMemoryAccessMonitorPrivate * priv = self->priv;
  DWORD old_prot, new_prot;
  BOOL success;
  gboolean is_guarded = FALSE;
  guint num_pages;

  new_prot = PAGE_NOACCESS;

  if ((priv->access_mask & GUM_PAGE_READ) != 0)
  {
    if (priv->auto_reset)
    {
      is_guarded = TRUE;
      new_prot = details->prot | PAGE_GUARD;
    }
    else
    {
      new_prot = PAGE_NOACCESS;
    }
  }
  else
  {
    switch (details->prot & 0xFF)
    {
    case PAGE_EXECUTE:
      if ((priv->access_mask & GUM_PAGE_EXECUTE) != 0)
        new_prot = PAGE_READONLY;
      else
        return TRUE;
      break;
    case PAGE_EXECUTE_READ:
      if ((priv->access_mask & GUM_PAGE_EXECUTE) != 0)
        new_prot = PAGE_READONLY;
      else
        return TRUE;
      break;
    case PAGE_EXECUTE_READWRITE:
      if (priv->access_mask == GUM_PAGE_WRITE)
        new_prot = PAGE_EXECUTE_READ;
      else if (priv->access_mask == (GUM_PAGE_EXECUTE | GUM_PAGE_WRITE))
        new_prot = PAGE_READONLY;
      else if (priv->access_mask == GUM_PAGE_EXECUTE)
        new_prot = PAGE_READWRITE;
      else
        g_assert_not_reached ();
      break;
    case PAGE_EXECUTE_WRITECOPY:
      if (priv->access_mask == GUM_PAGE_WRITE)
        new_prot = PAGE_EXECUTE_READ;
      else if (priv->access_mask == (GUM_PAGE_EXECUTE | GUM_PAGE_WRITE))
        new_prot = PAGE_READONLY;
      else if (priv->access_mask == GUM_PAGE_EXECUTE)
        new_prot = PAGE_WRITECOPY;
      else
        g_assert_not_reached ();
      break;
    case PAGE_NOACCESS:
      return TRUE;
    case PAGE_READONLY:
      return TRUE;
    case PAGE_READWRITE:
      if ((priv->access_mask & GUM_PAGE_WRITE) != 0)
        new_prot = PAGE_READONLY;
      else
        return TRUE;
      break;
    case PAGE_WRITECOPY:
      if ((priv->access_mask & GUM_PAGE_WRITE) != 0)
        new_prot = PAGE_READONLY;
      else
        return TRUE;
      break;
    default:
      g_assert_not_reached ();
    }
  }

  num_pages = priv->num_pages;

  priv->pages_details = g_realloc (priv->pages_details, 
      (num_pages + 1) * sizeof (priv->pages_details[0]));

  priv->pages_details[num_pages].range_index = details->range_index;
  priv->pages_details[num_pages].original_protection = details->prot;
  priv->pages_details[num_pages].address = 
      (gpointer) details->range->base_address;
  priv->pages_details[num_pages].is_guarded = is_guarded;
  priv->pages_details[num_pages].completed = 0;

  priv->num_pages++;

  success = VirtualProtect (GSIZE_TO_POINTER (details->range->base_address),
      details->range->size, new_prot, &old_prot);
  if (!success)
    g_atomic_int_add (&self->priv->pages_remaining, -1);

  return TRUE;
}

static gboolean
gum_clear_guard_flag (const GumLiveRangeDetails * details,
                      gpointer user_data)
{
  DWORD old_prot;
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR (user_data);
  GumMemoryAccessMonitorPrivate * priv = self->priv;
  guint i;

  for (i = 0; i != priv->num_pages; i++)
  {
    const GumPageDetails * page = &priv->pages_details[i];
    const GumMemoryRange * r = &priv->ranges[page->range_index];

    if (GUM_MEMORY_RANGE_INCLUDES (r, details->range->base_address))
    {
      return VirtualProtect ((void *) details->range->base_address,
          details->range->size, page->original_protection, &old_prot);
    }
  }
  return FALSE;
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

      /* force the iteration one page at a time */
      size = MIN (mbi.RegionSize, self->priv->page_size);

      details.range = &range;
      details.prot = mbi.Protect;
      details.range_index = i;

      range.base_address = GUM_ADDRESS (cur);
      range.size = MIN ((gsize) ((guint8 *) end - (guint8 *) cur),
          size - ((guint8 *) cur - (guint8 *) mbi.BaseAddress));

      carry_on = func (&details, user_data);

      cur = (guint8 *) mbi.BaseAddress + size;
    }
    while (cur < end && carry_on);
  }
}

static gboolean
gum_memory_access_monitor_on_exception (GumExceptionDetails * details,
                                        gpointer user_data)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR_CAST (user_data);
  const GumMemoryAccessMonitorPrivate * priv = self->priv;
  GumMemoryAccessDetails d;
  guint i;

  d.operation = details->memory.operation;
  d.from = details->address;
  d.address = details->memory.address;

  for (i = 0; i != priv->num_pages; i++)
  {
    const GumPageDetails * page = &priv->pages_details[i];
    const GumMemoryRange * r = &priv->ranges[page->range_index];
    guint operation_mask;
    guint operations_reported;
    guint pages_remaining;

    if ((page->address <= d.address) && 
        ((guint8 *) page->address + priv->page_size > (guint8*) d.address))
    {
      /* make sure that we don't misinterpret access violation / page guard */
      if (page->is_guarded)
      {
        if (details->type != GUM_EXCEPTION_GUARD_PAGE)
          return FALSE;
      }
      else if (details->type == GUM_EXCEPTION_ACCESS_VIOLATION)
      {
        GumPageProtection gum_original_protection = 
            gum_page_protection_from_windows (page->original_protection);
        switch (d.operation)
        {
        case GUM_MEMOP_READ:
          if ((gum_original_protection & GUM_PAGE_READ) == 0)
            return FALSE;
          break;
        case GUM_MEMOP_WRITE:
          if ((gum_original_protection & GUM_PAGE_WRITE) == 0)
            return FALSE;
          break;
        case GUM_MEMOP_EXECUTE:
          if ((gum_original_protection & GUM_PAGE_EXECUTE) == 0)
            return FALSE;
          break;
        default:
          g_assert_not_reached();
        }
      }
      else 
        return FALSE;

      /* restore the original protection if needed */
      if (priv->auto_reset && !page->is_guarded)
      {
        DWORD old_prot;
        /* may be called multiple times in case of simultaneous access
         * but it should not be a problem */
        VirtualProtect (
            (guint8 *) d.address - (((guintptr) d.address) % priv->page_size),
            priv->page_size, page->original_protection, &old_prot);
      }

      /* if an operation was already reported, don't report it. */
      operation_mask = 1 << d.operation;
      operations_reported = g_atomic_int_or (&page->completed, operation_mask);
      if ((operations_reported != 0) && priv->auto_reset)
        return FALSE;

      pages_remaining;
      if (!operations_reported)
        pages_remaining = g_atomic_int_add (&priv->pages_remaining, -1) - 1;
      else
        pages_remaining = g_atomic_int_get (&priv->pages_remaining);
      d.pages_completed = priv->pages_total - pages_remaining;

      d.range_index = page->range_index;
      d.page_index = (guint8 *) d.address - (guint8 *) r->base_address;
      d.page_index = d.page_index / priv->page_size;
      d.pages_total = priv->pages_total;

      priv->notify_func (self, &d, priv->notify_data);

      return TRUE;
    }
  }

  return FALSE;
}
