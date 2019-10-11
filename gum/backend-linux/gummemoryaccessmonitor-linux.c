/*
 * Copyright (C) 2010-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2019 Álvaro Felipe Melchor <alvaro.felipe91@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemoryaccessmonitor.h"

#include "gumexceptor.h"
#include "gumlinux.h"

#include <gio/gio.h>
#include <sys/mman.h>

typedef struct _GumRangeStats GumRangeStats;
typedef struct _GumPageDetails GumPageDetails;

typedef gboolean (* GumFoundLiveRangeFunc) (const GumPageDetails * details,
    gpointer user_data);

struct _GumMemoryAccessMonitor
{
  GObject parent;

  guint page_size;

  gboolean enabled;
  GumExceptor * exceptor;

  GumMemoryRange * ranges;
  guint num_ranges;
  volatile gint pages_remaining;
  gint pages_total;

  GumPageProtection access_mask;
  GArray * pages;
  gboolean auto_reset;

  GumMemoryAccessNotify notify_func;
  gpointer notify_data;
  GDestroyNotify notify_data_destroy;
};

struct _GumPageDetails
{
  GumLinuxRange range;
  guint range_index;
  volatile guint completed;
};

struct _GumRangeStats
{
  guint live_size;
  guint guarded_size;
};

static void gum_memory_access_monitor_dispose (GObject * object);
static void gum_memory_access_monitor_finalize (GObject * object);

static gboolean gum_collect_range_stats (const GumPageDetails * details,
    gpointer user_data);
static void gum_memory_access_monitor_enumerate_live_ranges (
    GumMemoryAccessMonitor * self, GumFoundLiveRangeFunc func,
    gpointer user_data);
static void gum_linux_free_ranges (gpointer data);
static gboolean gum_linux_set_flag (const GumPageDetails * details,
    gpointer user_data);
static gboolean gum_linux_clear_flag (const GumPageDetails * details,
    gpointer user_data);
static gboolean gum_memory_access_monitor_on_exception (
    GumExceptionDetails * details, gpointer user_data);

G_DEFINE_TYPE (GumMemoryAccessMonitor, gum_memory_access_monitor, G_TYPE_OBJECT)

static void
gum_memory_access_monitor_class_init (GumMemoryAccessMonitorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_memory_access_monitor_dispose;
  object_class->finalize = gum_memory_access_monitor_finalize;
}

static void
gum_memory_access_monitor_init (GumMemoryAccessMonitor * self)
{
  self->page_size = gum_query_page_size ();
}

static void
gum_memory_access_monitor_dispose (GObject * object)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR (object);

  gum_memory_access_monitor_disable (self);

  if (self->notify_data_destroy != NULL)
    g_clear_pointer (&self->notify_data, self->notify_data_destroy);

  self->notify_data = NULL;
  self->notify_func = NULL;

  G_OBJECT_CLASS (gum_memory_access_monitor_parent_class)->dispose (object);
}

static void
gum_memory_access_monitor_finalize (GObject * object)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR (object);

  g_free (self->ranges);

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
  guint i;

  monitor = g_object_new (GUM_TYPE_MEMORY_ACCESS_MONITOR, NULL);
  monitor->ranges = g_memdup (ranges, num_ranges * sizeof (GumMemoryRange));
  monitor->num_ranges = num_ranges;
  monitor->access_mask = access_mask;
  monitor->auto_reset = auto_reset;
  monitor->pages_total = 0;

  for (i = 0; i != num_ranges; i++)
  {
    GumMemoryRange * r = &monitor->ranges[i];
    gsize aligned_start, aligned_end;
    guint num_pages;

    aligned_start = r->base_address & ~((gsize) monitor->page_size - 1);
    aligned_end = (r->base_address + r->size + monitor->page_size - 1) &
        ~((gsize) monitor->page_size - 1);
    r->base_address = aligned_start;
    r->size = aligned_end - aligned_start;

    num_pages = r->size / monitor->page_size;
    g_atomic_int_add (&monitor->pages_remaining, num_pages);
    monitor->pages_total += num_pages;
  }

  monitor->notify_func = func;
  monitor->notify_data = data;
  monitor->notify_data_destroy = data_destroy;

  return monitor;
}

gboolean
gum_memory_access_monitor_enable (GumMemoryAccessMonitor * self,
                                  GError ** error)
{
  GumRangeStats stats;

  if (self->enabled)
    return TRUE;

  stats.live_size = 0;
  stats.guarded_size = 0;

  gum_memory_access_monitor_enumerate_live_ranges (self,
      gum_collect_range_stats, &stats);

  if (stats.live_size != self->pages_total * self->page_size)
    goto error_invalid_pages;
  else if (stats.guarded_size != 0)
    goto error_guarded_pages;

  self->exceptor = gum_exceptor_obtain ();
  gum_exceptor_add (self->exceptor, gum_memory_access_monitor_on_exception,
      self);

  self->pages = g_array_new (FALSE, FALSE, sizeof (GumPageDetails));

  gum_memory_access_monitor_enumerate_live_ranges (self, gum_linux_set_flag,
      self);

  self->enabled = TRUE;

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
        "one or more pages already have PROT_NONE set");
    return FALSE;
  }
}

static gboolean
gum_collect_range_stats (const GumPageDetails * details,
                         gpointer user_data)
{
  GumRangeStats * stats = (GumRangeStats *) user_data;
  const GumLinuxRange * range = &details->range;

  stats->live_size += range->size;
  if (range->prot == GUM_PAGE_NO_ACCESS)
    stats->guarded_size += range->size;

  return TRUE;
}

void
gum_memory_access_monitor_disable (GumMemoryAccessMonitor * self)
{
  if (!self->enabled)
    return;

  gum_memory_access_monitor_enumerate_live_ranges (self,
      gum_linux_clear_flag, self);

  gum_exceptor_remove (self->exceptor, gum_memory_access_monitor_on_exception,
      self);
  g_object_unref (self->exceptor);
  self->exceptor = NULL;

  g_array_free (self->pages, TRUE);

  self->pages = NULL;
  self->enabled = FALSE;
}

static void
gum_memory_access_monitor_enumerate_live_ranges (GumMemoryAccessMonitor * self,
                                                 GumFoundLiveRangeFunc func,
                                                 gpointer user_data)
{
  GList * head;
  guint i;
  gboolean carry_on = TRUE;

  head = gum_linux_collect_ranges ();

  for (i = 0; i != self->num_ranges && carry_on; i++)
  {
    GList * range = head;
    GumMemoryRange * r = &self->ranges[i];
    GumAddress cur = r->base_address;
    GumAddress end = cur + r->size;

    while ((range = g_list_next (range)))
    {
      GumLinuxRange * lr = (GumLinuxRange *) range->data;

      do
      {
        if (cur >= lr->base && cur + self->page_size - 1 < lr->base + lr->size)
        {
          GumPageDetails details;

          details.range.base = cur;
          details.range.size = self->page_size;
          details.range.prot = lr->prot;
          details.range_index = i;
          details.completed = 0;

          carry_on = func (&details, user_data);

          cur += self->page_size;
        }
        else
        {
          break;
        }
      }
      while (cur < end && carry_on);
    }
  }

  g_list_free_full (head, gum_linux_free_ranges);
}

static void
gum_linux_free_ranges (gpointer data)
{
  g_slice_free (GumLinuxRange, data);
}

static gboolean
gum_linux_set_flag (const GumPageDetails * details,
                    gpointer user_data)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR (user_data);
  const GumLinuxRange * range = &details->range;
  GumPageProtection access_mask = self->access_mask;
  GumPageProtection new_prot = GUM_PAGE_NO_ACCESS;

  switch (range->prot)
  {
    case GUM_PAGE_READ:
      if ((access_mask & GUM_PAGE_READ) != 0)
        new_prot = GUM_PAGE_WRITE;
      else
        return TRUE;
      break;
    case GUM_PAGE_WRITE:
      if ((access_mask & GUM_PAGE_WRITE) != 0)
        new_prot = GUM_PAGE_READ;
      else
        return TRUE;
      break;
    case GUM_PAGE_EXECUTE:
      if ((access_mask & GUM_PAGE_EXECUTE) != 0)
        new_prot = GUM_PAGE_WRITE;
      else
        return TRUE;
      break;
    case GUM_PAGE_RW:
      if (access_mask == GUM_PAGE_WRITE)
        new_prot = GUM_PAGE_READ;
      else if (access_mask == GUM_PAGE_READ || access_mask == GUM_PAGE_EXECUTE)
        new_prot = GUM_PAGE_WRITE;
      else if (access_mask == (GUM_PAGE_EXECUTE | GUM_PAGE_WRITE))
        new_prot = GUM_PAGE_NO_ACCESS;
      break;
    case GUM_PAGE_RX:
      if (access_mask == GUM_PAGE_READ ||
          access_mask == GUM_PAGE_EXECUTE ||
          access_mask == GUM_PAGE_RX)
        new_prot = GUM_PAGE_WRITE;
      else
        return TRUE;
      break;
    case GUM_PAGE_RWX:
      new_prot = GUM_PAGE_NO_ACCESS;
      break;
    default:
      g_assert_not_reached ();
  }

  g_array_append_val (self->pages, *details);

  gum_mprotect (GSIZE_TO_POINTER (range->base), range->size, new_prot);

  return TRUE;
}

static gboolean
gum_linux_clear_flag (const GumPageDetails * details,
                      gpointer user_data)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR (user_data);
  const GumLinuxRange * range = &details->range;
  guint i;

  for (i = 0; i != self->pages->len; i++)
  {
    const GumPageDetails * page = 
      &g_array_index (self->pages, GumPageDetails, i);
    const GumLinuxRange * r = &page->range;

    if (range->base >= r->base &&
        range->base + range->size - 1 < r->base + r->size)
    {
      gum_mprotect (GSIZE_TO_POINTER (r->base), r->size, r->prot);
      return TRUE;
    }
  }

  return FALSE;
}

static gboolean
gum_memory_access_monitor_on_exception (GumExceptionDetails * details,
                                        gpointer user_data)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR (user_data);
  GumMemoryAccessDetails d;
  guint i;

  if (details->type != GUM_EXCEPTION_ACCESS_VIOLATION)
    return FALSE;

  d.operation = details->memory.operation;
  d.from = details->address;
  d.address = details->memory.address;

  for (i = 0; i != self->pages->len; i++)
  {
    GumPageDetails * page = &g_array_index (self->pages, GumPageDetails, i);
    const GumLinuxRange * range = &page->range;
    const GumMemoryRange * r = &self->ranges[page->range_index];
    guint operation_mask;
    guint operations_reported;
    guint pages_remaining;

    if ((GPOINTER_TO_SIZE (d.address) >= range->base) &&
        GPOINTER_TO_SIZE (d.address) < range->base + self->page_size)
    {
      GumPageProtection original_prot = range->prot;
      switch (d.operation)
      {
        case GUM_MEMOP_READ:
          if ((original_prot & GUM_PAGE_READ) == 0)
            return FALSE;
          break;
        case GUM_MEMOP_WRITE:
          if ((original_prot & GUM_PAGE_WRITE) == 0)
            return FALSE;
          break;
        case GUM_MEMOP_EXECUTE:
          if ((original_prot & GUM_PAGE_WRITE) == 0)
            return FALSE;
          break;
        default:
          g_assert_not_reached ();
      }

      if (self->auto_reset)
        gum_mprotect (GSIZE_TO_POINTER (range->base), range->size, range->prot);

      operation_mask = 1 << d.operation;
      operations_reported = g_atomic_int_or (&page->completed, operation_mask);
      if (operations_reported != 0 && self->auto_reset)
        return FALSE;
      if (!operations_reported)
        pages_remaining = g_atomic_int_add (&self->pages_remaining, -1) - 1;
      else
        pages_remaining = g_atomic_int_get (&self->pages_remaining);
      d.pages_completed = self->pages_total - pages_remaining;

      d.range_index = page->range_index;
      d.page_index = (guint8 *) d.address - (guint8 *) r->base_address;
      d.page_index = d.page_index / self->page_size;
      d.pages_total = self->pages_total;

      self->notify_func (self, &d, self->notify_data);

      return TRUE;
    }
  }

  return FALSE;
}
