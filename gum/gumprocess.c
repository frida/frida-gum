/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "gumcloak.h"

typedef struct _GumEmitThreadsContext GumEmitThreadsContext;
typedef struct _GumEmitRangesContext GumEmitRangesContext;

struct _GumEmitThreadsContext
{
  GumFoundThreadFunc func;
  gpointer user_data;
};

struct _GumEmitRangesContext
{
  GumFoundRangeFunc func;
  gpointer user_data;
};

static gboolean gum_emit_thread_if_not_cloaked (
    const GumThreadDetails * details, gpointer user_data);
static gboolean gum_emit_range_if_not_cloaked (const GumRangeDetails * details,
    gpointer user_data);

GumOS
gum_process_get_native_os (void)
{
#if defined (G_OS_WIN32)
  return GUM_OS_WINDOWS;
#elif defined (HAVE_MAC)
  return GUM_OS_MAC;
#elif defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
  return GUM_OS_LINUX;
#elif defined (HAVE_IOS)
  return GUM_OS_IOS;
#elif defined (HAVE_ANDROID)
  return GUM_OS_ANDROID;
#elif defined (HAVE_QNX)
  return GUM_OS_QNX;
#else
# error Unknown OS
#endif
}

void
gum_process_enumerate_threads (GumFoundThreadFunc func,
                               gpointer user_data)
{
  GumEmitThreadsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  _gum_process_enumerate_threads (gum_emit_thread_if_not_cloaked, &ctx);
}

static gboolean
gum_emit_thread_if_not_cloaked (const GumThreadDetails * details,
                                gpointer user_data)
{
  GumEmitThreadsContext * ctx = user_data;

  if (gum_cloak_has_thread (details->id))
    return TRUE;

  return ctx->func (details, ctx->user_data);
}

void
gum_process_enumerate_ranges (GumPageProtection prot,
                              GumFoundRangeFunc func,
                              gpointer user_data)
{
  GumEmitRangesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  _gum_process_enumerate_ranges (prot, gum_emit_range_if_not_cloaked, &ctx);
}

static gboolean
gum_emit_range_if_not_cloaked (const GumRangeDetails * details,
                               gpointer user_data)
{
  GumEmitRangesContext * ctx = user_data;
  GArray * sub_ranges;

  sub_ranges = gum_cloak_clip_range (details->range);
  if (sub_ranges != NULL)
  {
    gboolean carry_on = TRUE;
    GumRangeDetails sub_details;
    guint i;

    sub_details.prot = details->prot;
    sub_details.file = details->file;

    for (i = 0; i != sub_ranges->len && carry_on; i++)
    {
      sub_details.range = &g_array_index (sub_ranges, GumMemoryRange, i);

      carry_on = ctx->func (&sub_details, ctx->user_data);
    }

    g_array_free (sub_ranges, TRUE);

    return carry_on;
  }

  return ctx->func (details, ctx->user_data);
}
