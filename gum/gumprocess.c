/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "gumcloak.h"

typedef struct _GumEmitRangesContext GumEmitRangesContext;

struct _GumEmitRangesContext
{
  GumFoundRangeFunc func;
  gpointer user_data;
};

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

  if (gum_cloak_has_base_address (details->range->base_address))
    return TRUE;

  return ctx->func (details, ctx->user_data);
}
