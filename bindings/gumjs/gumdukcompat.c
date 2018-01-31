/*
 * Copyright (C) 2017-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukcompat.h"

#include <math.h>

double
gum_duk_log2 (double x)
{
#ifdef HAVE_LOG2
  return log2 (x);
#else
  return log (x) / log (2);
#endif
}

double
gum_duk_date_get_now (void)
{
  return (double) (g_get_real_time () / G_GINT64_CONSTANT (1000));
}

double
gum_duk_date_get_monotonic_time (void)
{
  return (double) (g_get_monotonic_time () / G_GINT64_CONSTANT (1000));
}
