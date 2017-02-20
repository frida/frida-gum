/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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
