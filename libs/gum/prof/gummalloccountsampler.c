/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummalloccountsampler.h"

#include "gumcallcountsampler.h"

#include <stdlib.h>

GumSampler *
gum_malloc_count_sampler_new (void)
{
  return gum_call_count_sampler_new (
      GUM_FUNCPTR_TO_POINTER (malloc),
      GUM_FUNCPTR_TO_POINTER (calloc),
      GUM_FUNCPTR_TO_POINTER (realloc),
      NULL);
}
