/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
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
