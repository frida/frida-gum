/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 * Copyright (C) 2008 Christian Berentsen <christian.berentsen@tandberg.com>
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

#ifndef __PROFILER_HARNESS_H__
#define __PROFILER_HARNESS_H__

#include "gumprofiler.h"

#include "fakesampler.h"

typedef struct _ProfilerHarness ProfilerHarness;

struct _ProfilerHarness
{
  GumProfiler * profiler;

  GumSampler * sampler;
  GumFakeSampler * fake_sampler;
};

G_BEGIN_DECLS

void profiler_harness_setup (ProfilerHarness * h);
void profiler_harness_teardown (ProfilerHarness * h);

G_END_DECLS

#endif
