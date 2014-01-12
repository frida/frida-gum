/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumsampler.h"

#include "testutil.h"

#include <stdlib.h>

#if defined (G_OS_WIN32) || defined (HAVE_DARWIN)
# define HAVE_BUSY_CYCLE_SAMPLER
#endif

#define SAMPLER_TESTCASE(NAME) \
    void test_sampler_ ## NAME ( \
        TestSamplerFixture * fixture, gconstpointer data)
#define SAMPLER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Prof/Sampler", test_sampler, NAME, \
        TestSamplerFixture)

typedef struct _TestSamplerFixture
{
  GumSampler * sampler;
} TestSamplerFixture;

static void
test_sampler_fixture_setup (TestSamplerFixture * fixture,
                            gconstpointer data)
{
}

static void
test_sampler_fixture_teardown (TestSamplerFixture * fixture,
                               gconstpointer data)
{
  if (fixture->sampler != NULL)
    g_object_unref (fixture->sampler);
}
