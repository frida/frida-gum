/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsampler.h"

#include "testutil.h"
#include "valgrind.h"

#include <stdlib.h>

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
