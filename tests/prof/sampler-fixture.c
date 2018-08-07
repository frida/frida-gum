/*
 * Copyright (C) 2008-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
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
  g_clear_object (&fixture->sampler);
}
