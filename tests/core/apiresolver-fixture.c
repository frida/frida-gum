/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumapiresolver.h"

#include "testutil.h"

#include <string.h>

#define API_RESOLVER_TESTCASE(NAME) \
    void test_api_resolver_ ## NAME ( \
        TestApiResolverFixture * fixture, gconstpointer data)
#define API_RESOLVER_TESTENTRY(NAME) \
    TEST_ENTRY_WITH_FIXTURE ("Core/ApiResolver", test_api_resolver, NAME, \
        TestApiResolverFixture)

typedef struct _TestApiResolverFixture TestApiResolverFixture;
typedef struct _TestForEachContext TestForEachContext;

struct _TestApiResolverFixture
{
  GumApiResolver * resolver;
};

struct _TestForEachContext
{
  gboolean value_to_return;
  guint number_of_calls;
};

static void
test_api_resolver_fixture_setup (TestApiResolverFixture * fixture,
                                 gconstpointer data)
{
}

static void
test_api_resolver_fixture_teardown (TestApiResolverFixture * fixture,
                                    gconstpointer data)
{
  g_clear_object (&fixture->resolver);
}

static gboolean check_module_import (const GumApiDetails * details,
    gpointer user_data);
static gboolean match_found_cb (const GumApiDetails * details,
    gpointer user_data);
