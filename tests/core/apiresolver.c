/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "apiresolver-fixture.c"

TEST_LIST_BEGIN (api_resolver)
  API_RESOLVER_TESTENTRY (module_exports_can_be_resolved)
  API_RESOLVER_TESTENTRY (module_imports_can_be_resolved)
  API_RESOLVER_TESTENTRY (objc_methods_can_be_resolved)
TEST_LIST_END ()

API_RESOLVER_TESTCASE (module_exports_can_be_resolved)
{
  TestForEachContext ctx;
  GError * error = NULL;
#ifdef G_OS_WIN32
  const gchar * query = "exports:*!_open*";
#else
  const gchar * query = "exports:*!open*";
#endif

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert (fixture->resolver != NULL);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_api_resolver_enumerate_matches (fixture->resolver, query, match_found_cb,
      &ctx, &error);
  g_assert (error == NULL);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_api_resolver_enumerate_matches (fixture->resolver, query, match_found_cb,
      &ctx, &error);
  g_assert (error == NULL);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

API_RESOLVER_TESTCASE (module_imports_can_be_resolved)
{
#ifdef HAVE_DARWIN
  GError * error = NULL;
  const gchar * query = "imports:gum-tests!*";
  guint number_of_imports_seen = 0;

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert (fixture->resolver != NULL);

  gum_api_resolver_enumerate_matches (fixture->resolver, query,
      check_module_import, &number_of_imports_seen, &error);
  g_assert (error == NULL);
#else
  (void) check_module_import;
#endif
}

static gboolean
check_module_import (const GumApiDetails * details,
                     gpointer user_data)
{
  guint * number_of_imports_seen = user_data;

  g_assert (strstr (details->name, "gum-tests") == NULL);

  (*number_of_imports_seen)++;

  return TRUE;
}

API_RESOLVER_TESTCASE (objc_methods_can_be_resolved)
{
  TestForEachContext ctx;
  GError * error = NULL;

  fixture->resolver = gum_api_resolver_make ("objc");
  if (fixture->resolver == NULL)
  {
    g_print ("<skipping, not available> ");
    return;
  }

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_api_resolver_enumerate_matches (fixture->resolver, "+[*Arr* arr*]",
      match_found_cb, &ctx, &error);
  g_assert (error == NULL);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_api_resolver_enumerate_matches (fixture->resolver, "+[*Arr* arr*]",
      match_found_cb, &ctx, &error);
  g_assert (error == NULL);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

static gboolean
match_found_cb (const GumApiDetails * details,
                gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}
