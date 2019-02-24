/*
 * Copyright (C) 2016-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "apiresolver-fixture.c"

TESTLIST_BEGIN (api_resolver)
  TESTENTRY (module_exports_can_be_resolved)
  TESTENTRY (module_imports_can_be_resolved)
  TESTENTRY (objc_methods_can_be_resolved)

#ifdef HAVE_ANDROID
  TESTENTRY (linker_exports_can_be_resolved_on_android)
#endif
TESTLIST_END ()

TESTCASE (module_exports_can_be_resolved)
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

TESTCASE (module_imports_can_be_resolved)
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

TESTCASE (objc_methods_can_be_resolved)
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

#ifdef HAVE_ANDROID

typedef struct _TestLinkerExportsContext TestLinkerExportsContext;

struct _TestLinkerExportsContext
{
  guint number_of_calls;
  GumAddress expected_address;
};

static gboolean check_linker_export (const GumApiDetails * details,
    gpointer user_data);

TESTCASE (linker_exports_can_be_resolved_on_android)
{
  const gchar * linker_name = (sizeof (gpointer) == 4)
      ? "/system/bin/linker"
      : "/system/bin/linker64";
  const gchar * linker_exports[] =
  {
    "dlopen",
    "dlsym",
    "dlclose",
    "dlerror",
  };
  guint i;

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert (fixture->resolver != NULL);

  for (i = 0; i != G_N_ELEMENTS (linker_exports); i++)
  {
    const gchar * name = linker_exports[i];
    gchar * query;
    TestLinkerExportsContext ctx;
    GError * error = NULL;

    query = g_strconcat ("exports:*!", name, NULL);

    ctx.number_of_calls = 0;
    ctx.expected_address = gum_module_find_export_by_name (linker_name, name);
    g_assert (ctx.expected_address != 0);

    gum_api_resolver_enumerate_matches (fixture->resolver, query,
        check_linker_export, &ctx, &error);
    g_assert (error == NULL);
    g_assert_cmpuint (ctx.number_of_calls, >=, 1);

    g_free (query);
  }
}

static gboolean
check_linker_export (const GumApiDetails * details,
                     gpointer user_data)
{
  TestLinkerExportsContext * ctx = (TestLinkerExportsContext *) user_data;

  g_assert_cmphex (details->address, ==, ctx->expected_address);

  ctx->number_of_calls++;

  return TRUE;
}

#endif
