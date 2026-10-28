/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "cmodule-fixture.c"

TESTLIST_BEGIN (cmodule)
  TESTENTRY (source_is_compiled_and_host_symbol_resolved)
  TESTENTRY (symbols_can_be_enumerated)
  TESTENTRY (undefined_symbol_is_reported)
  if (GPOINTER_TO_UINT (fixture_data) == GUM_CMODULE_TOOLCHAIN_EXTERNAL)
    TESTENTRY (prebuilt_binary_is_loaded)
TESTLIST_END ()

typedef struct _TestCModuleSymbolSearch TestCModuleSymbolSearch;

struct _TestCModuleSymbolSearch
{
  const gchar * name;
  gpointer address;
};

static void test_cmodule_store_symbol (const GumCSymbolDetails * details,
    gpointer user_data);

TESTCASE (source_is_compiled_and_host_symbol_resolved)
{
  int (* compute) (int x);

  if (!test_cmodule_fixture_build (fixture,
      TEST_CMODULE_EXPORT_PREAMBLE
      "extern int host_add (int a, int b);\n"
      "EXPORT int compute (int x) { return host_add (x, 7); }\n"))
  {
    return;
  }

  compute = gum_cmodule_find_symbol_by_name (fixture->cmodule, "compute");
  g_assert_nonnull (compute);
  g_assert_cmpint (compute (10), ==, 17);
}

TESTCASE (symbols_can_be_enumerated)
{
  TestCModuleSymbolSearch search;

  if (!test_cmodule_fixture_build (fixture,
      TEST_CMODULE_EXPORT_PREAMBLE
      "EXPORT int compute (int x) { return x + 1; }\n"))
  {
    return;
  }

  search.name = "compute";
  search.address = NULL;
  gum_cmodule_enumerate_symbols (fixture->cmodule, test_cmodule_store_symbol,
      &search);

  g_assert_nonnull (search.address);
  g_assert_true (search.address ==
      gum_cmodule_find_symbol_by_name (fixture->cmodule, "compute"));
}

TESTCASE (undefined_symbol_is_reported)
{
  GError * error = NULL;

  if (!test_cmodule_fixture_has_toolchain (fixture))
    return;

  fixture->cmodule = gum_cmodule_new (
      TEST_CMODULE_EXPORT_PREAMBLE
      "extern int nope (void);\n"
      "EXPORT int f (void) { return nope (); }\n",
      NULL, &fixture->options, &error);
  if (error == NULL)
    gum_cmodule_link (fixture->cmodule, &error);

  g_assert_nonnull (error);
  g_assert_nonnull (strstr (error->message, "nope"));
  g_error_free (error);
}

TESTCASE (prebuilt_binary_is_loaded)
{
  gchar * data_dir, * path;
  gchar * contents;
  gsize length;
  GBytes * binary;
  GError * error = NULL;
  int (* sum) (int a, int b);
  int (* get_magic) (void);

  data_dir = test_util_get_data_dir ();
  path = g_build_filename (data_dir, TEST_CMODULE_PREBUILT_BINARY, NULL);
  g_assert_true (g_file_get_contents (path, &contents, &length, NULL));
  g_free (path);
  g_free (data_dir);
  binary = g_bytes_new_take (contents, length);

  fixture->cmodule = gum_cmodule_new (NULL, binary, &fixture->options,
      &error);
  g_bytes_unref (binary);
  g_assert_no_error (error);

  gum_cmodule_link (fixture->cmodule, &error);
  g_assert_no_error (error);

  sum = gum_cmodule_find_symbol_by_name (fixture->cmodule,
      "gum_test_mapper_sum");
  g_assert_nonnull (sum);
  g_assert_cmpint (sum (3, 4), ==, 7);

  get_magic = gum_cmodule_find_symbol_by_name (fixture->cmodule,
      "gum_test_mapper_get_magic");
  g_assert_nonnull (get_magic);
  g_assert_cmphex (get_magic (), ==, 0x1337);
}

static void
test_cmodule_store_symbol (const GumCSymbolDetails * details,
                           gpointer user_data)
{
  TestCModuleSymbolSearch * search = user_data;

  if (strcmp (details->name, search->name) == 0)
    search->address = details->address;
}
