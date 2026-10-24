/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gumcmodule.h"

#include "testutil.h"

#define TESTCASE(NAME) \
    void test_elf_cmodule_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/ElfCModule", test_elf_cmodule, NAME)

TESTLIST_BEGIN (elf_cmodule)
  TESTENTRY (prebuilt_binary_is_mapped_through_facade)
  TESTENTRY (source_is_compiled_and_host_symbol_resolved)
TESTLIST_END ()

static int gum_test_elf_cmodule_host_add (int a, int b);

TESTCASE (prebuilt_binary_is_mapped_through_facade)
{
  gchar * data_dir, * path;
  gchar * contents;
  gsize length;
  GBytes * binary;
  GError * error = NULL;
  GumCModuleOptions options = { GUM_CMODULE_TOOLCHAIN_EXTERNAL };
  GumCModule * cmodule;
  int (* sum) (int a, int b);
  int (* get_magic) (void);

  data_dir = test_util_get_data_dir ();
  path = g_build_filename (data_dir, "elfmapper-target.so", NULL);
  g_assert_true (g_file_get_contents (path, &contents, &length, NULL));
  g_free (path);
  g_free (data_dir);
  binary = g_bytes_new_take (contents, length);

  cmodule = gum_cmodule_new (NULL, binary, &options, &error);
  g_bytes_unref (binary);
  g_assert_no_error (error);
  g_assert_nonnull (cmodule);

  gum_cmodule_link (cmodule, &error);
  g_assert_no_error (error);

  sum = GSIZE_TO_POINTER (
      gum_cmodule_find_symbol_by_name (cmodule, "gum_test_elf_sum"));
  g_assert_nonnull (sum);
  g_assert_cmpint (sum (3, 4), ==, 7);

  get_magic = GSIZE_TO_POINTER (
      gum_cmodule_find_symbol_by_name (cmodule, "gum_test_elf_get_magic"));
  g_assert_nonnull (get_magic);
  g_assert_cmphex (get_magic (), ==, 0x1337);

  gum_cmodule_drop_metadata (cmodule);
  g_object_unref (cmodule);
}

TESTCASE (source_is_compiled_and_host_symbol_resolved)
{
  const gchar * source =
      "extern int host_add (int a, int b);\n"
      "int compute (int x)\n"
      "{\n"
      "  return host_add (x, 7);\n"
      "}\n";
  GumCModuleOptions options = { GUM_CMODULE_TOOLCHAIN_EXTERNAL };
  GError * error = NULL;
  GumCModule * cmodule;
  int (* compute) (int x);

  cmodule = gum_cmodule_new (source, NULL, &options, &error);
  if (cmodule == NULL || error != NULL)
  {
    g_test_skip ("external C compiler not available");
    g_clear_error (&error);
    g_clear_object (&cmodule);
    return;
  }

  gum_cmodule_add_symbol (cmodule, "host_add", gum_test_elf_cmodule_host_add);

  if (!gum_cmodule_link (cmodule, &error))
  {
    g_test_skip (error->message);
    g_error_free (error);
    g_object_unref (cmodule);
    return;
  }

  compute = GSIZE_TO_POINTER (
      gum_cmodule_find_symbol_by_name (cmodule, "compute"));
  g_assert_nonnull (compute);
  g_assert_cmpint (compute (10), ==, 17);

  gum_cmodule_drop_metadata (cmodule);
  g_object_unref (cmodule);
}

static int
gum_test_elf_cmodule_host_add (int a,
                               int b)
{
  return a + b;
}
