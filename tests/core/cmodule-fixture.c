/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcmodule.h"

#include "testutil.h"

#include <stdio.h>
#include <string.h>
#include <glib/gstdio.h>

#define TESTCASE(NAME) \
    void test_cmodule_ ## NAME (TestCModuleFixture * fixture, \
        gconstpointer data)
#define TESTENTRY(NAME)                                                   \
    G_STMT_START                                                          \
    {                                                                     \
      extern void test_cmodule_ ##NAME (TestCModuleFixture * fixture,     \
          gconstpointer data);                                            \
      gchar * path;                                                       \
                                                                          \
      path = g_strconcat ("/Core/CModule", group, #NAME "#",              \
          (GPOINTER_TO_UINT (fixture_data) ==                             \
              GUM_CMODULE_TOOLCHAIN_INTERNAL) ? "Internal" : "External",  \
          NULL);                                                          \
                                                                          \
      g_test_add (path,                                                   \
          TestCModuleFixture,                                             \
          fixture_data,                                                   \
          test_cmodule_fixture_setup,                                     \
          test_cmodule_ ##NAME,                                           \
          test_cmodule_fixture_teardown);                                 \
                                                                          \
      g_free (path);                                                      \
    }                                                                     \
    G_STMT_END;

#if defined (HAVE_WINDOWS)
# define TEST_CMODULE_PREBUILT_BINARY "mapper-target.dll"
#elif defined (HAVE_DARWIN)
# define TEST_CMODULE_PREBUILT_BINARY "mapper-target.dylib"
#else
# define TEST_CMODULE_PREBUILT_BINARY "mapper-target.so"
#endif

#if defined (HAVE_ARM64)
# define TEST_CMODULE_MINGW_MACHINE "aarch64-"
#elif GLIB_SIZEOF_VOID_P == 8
# define TEST_CMODULE_MINGW_MACHINE "x86_64-"
#else
# define TEST_CMODULE_MINGW_MACHINE "i686-"
#endif

#define TEST_CMODULE_EXPORT_PREAMBLE \
    "#ifdef _WIN32\n" \
    "# define EXPORT __declspec (dllexport)\n" \
    "#else\n" \
    "# define EXPORT\n" \
    "#endif\n"

typedef struct _TestCModuleFixture TestCModuleFixture;

struct _TestCModuleFixture
{
  GumCModuleOptions options;
  GumCModule * cmodule;
};

static gboolean test_cmodule_fixture_has_toolchain (
    TestCModuleFixture * fixture);
static int test_cmodule_host_add (int a, int b);
static gboolean test_cmodule_external_toolchain_is_available (void);
static gboolean test_cmodule_program_exists (const gchar * name);
#if defined (HAVE_WINDOWS)
static gboolean test_cmodule_mingw_targets_host (void);
#elif !defined (HAVE_DARWIN)
static gboolean test_cmodule_gcc_targets_host (void);
static gboolean test_cmodule_read_elf_identity (const gchar * path,
    guint8 identity[4]);
#endif

static void
test_cmodule_fixture_setup (TestCModuleFixture * fixture,
                            gconstpointer data)
{
  fixture->options.toolchain = GPOINTER_TO_UINT (data);
}

static void
test_cmodule_fixture_teardown (TestCModuleFixture * fixture,
                               gconstpointer data)
{
  g_clear_object (&fixture->cmodule);
}

static gboolean
test_cmodule_fixture_build (TestCModuleFixture * fixture,
                            const gchar * source)
{
  GError * error = NULL;

  if (!test_cmodule_fixture_has_toolchain (fixture))
    return FALSE;

  fixture->cmodule = gum_cmodule_new (source, NULL, &fixture->options,
      &error);
  g_assert_no_error (error);

  gum_cmodule_add_symbol (fixture->cmodule, "host_add", test_cmodule_host_add);

  gum_cmodule_link (fixture->cmodule, &error);
  g_assert_no_error (error);

  return TRUE;
}

static gboolean
test_cmodule_fixture_has_toolchain (TestCModuleFixture * fixture)
{
  if (fixture->options.toolchain == GUM_CMODULE_TOOLCHAIN_INTERNAL ||
      test_cmodule_external_toolchain_is_available ())
  {
    return TRUE;
  }

  g_test_skip ("No external C toolchain targeting this architecture");

  return FALSE;
}

static int
test_cmodule_host_add (int a,
                       int b)
{
  return a + b;
}

static gboolean
test_cmodule_external_toolchain_is_available (void)
{
#if defined (HAVE_WINDOWS)
  return test_cmodule_program_exists ("cl") ||
      (test_cmodule_program_exists ("gcc") &&
       test_cmodule_program_exists ("dlltool") &&
       test_cmodule_mingw_targets_host ());
#elif defined (HAVE_DARWIN)
  return test_cmodule_program_exists ("clang");
#else
  return test_cmodule_program_exists ("gcc") &&
      test_cmodule_gcc_targets_host ();
#endif
}

static gboolean
test_cmodule_program_exists (const gchar * name)
{
  gboolean exists;
  gchar * path;

  path = g_find_program_in_path (name);
  exists = path != NULL;
  g_free (path);

  return exists;
}

#ifdef HAVE_WINDOWS

static gboolean
test_cmodule_mingw_targets_host (void)
{
  gchar machine[64] = "";
  FILE * output;

  output = _popen ("gcc -dumpmachine", "r");
  fgets (machine, sizeof (machine), output);
  _pclose (output);

  return g_str_has_prefix (machine, TEST_CMODULE_MINGW_MACHINE);
}

#elif !defined (HAVE_DARWIN)

static gboolean
test_cmodule_gcc_targets_host (void)
{
  gboolean targets_host = FALSE;
  gchar * object_path, * command;
  gint status;
  guint8 host[4], object[4];

  object_path = g_build_filename (g_get_tmp_dir (), "gum-cmodule-probe.o",
      NULL);
  command = g_strdup_printf ("gcc -c -x c /dev/null -o %s", object_path);

  if (!g_spawn_command_line_sync (command, NULL, NULL, &status, NULL) ||
      !g_spawn_check_wait_status (status, NULL))
  {
    goto beach;
  }

  targets_host = test_cmodule_read_elf_identity ("/proc/self/exe", host) &&
      test_cmodule_read_elf_identity (object_path, object) &&
      memcmp (host, object, sizeof (host)) == 0;

beach:
  g_unlink (object_path);
  g_free (command);
  g_free (object_path);

  return targets_host;
}

static gboolean
test_cmodule_read_elf_identity (const gchar * path,
                                guint8 identity[4])
{
  gboolean success = FALSE;
  FILE * file;
  guint8 header[20];

  file = fopen (path, "rb");
  if (file == NULL)
    return FALSE;

  if (fread (header, sizeof (header), 1, file) != 1)
    goto beach;

  identity[0] = header[4];
  identity[1] = header[5];
  identity[2] = header[18];
  identity[3] = header[19];
  success = TRUE;

beach:
  fclose (file);

  return success;
}

#endif
