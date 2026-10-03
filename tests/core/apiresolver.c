/*
 * Copyright (C) 2016-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023-2026 Håvard Sørbø <havard@hsorbo.no>
 * Copyright (C) 2025 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "apiresolver-fixture.c"

TESTLIST_BEGIN (api_resolver)
  TESTENTRY (module_exports_can_be_resolved_case_sensitively)
  TESTENTRY (module_exports_can_be_resolved_case_insensitively)
  TESTENTRY (module_imports_can_be_resolved)
  TESTENTRY (module_sections_can_be_resolved)
  TESTENTRY (objc_methods_can_be_resolved_case_sensitively)
  TESTENTRY (objc_methods_can_be_resolved_case_insensitively)
#ifdef HAVE_DARWIN
  TESTENTRY (module_exports_can_be_resolved_by_prefix)
  TESTENTRY (reexported_module_exports_can_be_resolved_by_prefix)
  TESTENTRY (objc_method_can_be_resolved_from_class_method_address)
  TESTENTRY (objc_method_can_be_resolved_from_instance_method_address)
#endif
  TESTENTRY (swift_functions_in_libswiftcore_can_be_resolved)
  TESTENTRY (swift_conformances_in_libswiftcore_can_be_resolved)
  TESTENTRY (swift_types_and_protocols_in_libswiftcore_can_be_resolved)
#ifdef HAVE_ANDROID
  TESTENTRY (linker_exports_can_be_resolved_on_android)
#endif
TESTLIST_END ()

TESTCASE (module_exports_can_be_resolved_case_sensitively)
{
  TestForEachContext ctx;
  GError * error = NULL;
#ifdef HAVE_WINDOWS
  const gchar * query = "exports:*!_open*";
#else
  const gchar * query = "exports:*!open*";
#endif

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert_nonnull (fixture->resolver);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_api_resolver_enumerate_matches (fixture->resolver, query, match_found_cb,
      &ctx, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_api_resolver_enumerate_matches (fixture->resolver, query, match_found_cb,
      &ctx, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

TESTCASE (module_exports_can_be_resolved_case_insensitively)
{
  TestForEachContext ctx;
  GError * error = NULL;
#ifdef HAVE_WINDOWS
  const gchar * query = "exports:*!_OpEn*/i";
#else
  const gchar * query = "exports:*!OpEn*/i";
#endif

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert_nonnull (fixture->resolver);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_api_resolver_enumerate_matches (fixture->resolver, query, match_found_cb,
      &ctx, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);
}

TESTCASE (module_imports_can_be_resolved)
{
#ifdef HAVE_DARWIN
  GError * error = NULL;
  const gchar * query = "imports:gum-tests!*";
  guint number_of_imports_seen = 0;

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert_nonnull (fixture->resolver);

  gum_api_resolver_enumerate_matches (fixture->resolver, query,
      check_module_import, &number_of_imports_seen, &error);
  g_assert_no_error (error);
#else
  (void) check_module_import;
#endif
}

static gboolean
check_module_import (const GumApiDetails * details,
                     gpointer user_data)
{
  guint * number_of_imports_seen = user_data;

  g_assert_null (strstr (details->name, "gum-tests"));

  (*number_of_imports_seen)++;

  return TRUE;
}

TESTCASE (module_sections_can_be_resolved)
{
#if defined (HAVE_DARWIN) || defined (HAVE_ELF)
  GError * error = NULL;
  const gchar * query = "sections:gum-tests!*data*";
  guint number_of_sections_seen = 0;

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert_nonnull (fixture->resolver);

  gum_api_resolver_enumerate_matches (fixture->resolver, query, check_section,
      &number_of_sections_seen, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (number_of_sections_seen, >, 1);
#else
  (void) check_section;
#endif
}

static gboolean
check_section (const GumApiDetails * details,
               gpointer user_data)
{
  guint * number_of_sections_seen = user_data;

  g_assert_nonnull (strstr (details->name, "data"));

  (*number_of_sections_seen)++;

  return TRUE;
}

#ifdef HAVE_DARWIN

TESTCASE (module_exports_can_be_resolved_by_prefix)
{
  GHashTable * by_prefix, * by_glob;
  GHashTableIter iter;
  const gchar * name;
  GumAddress * address;
  GError * error = NULL;

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert_nonnull (fixture->resolver);

  by_prefix = make_match_table ();
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "exports:libsystem_pthread.dylib!pthread_*", collect_match, by_prefix,
      &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_hash_table_size (by_prefix), >, 10);

  by_glob = make_match_table ();
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "exports:libsystem_pthread.dylib!*pthread_*", collect_match, by_glob,
      &error);
  g_assert_no_error (error);

  g_hash_table_iter_init (&iter, by_prefix);
  while (g_hash_table_iter_next (&iter, (gpointer *) &name,
      (gpointer *) &address))
  {
    GumAddress * glob_address = g_hash_table_lookup (by_glob, name);

    g_assert_nonnull (glob_address);
    g_assert_cmphex (*glob_address, ==, *address);
  }

  g_hash_table_iter_init (&iter, by_glob);
  while (g_hash_table_iter_next (&iter, (gpointer *) &name, NULL))
  {
    if (g_str_has_prefix (strchr (name, '!') + 1, "pthread_"))
      g_assert_true (g_hash_table_contains (by_prefix, name));
  }

  g_hash_table_unref (by_glob);
  g_hash_table_unref (by_prefix);
}

TESTCASE (reexported_module_exports_can_be_resolved_by_prefix)
{
  GumModule * pthread, * system;
  gchar * expected_name;
  GumAddress expected_address, * address;
  GHashTable * matches;
  GError * error = NULL;

  pthread = gum_process_find_module_by_name ("libsystem_pthread.dylib");
  g_assert_nonnull (pthread);
  system = gum_process_find_module_by_name ("libSystem.B.dylib");
  g_assert_nonnull (system);

  expected_name = g_strconcat (gum_module_get_path (system), "!",
      "pthread_create", NULL);
  expected_address = gum_module_find_export_by_name (pthread, "pthread_create");
  g_assert_cmphex (expected_address, !=, 0);

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert_nonnull (fixture->resolver);

  matches = make_match_table ();
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "exports:libSystem.B.dylib!pthread_create*", collect_match, matches,
      &error);
  g_assert_no_error (error);

  address = g_hash_table_lookup (matches, expected_name);
  g_assert_nonnull (address);
  g_assert_cmphex (*address, ==, expected_address);

  g_hash_table_unref (matches);
  g_free (expected_name);
  g_object_unref (system);
  g_object_unref (pthread);
}

#endif

static GHashTable *
make_match_table (void)
{
  return g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

static gboolean
collect_match (const GumApiDetails * details,
               gpointer user_data)
{
  GHashTable * matches = user_data;

  g_hash_table_insert (matches, g_strdup (details->name),
      g_memdup2 (&details->address, sizeof (GumAddress)));

  return TRUE;
}

TESTCASE (objc_methods_can_be_resolved_case_sensitively)
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
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_api_resolver_enumerate_matches (fixture->resolver, "+[*Arr* arr*]",
      match_found_cb, &ctx, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

TESTCASE (objc_methods_can_be_resolved_case_insensitively)
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
  gum_api_resolver_enumerate_matches (fixture->resolver, "+[*Arr* aRR*]/i",
      match_found_cb, &ctx, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);
}

static gboolean
match_found_cb (const GumApiDetails * details,
                gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

#ifdef HAVE_DARWIN

TESTCASE (objc_method_can_be_resolved_from_class_method_address)
{
  GumAddress address;
  GumModule * address_module;
  gchar * method = NULL;
  GError * error = NULL;

  fixture->resolver = gum_api_resolver_make ("objc");
  if (fixture->resolver == NULL)
  {
    g_print ("<skipping, not available> ");
    return;
  }

  gum_api_resolver_enumerate_matches (fixture->resolver, "+[NSArray array]",
      resolve_method_impl, &address, &error);
  g_assert_no_error (error);

  address_module = gum_process_find_module_by_address (address);
  g_assert_nonnull (address_module);

  method = _gum_objc_api_resolver_find_method_by_address (fixture->resolver,
      address, address_module);
  g_assert_nonnull (method);
  g_free (method);
}

TESTCASE (objc_method_can_be_resolved_from_instance_method_address)
{
  GumAddress address;
  GumModule * address_module;
  gchar * method = NULL;
  GError * error = NULL;

  fixture->resolver = gum_api_resolver_make ("objc");
  if (fixture->resolver == NULL)
  {
    g_print ("<skipping, not available> ");
    return;
  }

  gum_api_resolver_enumerate_matches (fixture->resolver,
      "-[NSArray initWithArray:]", resolve_method_impl, &address, &error);
  g_assert_no_error (error);

  address_module = gum_process_find_module_by_address (address);
  g_assert_nonnull (address_module);

  method = _gum_objc_api_resolver_find_method_by_address (fixture->resolver,
      address, address_module);
  g_assert_nonnull (method);
  g_free (method);
}

#endif

#ifdef HAVE_ELF
# ifdef HAVE_FREEBSD
#  define SWIFT_PLATFORM "freebsd"
# else
#  define SWIFT_PLATFORM "linux"
# endif
#endif

static gpointer open_swift_core (void);
static GumAddress find_swift_core_export (gpointer swift_core,
    const gchar * name);
static void close_swift_core (gpointer swift_core);
#ifdef HAVE_ELF
static void * open_swift_core_from_toolchain_in_path (void);
#endif

TESTCASE (swift_functions_in_libswiftcore_can_be_resolved)
{
  gpointer swift_core;
  GumAddress expected_address, address;
  GError * error = NULL;

  swift_core = open_swift_core ();
  if (swift_core == NULL)
  {
    g_test_skip ("Swift runtime not available");
    return;
  }

  expected_address = find_swift_core_export (swift_core,
      "$sSS9hasPrefixySbSSF");
  g_assert_cmpuint (expected_address, !=, 0);

  fixture->resolver = gum_api_resolver_make ("swift");
  g_assert_nonnull (fixture->resolver);

  address = 0;
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "functions:*swiftCore*!Swift.String.hasPrefix(Swift.String)*",
      resolve_method_impl, &address, &error);
  g_assert_no_error (error);
  g_assert_cmphex (gum_strip_code_address (address), ==,
      gum_strip_code_address (expected_address));

  close_swift_core (swift_core);
}

static gpointer
open_swift_core (void)
{
#if defined (HAVE_WINDOWS)
  return LoadLibraryW (L"swiftCore.dll");
#elif defined (HAVE_DARWIN)
  return dlopen ("/usr/lib/swift/libswiftCore.dylib", RTLD_LAZY | RTLD_GLOBAL);
#else
  void * swift_core;

  swift_core = open_swift_core_from_toolchain_in_path ();
  if (swift_core == NULL)
  {
    swift_core = dlopen ("/usr/lib/swift/" SWIFT_PLATFORM "/libswiftCore.so",
        RTLD_LAZY | RTLD_GLOBAL);
  }

  return swift_core;
#endif
}

static GumAddress
find_swift_core_export (gpointer swift_core,
                        const gchar * name)
{
#ifdef HAVE_WINDOWS
  return GUM_ADDRESS (GetProcAddress (swift_core, name));
#else
  return GUM_ADDRESS (dlsym (swift_core, name));
#endif
}

static void
close_swift_core (gpointer swift_core)
{
#ifdef HAVE_WINDOWS
  FreeLibrary (swift_core);
#else
  dlclose (swift_core);
#endif
}

#ifdef HAVE_ELF

static void *
open_swift_core_from_toolchain_in_path (void)
{
  void * swift_core;
  gchar * swift_link, * swift_binary, * bin_dir, * usr_dir, * lib_path;

  swift_link = g_find_program_in_path ("swift");
  if (swift_link == NULL)
    return NULL;

  swift_binary = realpath (swift_link, NULL);
  g_free (swift_link);
  if (swift_binary == NULL)
    return NULL;

  bin_dir = g_path_get_dirname (swift_binary);
  usr_dir = g_path_get_dirname (bin_dir);
  lib_path = g_build_filename (usr_dir, "lib", "swift", SWIFT_PLATFORM,
      "libswiftCore.so", NULL);

  swift_core = dlopen (lib_path, RTLD_LAZY | RTLD_GLOBAL);

  g_free (lib_path);
  g_free (usr_dir);
  g_free (bin_dir);
  free (swift_binary);

  return swift_core;
}

#endif

static gboolean
resolve_method_impl (const GumApiDetails * details,
                     gpointer user_data)
{
  GumAddress * address = user_data;

  *address = details->address;

  return FALSE;
}

TESTCASE (swift_conformances_in_libswiftcore_can_be_resolved)
{
  gpointer swift_core;
  GumAddress expected_address, * address;
  GHashTable * matches;
  GHashTableIter iter;
  const gchar * name;
  GError * error = NULL;

  swift_core = open_swift_core ();
  if (swift_core == NULL)
  {
    g_test_skip ("Swift runtime not available");
    return;
  }

  expected_address = find_swift_core_export (swift_core, "$sSiSHsMc");
  g_assert_cmpuint (expected_address, !=, 0);

  fixture->resolver = gum_api_resolver_make ("swift");
  g_assert_nonnull (fixture->resolver);

  matches = make_match_table ();
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "conformances:Swift.Int!Swift.Hashable", collect_match, matches, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_hash_table_size (matches), ==, 1);
  address = g_hash_table_lookup (matches, "Swift.Int!Swift.Hashable");
  g_assert_nonnull (address);
  g_assert_cmphex (*address, ==, expected_address);
  g_hash_table_unref (matches);

  matches = make_match_table ();
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "conformances:Swift.Int!*", collect_match, matches, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_hash_table_size (matches), >, 10);
  g_hash_table_iter_init (&iter, matches);
  while (g_hash_table_iter_next (&iter, (gpointer *) &name, NULL))
    g_assert_true (g_str_has_prefix (name, "Swift.Int!"));
  g_assert_true (g_hash_table_contains (matches, "Swift.Int!Swift.Hashable"));
  g_hash_table_unref (matches);

  matches = make_match_table ();
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "conformances:*!Swift.Hashable", collect_match, matches, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_hash_table_size (matches), >, 10);
  address = g_hash_table_lookup (matches, "Swift.Int!Swift.Hashable");
  g_assert_nonnull (address);
  g_assert_cmphex (*address, ==, expected_address);
  g_hash_table_unref (matches);

  matches = make_match_table ();
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "conformances:swift.int!swift.hashable/i", collect_match, matches,
      &error);
  g_assert_no_error (error);
  g_assert_true (g_hash_table_contains (matches, "Swift.Int!Swift.Hashable"));
  g_hash_table_unref (matches);

  close_swift_core (swift_core);
}

TESTCASE (swift_types_and_protocols_in_libswiftcore_can_be_resolved)
{
  gpointer swift_core;
  GumAddress expected_type, expected_protocol, * address;
  GHashTable * matches;
  GHashTableIter iter;
  const gchar * name;
  GError * error = NULL;

  swift_core = open_swift_core ();
  if (swift_core == NULL)
  {
    g_test_skip ("Swift runtime not available");
    return;
  }

  expected_type = find_swift_core_export (swift_core, "$sSiMn");
  g_assert_cmpuint (expected_type, !=, 0);
  expected_protocol = find_swift_core_export (swift_core, "$sSHMp");
  g_assert_cmpuint (expected_protocol, !=, 0);

  fixture->resolver = gum_api_resolver_make ("swift");
  g_assert_nonnull (fixture->resolver);

  matches = make_match_table ();
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "types:*!Swift.Int", collect_match, matches, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_hash_table_size (matches), ==, 1);
  g_hash_table_iter_init (&iter, matches);
  g_hash_table_iter_next (&iter, (gpointer *) &name, (gpointer *) &address);
  g_assert_true (g_str_has_suffix (name, "!Swift.Int"));
  g_assert_cmphex (*address, ==, expected_type);
  g_hash_table_unref (matches);

  matches = make_match_table ();
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "types:*swiftCore*!Swift.*", collect_match, matches, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_hash_table_size (matches), >, 100);
  g_hash_table_iter_init (&iter, matches);
  while (g_hash_table_iter_next (&iter, (gpointer *) &name, NULL))
    g_assert_nonnull (strstr (name, "!Swift."));
  g_hash_table_unref (matches);

  matches = make_match_table ();
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "protocols:*!Swift.Hashable", collect_match, matches, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_hash_table_size (matches), ==, 1);
  g_hash_table_iter_init (&iter, matches);
  g_hash_table_iter_next (&iter, (gpointer *) &name, (gpointer *) &address);
  g_assert_cmphex (*address, ==, expected_protocol);
  g_hash_table_unref (matches);

  matches = make_match_table ();
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "types:*!swift.int/i", collect_match, matches, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_hash_table_size (matches), ==, 1);
  g_hash_table_unref (matches);

  close_swift_core (swift_core);
}

#ifdef HAVE_ANDROID

typedef struct _TestLinkerExportsContext TestLinkerExportsContext;

struct _TestLinkerExportsContext
{
  guint number_of_calls;

  gchar * expected_name;
  GumAddress expected_address;
};

static gboolean check_linker_export (const GumApiDetails * details,
    gpointer user_data);

TESTCASE (linker_exports_can_be_resolved_on_android)
{
  const gchar * linker_name, * libdl_name;
  const gchar * linker_exports[] =
  {
    "dlopen",
    "dlsym",
    "dlclose",
    "dlerror",
  };
  GumModule * correct_module, * incorrect_module;
  guint i;

  if (gum_android_get_api_level () >= 29)
  {
    linker_name = (sizeof (gpointer) == 4)
        ? "/apex/com.android.runtime/bin/linker"
        : "/apex/com.android.runtime/bin/linker64";
    libdl_name = (sizeof (gpointer) == 4)
        ? "/apex/com.android.runtime/lib/bionic/libdl.so"
        : "/apex/com.android.runtime/lib64/bionic/libdl.so";
  }
  else
  {
    linker_name = (sizeof (gpointer) == 4)
        ? "/system/bin/linker"
        : "/system/bin/linker64";
    libdl_name = (sizeof (gpointer) == 4)
        ? "/system/lib/libdl.so"
        : "/system/lib64/libdl.so";
  }

  if (gum_android_get_api_level () >= 26)
  {
    correct_module = gum_process_find_module_by_name (libdl_name);
    incorrect_module = gum_process_find_module_by_name (linker_name);
  }
  else
  {
    correct_module = gum_process_find_module_by_name (linker_name);
    incorrect_module = gum_process_find_module_by_name (libdl_name);
  }

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert_nonnull (fixture->resolver);

  for (i = 0; i != G_N_ELEMENTS (linker_exports); i++)
  {
    const gchar * func_name = linker_exports[i];
    gchar * query;
    TestLinkerExportsContext ctx;
    GError * error = NULL;

    query = g_strconcat ("exports:*!", func_name, NULL);

    g_assert_true (
        gum_module_find_export_by_name (incorrect_module, func_name) == 0);

    ctx.number_of_calls = 0;
    ctx.expected_name = g_strdup_printf ("%s!%s",
        gum_module_get_name (correct_module),
        func_name);
    ctx.expected_address =
        gum_module_find_export_by_name (correct_module, func_name);
    g_assert_cmpuint (ctx.expected_address, !=, 0);

    gum_api_resolver_enumerate_matches (fixture->resolver, query,
        check_linker_export, &ctx, &error);
    g_assert_no_error (error);
    g_assert_cmpuint (ctx.number_of_calls, >=, 1);

    g_free (ctx.expected_name);

    g_free (query);
  }

  g_object_unref (incorrect_module);
  g_object_unref (correct_module);
}

static gboolean
check_linker_export (const GumApiDetails * details,
                     gpointer user_data)
{
  TestLinkerExportsContext * ctx = (TestLinkerExportsContext *) user_data;

  g_assert_cmpstr (details->name, ==, ctx->expected_name);
  g_assert_cmphex (details->address, ==, ctx->expected_address);

  ctx->number_of_calls++;

  return TRUE;
}

#endif
