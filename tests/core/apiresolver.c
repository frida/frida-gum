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
#if defined (HAVE_DARWIN) || defined (HAVE_ELF)
  TESTENTRY (swift_functions_in_symbol_table_can_be_resolved)
  TESTENTRY (swift_exported_functions_in_libswiftcore_are_listed_once)
#endif
  TESTENTRY (swift_conformances_in_libswiftcore_can_be_resolved)
  TESTENTRY (swift_types_and_protocols_in_libswiftcore_can_be_resolved)
  TESTENTRY (swift_vtable_slots_in_libswiftcore_are_named_from_dispatch_thunks)
#if defined (HAVE_ARM64) || (defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8)
  TESTENTRY (swift_async_dispatch_thunk_names_its_slot)
  TESTENTRY (swift_async_dispatch_thunk_via_indirect_pointer_names_its_slot)
#endif
#ifdef HAVE_ARM64
  TESTENTRY (swift_async_dispatch_thunk_with_ptrauth_names_its_slot)
  TESTENTRY (swift_dispatch_thunk_with_resilient_superclass_names_its_slot)
  TESTENTRY (swift_class_method_thunk_with_resilient_superclass_names_its_slot)
  TESTENTRY (swift_devirtualized_dispatch_thunk_names_no_slot)
#endif
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

#ifdef HAVE_QNX
# define GUM_TESTS_PING_LABEL \
    G_STRINGIFY (__USER_LABEL_PREFIX__) "$s8GumTests4pingyyF"
#else
# define GUM_TESTS_PING_LABEL \
    "\"" G_STRINGIFY (__USER_LABEL_PREFIX__) "$s8GumTests4pingyyF\""
#endif

static gpointer open_swift_core (void);
static GumAddress find_swift_core_export (gpointer swift_core,
    const gchar * name);
static void close_swift_core (gpointer swift_core);
#ifdef HAVE_ELF
static void * open_swift_core_from_toolchain_in_path (void);
#endif
#if defined (HAVE_DARWIN) || defined (HAVE_ELF)
static void gum_tests_ping (void)
    __asm__ (GUM_TESTS_PING_LABEL);
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

#if defined (HAVE_DARWIN) || defined (HAVE_ELF)

TESTCASE (swift_functions_in_symbol_table_can_be_resolved)
{
  gpointer swift_core;
  TestForEachContext ctx;
  GumAddress address;
  GError * error = NULL;

  if (gum_module_find_symbol_by_name (gum_process_get_main_module (),
      "$s8GumTests4pingyyF") == 0)
  {
    g_test_skip ("Test binary is stripped");
    return;
  }

  swift_core = open_swift_core ();
  if (swift_core == NULL)
  {
    g_test_skip ("Swift runtime not available");
    return;
  }

  fixture->resolver = gum_api_resolver_make ("swift");
  g_assert_nonnull (fixture->resolver);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "functions:*gum-tests*!GumTests.ping() -> ()", match_found_cb, &ctx,
      &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);

  address = 0;
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "functions:*gum-tests*!GumTests.ping() -> ()", resolve_method_impl,
      &address, &error);
  g_assert_no_error (error);
  g_assert_cmphex (gum_strip_code_address (address), ==,
      gum_strip_code_address (GUM_ADDRESS (gum_tests_ping)));

  close_swift_core (swift_core);
}

TESTCASE (swift_exported_functions_in_libswiftcore_are_listed_once)
{
  gpointer swift_core;
  TestForEachContext ctx;
  GError * error = NULL;

  swift_core = open_swift_core ();
  if (swift_core == NULL)
  {
    g_test_skip ("Swift runtime not available");
    return;
  }

  fixture->resolver = gum_api_resolver_make ("swift");
  g_assert_nonnull (fixture->resolver);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "functions:*swiftCore*!Swift.String.hasPrefix(Swift.String) -> "
      "Swift.Bool",
      match_found_cb, &ctx, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);

  close_swift_core (swift_core);
}

static void
gum_tests_ping (void)
{
}

#endif

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

TESTCASE (swift_vtable_slots_in_libswiftcore_are_named_from_dispatch_thunks)
{
  gpointer swift_core;
  GumAddress expected_address, address;
  GHashTable * matches;
  GError * error = NULL;

  swift_core = open_swift_core ();
  if (swift_core == NULL)
  {
    g_test_skip ("Swift runtime not available");
    return;
  }

  expected_address = find_swift_core_export (swift_core,
      "$ss13ManagedBufferC12_doNotCallMeAByxq_Gyt_tcfC");
  g_assert_cmpuint (expected_address, !=, 0);

  fixture->resolver = gum_api_resolver_make ("swift");
  g_assert_nonnull (fixture->resolver);

  address = 0;
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "functions:*swiftCore*!dispatch thunk of *", resolve_method_impl,
      &address, &error);
  g_assert_no_error (error);
  if (address == 0)
  {
    g_test_skip ("Swift runtime exports no dispatch thunks");
    close_swift_core (swift_core);
    return;
  }

  address = 0;
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "functions:*swiftCore*!Swift.ManagedBuffer.__allocating_init"
      "(_doNotCallMe: ())*",
      resolve_method_impl, &address, &error);
  g_assert_no_error (error);
  g_assert_cmphex (gum_strip_code_address (address), ==,
      gum_strip_code_address (expected_address));

  matches = make_match_table ();
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "functions:*swiftCore*!Swift.ManagedBuffer.vtable[*", collect_match,
      matches, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_hash_table_size (matches), ==, 0);
  g_hash_table_unref (matches);

  close_swift_core (swift_core);
}

#ifdef HAVE_ARM64

TESTCASE (swift_async_dispatch_thunk_names_its_slot)
{
  const guint32 thunk[] = {
    GUINT32_TO_LE (0xb24403bd), GUINT32_TO_LE (0xd10083ff),
    GUINT32_TO_LE (0xa9017bfd), GUINT32_TO_LE (0xf90007f6),
    GUINT32_TO_LE (0x910043fd), GUINT32_TO_LE (0xf9400288),
    GUINT32_TO_LE (0xf9407108), GUINT32_TO_LE (0x29400109),
    GUINT32_TO_LE (0x93407d29), GUINT32_TO_LE (0x8b080121),
    GUINT32_TO_LE (0xf90003e1), GUINT32_TO_LE (0x94000065),
    GUINT32_TO_LE (0xf9000ac0), GUINT32_TO_LE (0x90000008),
    GUINT32_TO_LE (0x91307108), GUINT32_TO_LE (0xa9002016),
    GUINT32_TO_LE (0xaa0003f6), GUINT32_TO_LE (0xf94003e0),
    GUINT32_TO_LE (0xa9417bfd), GUINT32_TO_LE (0x9243fbbd),
    GUINT32_TO_LE (0x910083ff), GUINT32_TO_LE (0xd61f0000),
  };

  g_assert_cmpint (_gum_swift_api_resolver_find_vtable_index_in_thunk (thunk),
      ==, 28);
}

TESTCASE (swift_async_dispatch_thunk_via_indirect_pointer_names_its_slot)
{
  const guint32 thunk[] = {
    GUINT32_TO_LE (0xf81f0ffe), GUINT32_TO_LE (0xf9400288),
    GUINT32_TO_LE (0xf9406508), GUINT32_TO_LE (0x927ff909),
    GUINT32_TO_LE (0xf240011f), GUINT32_TO_LE (0xf9400129),
    GUINT32_TO_LE (0x9a890108), GUINT32_TO_LE (0x29400109),
    GUINT32_TO_LE (0x93407d29), GUINT32_TO_LE (0x8b090101),
    GUINT32_TO_LE (0x90000008), GUINT32_TO_LE (0xf90007e1),
    GUINT32_TO_LE (0xf9400108), GUINT32_TO_LE (0xd63f0100),
    GUINT32_TO_LE (0x90000008), GUINT32_TO_LE (0x91000108),
    GUINT32_TO_LE (0xf9000ac0), GUINT32_TO_LE (0xa9002016),
    GUINT32_TO_LE (0xaa0003f6), GUINT32_TO_LE (0xf94007e0),
    GUINT32_TO_LE (0xf84107fe), GUINT32_TO_LE (0xd61f0000),
  };

  g_assert_cmpint (_gum_swift_api_resolver_find_vtable_index_in_thunk (thunk),
      ==, 25);
}

TESTCASE (swift_async_dispatch_thunk_with_ptrauth_names_its_slot)
{
  const guint32 thunk[] = {
    GUINT32_TO_LE (0xd503237f), GUINT32_TO_LE (0xb24403bd),
    GUINT32_TO_LE (0xd100c3ff), GUINT32_TO_LE (0xa9027bfd),
    GUINT32_TO_LE (0x910063f0), GUINT32_TO_LE (0xf2f86350),
    GUINT32_TO_LE (0xaa1603f1), GUINT32_TO_LE (0xdac10e11),
    GUINT32_TO_LE (0xf9000ff1), GUINT32_TO_LE (0x910083fd),
    GUINT32_TO_LE (0xf9400290), GUINT32_TO_LE (0xaa1403f1),
    GUINT32_TO_LE (0xf2ed5c31), GUINT32_TO_LE (0xdac11a30),
    GUINT32_TO_LE (0xf84e0e08), GUINT32_TO_LE (0xaa1003e0),
    GUINT32_TO_LE (0xf90007f0), GUINT32_TO_LE (0xaa0803f0),
    GUINT32_TO_LE (0xaa0003f1), GUINT32_TO_LE (0xf2f14331),
    GUINT32_TO_LE (0xdac11a30), GUINT32_TO_LE (0xaa1003f1),
    GUINT32_TO_LE (0xdac147f1), GUINT32_TO_LE (0xeb11021f),
    GUINT32_TO_LE (0x54000040), GUINT32_TO_LE (0xd4388e40),
    GUINT32_TO_LE (0xb8800e11), GUINT32_TO_LE (0x8b110210),
    GUINT32_TO_LE (0xaa0003f1), GUINT32_TO_LE (0xf2f14331),
    GUINT32_TO_LE (0xdac10230), GUINT32_TO_LE (0xf9000bf0),
    GUINT32_TO_LE (0xaa0803f0), GUINT32_TO_LE (0xaa0003f1),
    GUINT32_TO_LE (0xf2f14331), GUINT32_TO_LE (0xdac11a30),
    GUINT32_TO_LE (0xaa1003f1), GUINT32_TO_LE (0xdac147f1),
    GUINT32_TO_LE (0xeb11021f), GUINT32_TO_LE (0x54000040),
    GUINT32_TO_LE (0xd4388e40), GUINT32_TO_LE (0xb9400600),
    GUINT32_TO_LE (0x94000121), GUINT32_TO_LE (0xaa1603f1),
    GUINT32_TO_LE (0xf9000ac0), GUINT32_TO_LE (0xaa0003f0),
    GUINT32_TO_LE (0xf2f7b450), GUINT32_TO_LE (0xdac10a11),
    GUINT32_TO_LE (0xf9000011), GUINT32_TO_LE (0x91002008),
    GUINT32_TO_LE (0xb0000010), GUINT32_TO_LE (0x91032210),
    GUINT32_TO_LE (0xaa0803f1), GUINT32_TO_LE (0xf2fae0f1),
    GUINT32_TO_LE (0xdac10230), GUINT32_TO_LE (0xf9000410),
    GUINT32_TO_LE (0xaa0003f6), GUINT32_TO_LE (0xa94083e1),
    GUINT32_TO_LE (0xa9427bfd), GUINT32_TO_LE (0x9243fbbd),
    GUINT32_TO_LE (0x9100c3ff), GUINT32_TO_LE (0xd50323ff),
    GUINT32_TO_LE (0xca1e07d0), GUINT32_TO_LE (0xb6f00050),
    GUINT32_TO_LE (0xd4388e20), GUINT32_TO_LE (0xaa0103f0),
    GUINT32_TO_LE (0xf2f14330), GUINT32_TO_LE (0xd71f0810),
  };

  g_assert_cmpint (_gum_swift_api_resolver_find_vtable_index_in_thunk (thunk),
      ==, 28);
}

TESTCASE (swift_dispatch_thunk_with_resilient_superclass_names_its_slot)
{
  const guint32 thunk[] = {
    GUINT32_TO_LE (0xf9400288), GUINT32_TO_LE (0x90000049),
    GUINT32_TO_LE (0xf9406929), GUINT32_TO_LE (0x8b090108),
    GUINT32_TO_LE (0xf9400d00), GUINT32_TO_LE (0xd61f0000),
  };

  g_assert_cmpint (_gum_swift_api_resolver_find_vtable_index_in_thunk (thunk),
      ==, 3);
}

TESTCASE (swift_class_method_thunk_with_resilient_superclass_names_its_slot)
{
  const guint32 thunk[] = {
    GUINT32_TO_LE (0xb24403bd), GUINT32_TO_LE (0xd10083ff),
    GUINT32_TO_LE (0xa9017bfd), GUINT32_TO_LE (0xf90007f6),
    GUINT32_TO_LE (0x910043fd), GUINT32_TO_LE (0x90000048),
    GUINT32_TO_LE (0xf9406908), GUINT32_TO_LE (0x8b080288),
    GUINT32_TO_LE (0xf9400908), GUINT32_TO_LE (0x29400109),
    GUINT32_TO_LE (0x93407d29), GUINT32_TO_LE (0x8b080121),
    GUINT32_TO_LE (0xf90003e1), GUINT32_TO_LE (0x940000ae),
    GUINT32_TO_LE (0xf9000ac0), GUINT32_TO_LE (0x90000008),
    GUINT32_TO_LE (0x91398108), GUINT32_TO_LE (0xa9002016),
    GUINT32_TO_LE (0xaa0003f6), GUINT32_TO_LE (0xf94003e0),
    GUINT32_TO_LE (0xa9417bfd), GUINT32_TO_LE (0x9243fbbd),
    GUINT32_TO_LE (0x910083ff), GUINT32_TO_LE (0xd61f0000),
  };

  g_assert_cmpint (_gum_swift_api_resolver_find_vtable_index_in_thunk (thunk),
      ==, 2);
}

TESTCASE (swift_devirtualized_dispatch_thunk_names_no_slot)
{
  const guint32 thunk_and_next_function[] = {
    GUINT32_TO_LE (0x1400048d), GUINT32_TO_LE (0xf9400288),
    GUINT32_TO_LE (0xf9406d00), GUINT32_TO_LE (0xd61f0000),
  };

  g_assert_cmpint (_gum_swift_api_resolver_find_vtable_index_in_thunk (
      thunk_and_next_function), ==, -1);
}

#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8

TESTCASE (swift_async_dispatch_thunk_names_its_slot)
{
  const guint8 thunk[] = {
    0x48, 0x0f, 0xba, 0xed, 0x3c, 0x55, 0x41, 0x56,
    0x48, 0x8d, 0x6c, 0x24, 0x08, 0x48, 0x83, 0xec,
    0x08, 0x53, 0x48, 0x83, 0xec, 0x18, 0x49, 0x8b,
    0x45, 0x00, 0x48, 0x8b, 0x80, 0xe0, 0x00, 0x00,
    0x00, 0x48, 0x63, 0x08, 0x48, 0x01, 0xc1, 0x48,
    0x89, 0xcb, 0x8b, 0x78, 0x04, 0xe8, 0xc4, 0x01,
    0x00, 0x00, 0x49, 0x89, 0x46, 0x10, 0x4c, 0x89,
    0x30, 0x48, 0x8d, 0x0d, 0x80, 0x01, 0x00, 0x00,
    0x48, 0x89, 0x48, 0x08, 0x49, 0x89, 0xc6, 0x48,
    0x89, 0xd8, 0x48, 0x83, 0xc4, 0x18, 0x5b, 0x48,
    0x83, 0xc4, 0x10, 0x5d, 0x48, 0x0f, 0xba, 0xf5,
    0x3c, 0xff, 0xe0,
  };

  g_assert_cmpint (_gum_swift_api_resolver_find_vtable_index_in_thunk (thunk),
      ==, 28);
}

TESTCASE (swift_async_dispatch_thunk_via_indirect_pointer_names_its_slot)
{
  const guint8 thunk[] = {
    0x56, 0x48, 0x83, 0xec, 0x30, 0x4c, 0x89, 0x74,
    0x24, 0x28, 0x49, 0x8b, 0x45, 0x00, 0x48, 0x8b,
    0x80, 0xc8, 0x00, 0x00, 0x00, 0xa8, 0x01, 0x74,
    0x07, 0x48, 0x83, 0xe0, 0xfe, 0x48, 0x8b, 0x00,
    0x48, 0x63, 0x08, 0x48, 0x01, 0xc1, 0x48, 0x89,
    0xce, 0x8b, 0x48, 0x04, 0xff, 0x15, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x89, 0x46, 0x10, 0x4c, 0x89,
    0x30, 0x48, 0x8d, 0x0d, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x48, 0x08, 0x49, 0x89, 0xc6, 0x48,
    0x89, 0xf0, 0x48, 0x83, 0xc4, 0x30, 0x5e, 0x48,
    0xff, 0xe0,
  };

  g_assert_cmpint (_gum_swift_api_resolver_find_vtable_index_in_thunk (thunk),
      ==, 25);
}

#endif

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
