/*
 * Copyright (C) 2025-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2026 Sam Sun <samsun@nvidia.com>
 * Copyright (C) 2026 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummoduleregistry.h"

#include "gumcloak.h"
#include "gumelfmodule.h"
#include "guminterceptor.h"
#include "testutil.h"

#ifdef HAVE_WINDOWS
# include <windows.h>
# include <shlobj.h>
#elif !defined (G_OS_NONE)
# include <dlfcn.h>
#endif
#ifdef HAVE_LINUX
# include "interceptor-callbacklistener.h"
# include <link.h>
# include <sys/mman.h>
#endif

#define TESTCASE(NAME) \
    void test_module_registry_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/ModuleRegistry", test_module_registry, NAME)

TESTLIST_BEGIN (module_registry)
  TESTENTRY (module_registry_should_emit_signal_on_add)
  TESTENTRY (module_removal_should_be_emitted_after_its_range_is_cloaked)
  TESTENTRY (module_should_unload_after_export_lookup)
  TESTENTRY (module_should_unload_after_being_initialized)
  TESTENTRY (hooks_should_be_discarded_when_module_unloads)
  TESTENTRY (dependency_export_can_be_found)
  TESTENTRY (delay_loaded_modules_should_be_registered)
  TESTENTRY (executable_images_should_be_registered)
  TESTENTRY (global_export_lookup_should_survive_module_loading)
  TESTENTRY (registry_should_have_modules_for_every_thread_obtaining_it)
  TESTENTRY (nonzero_vaddr_module_should_be_found_at_its_header)
  TESTENTRY (displaced_nonzero_vaddr_module_should_be_found_at_its_header)
  TESTENTRY (relocated_program_headers_can_be_parsed)
  TESTENTRY (online_elf_should_allow_padded_inline_program_headers)
  TESTENTRY (online_elf_should_bound_inline_program_headers)
  TESTENTRY (online_elf_should_skip_unreadable_section_headers)
  TESTENTRY (online_elf_should_skip_unreadable_section_names)
TESTLIST_END ()

typedef enum _TestModuleUse TestModuleUse;
typedef struct _TestModuleRemoval TestModuleRemoval;

enum _TestModuleUse
{
  TEST_MODULE_USE_EXPORT_LOOKUP,
  TEST_MODULE_USE_INITIALIZATION,
};

struct _TestModuleRemoval
{
  const gchar * name;
  guint count;
};

static void on_module_added (GumModuleRegistry * registry, GumModule * module,
    gpointer user_data);
static void on_module_removed (GumModuleRegistry * registry, GumModule * module,
    gpointer user_data);
static void assert_module_unloads_after_use (TestModuleUse use);
static void on_observer_target_removed (GumModuleRegistry * registry,
    GumModule * module, gpointer user_data);
static gpointer load_library (const gchar * path);
static void unload_library (gpointer handle);
#ifndef HAVE_QNX
static gboolean library_is_loaded (const gchar * path);
#endif

#if defined (HAVE_WINDOWS)
# define GUM_OBSERVER_TARGET_MODULE_FILENAME "module-observer-target.dll"
#elif defined (HAVE_DARWIN)
# define GUM_OBSERVER_TARGET_MODULE_FILENAME "module-observer-target.dylib"
#else
# define GUM_OBSERVER_TARGET_MODULE_FILENAME "module-observer-target.so"
#endif
#define GUM_OBSERVER_TARGET_MODULE_EXPORT "gum_module_observer_target_function"

#ifdef HAVE_WINDOWS

# define GUM_DEPENDENT_MODULE_FILENAME "module-registry-dependent.dll"
# define GUM_DEPENDENCY_MODULE_FILENAME "module-registry-dependency.dll"
# define GUM_DELAY_LOADED_MODULE_FILENAME "windows.storage.dll"
# define GUM_PROGRAM_MODULE_FILENAME "module-registry-program.exe"
# define GUM_RACER_PROGRAM_FILENAME "module-registry-racer.exe"

typedef struct _TestFindModuleContext TestFindModuleContext;

struct _TestFindModuleContext
{
  const gchar * name;
  GumModule * module;
};

typedef struct _TestLoaderRace TestLoaderRace;

struct _TestLoaderRace
{
  const gunichar2 * module_path;
  guint num_loads;
  gboolean lookups_done;
};

static void on_delay_loaded_module_added (GumModuleRegistry * registry,
    GumModule * module, gpointer user_data);
static GumModule * find_registered_module (const gchar * name);
static gboolean store_module_if_named (GumModule * module,
    gpointer user_data);
static DWORD WINAPI look_up_missing_exports (LPVOID data);
static DWORD WINAPI load_and_unload_module (LPVOID data);

#endif

#ifdef HAVE_LINUX

# define GUM_TARGET_MODULE_FILENAME "module-registry-target.so"
# define GUM_DEPENDENT_MODULE_FILENAME "module-registry-dependent.so"
# define GUM_DEPENDENCY_MODULE_FILENAME "module-registry-dependency.so"
# define GUM_NONZERO_VADDR_MODULE_FILENAME \
    "module-registry-target-nonzero-vaddr.so"
# define GUM_NONZERO_VADDR_MODULE_LINK_ADDRESS 0x400000
# define GUM_RACER_PROGRAM_FILENAME "module-registry-racer"

typedef struct _TestModuleHooks TestModuleHooks;
typedef struct _TestNonzeroVaddrContext TestNonzeroVaddrContext;

struct _TestModuleHooks
{
  gboolean seen_add;
  gboolean seen_remove;
};

struct _TestNonzeroVaddrContext
{
  gboolean seen;
  GumMemoryRange range;
};

static void on_target_module_added (GumModuleRegistry * registry,
    GumModule * module, gpointer user_data);
static void on_target_module_removed (GumModuleRegistry * registry,
    GumModule * module, gpointer user_data);
static gboolean is_target_module (GumModule * module);
static void assert_nonzero_vaddr_module_found_at_its_header (
    gboolean occupy_link_address);
static void on_nonzero_vaddr_module_added (GumModuleRegistry * registry,
    GumModule * module, gpointer user_data);
static void assert_online_elf_skips_unreadable_section_data (gboolean names);

#endif

#if defined (HAVE_WINDOWS) || defined (HAVE_LINUX)
# define GUM_DEPENDENCY_MODULE_EXPORT "gum_module_registry_dependency_function"
#endif

#if defined (HAVE_WINDOWS) || \
    (defined (HAVE_LINUX) && !defined (HAVE_ANDROID))
# define GUM_HAVE_MODULE_REGISTRY_RACER 1

static gboolean run_module_registry_racer (void);
#endif

#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID) && \
    defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# define GUM_HAVE_RELOCATED_PHDR_TARGET 1
#endif

#ifdef HAVE_LINUX
# if GLIB_SIZEOF_VOID_P == 8
#  define GUM_TEST_ELF_CLASS ELFCLASS64
# else
#  define GUM_TEST_ELF_CLASS ELFCLASS32
# endif
# if G_BYTE_ORDER == G_LITTLE_ENDIAN
#  define GUM_TEST_ELF_ENCODING ELFDATA2LSB
# else
#  define GUM_TEST_ELF_ENCODING ELFDATA2MSB
# endif
# define GUM_TEST_UNOPENABLE_PATH "/nonexistent/gum-test-image.so"
#endif

#ifdef GUM_HAVE_RELOCATED_PHDR_TARGET

# define GUM_RELOCATED_PHDR_TARGET_FILENAME \
    "module-registry-target-relocated-phdr-linux-x86_64.so"
# define GUM_TARGET_MODULE_EXPORT "gum_module_registry_target_function"

typedef struct _TestRelocatedPhdrContext TestRelocatedPhdrContext;

struct _TestRelocatedPhdrContext
{
  gboolean seen;
  GumAddress export_address;
};

static void on_relocated_phdr_module_added (GumModuleRegistry * registry,
    GumModule * module, gpointer user_data);
static gboolean on_relocated_phdr_export_found (
    const GumExportDetails * details, gpointer user_data);
static void assert_relocated_phdr_layout (const gchar * path);

#endif

TESTCASE (module_registry_should_emit_signal_on_add)
{
  GumModuleRegistry * registry;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  registry = gum_module_registry_obtain ();
  g_signal_connect (registry, "module-added", G_CALLBACK (on_module_added),
      NULL);
  g_signal_connect (registry, "module-removed", G_CALLBACK (on_module_removed),
      NULL);
  g_printerr ("Sleeping in PID %u...\n", gum_process_get_id ());
  while (TRUE)
    g_usleep (60 * G_USEC_PER_SEC);
}

TESTCASE (module_removal_should_be_emitted_after_its_range_is_cloaked)
{
#ifdef G_OS_NONE
  g_test_skip ("dynamic libraries are not supported by the Barebone backend");
#else
  gchar * data_dir, * path;
  GumModuleRegistry * registry;
  TestModuleRemoval removal = { GUM_OBSERVER_TARGET_MODULE_FILENAME, 0 };
  gulong handler;
  gpointer handle;
  GumModule * module;
  GumMemoryRange range;

  data_dir = test_util_get_data_dir ();
  path = g_build_filename (data_dir, GUM_OBSERVER_TARGET_MODULE_FILENAME,
      NULL);

  registry = gum_module_registry_obtain ();
  handler = g_signal_connect (registry, "module-removed",
      G_CALLBACK (on_observer_target_removed), &removal);

  handle = load_library (path);
  module =
      gum_process_find_module_by_name (GUM_OBSERVER_TARGET_MODULE_FILENAME);
  g_assert_nonnull (module);
  range = *gum_module_get_range (module);
  g_object_unref (module);

  gum_cloak_add_range (&range);
  unload_library (handle);
  gum_cloak_remove_range (&range);

  module =
      gum_process_find_module_by_name (GUM_OBSERVER_TARGET_MODULE_FILENAME);
  if (module != NULL)
  {
    g_object_unref (module);
    g_test_skip ("the loader kept the module loaded");
  }
  else
  {
    g_assert_cmpuint (removal.count, ==, 1);
  }

  g_signal_handler_disconnect (registry, handler);
  g_free (path);
  g_free (data_dir);
#endif
}

TESTCASE (module_should_unload_after_export_lookup)
{
  assert_module_unloads_after_use (TEST_MODULE_USE_EXPORT_LOOKUP);
}

TESTCASE (module_should_unload_after_being_initialized)
{
  assert_module_unloads_after_use (TEST_MODULE_USE_INITIALIZATION);
}

TESTCASE (hooks_should_be_discarded_when_module_unloads)
{
#ifdef HAVE_LINUX
  GumModuleRegistry * registry;
  GumInterceptor * interceptor;
  TestCallbackListener * listener;
  TestModuleHooks hooks = { 0, };
  gulong added_handler, removed_handler;
  gchar * data_dir, * target_path;
  void * handle;
  gpointer target;
  GumAttachReturn result;

  registry = gum_module_registry_obtain ();
  interceptor = gum_interceptor_obtain ();
  listener = test_callback_listener_new ();

  added_handler = g_signal_connect (registry, "module-added",
      G_CALLBACK (on_target_module_added), &hooks);
  removed_handler = g_signal_connect (registry, "module-removed",
      G_CALLBACK (on_target_module_removed), &hooks);

  data_dir = test_util_get_data_dir ();
  target_path = g_build_filename (data_dir, GUM_TARGET_MODULE_FILENAME, NULL);

  handle = dlopen (target_path, RTLD_NOW | RTLD_LOCAL);
  g_assert_nonnull (handle);
  g_assert_true (hooks.seen_add);

  target = dlsym (handle, "gum_module_registry_target_function");
  g_assert_nonnull (target);

  result = gum_interceptor_attach (interceptor, target,
      GUM_INVOCATION_LISTENER (listener), NULL);
  g_assert_cmpint (result, ==, GUM_ATTACH_OK);

  dlclose (handle);

  /*
   * If the C library unloaded the module (glibc does; musl keeps it resident),
   * its live hook must have been discarded without restoring the now-unmapped
   * prologue, so detaching afterwards has to be a safe no-op.
   */
  gum_interceptor_detach (interceptor, GUM_INVOCATION_LISTENER (listener));

  if (!hooks.seen_remove)
    g_test_skip ("dlclose did not unload the module on this platform");

  g_signal_handler_disconnect (registry, added_handler);
  g_signal_handler_disconnect (registry, removed_handler);
  g_object_unref (listener);

  g_free (target_path);
  g_free (data_dir);
#else
  g_test_skip ("only supported on Linux");
#endif
}

TESTCASE (dependency_export_can_be_found)
{
#if defined (HAVE_WINDOWS)
  gchar * data_dir, * target_path;
  gunichar2 * target_path_utf16;
  HMODULE handle;
  GumModule * module;
  GumAddress address;

  gum_module_registry_obtain ();

  data_dir = test_util_get_data_dir ();
  target_path = g_build_filename (data_dir, GUM_DEPENDENT_MODULE_FILENAME,
      NULL);
  target_path_utf16 = g_utf8_to_utf16 (target_path, -1, NULL, NULL, NULL);

  handle = LoadLibraryExW ((LPCWSTR) target_path_utf16, NULL,
      LOAD_WITH_ALTERED_SEARCH_PATH);
  g_assert_nonnull (handle);

  module = find_registered_module (GUM_DEPENDENCY_MODULE_FILENAME);
  g_assert_nonnull (module);

  address = gum_module_find_export_by_name (module,
      GUM_DEPENDENCY_MODULE_EXPORT);
  g_assert_cmphex (address, ==, GUM_ADDRESS (GetProcAddress (
      GetModuleHandleA (GUM_DEPENDENCY_MODULE_FILENAME),
      GUM_DEPENDENCY_MODULE_EXPORT)));

  g_object_unref (module);

  FreeLibrary (handle);

  module = find_registered_module (GUM_DEPENDENCY_MODULE_FILENAME);
  g_assert_null (module);

  g_free (target_path_utf16);
  g_free (target_path);
  g_free (data_dir);
#elif defined (HAVE_LINUX)
  gchar * data_dir, * target_path;
  void * handle;
  GumModule * module;
  GumAddress address;

  gum_module_registry_obtain ();

  data_dir = test_util_get_data_dir ();
  target_path = g_build_filename (data_dir, GUM_DEPENDENT_MODULE_FILENAME,
      NULL);

  handle = dlopen (target_path, RTLD_NOW | RTLD_LOCAL);
  g_assert_nonnull (handle);

  module = gum_process_find_module_by_name (GUM_DEPENDENCY_MODULE_FILENAME);
  g_assert_nonnull (module);

  address = gum_module_find_export_by_name (module,
      GUM_DEPENDENCY_MODULE_EXPORT);
  g_assert_cmphex (address, ==,
      GUM_ADDRESS (dlsym (handle, GUM_DEPENDENCY_MODULE_EXPORT)));

  g_object_unref (module);
  dlclose (handle);
  g_free (target_path);
  g_free (data_dir);
#else
  g_test_skip ("only supported on Windows and Linux");
#endif
}

TESTCASE (delay_loaded_modules_should_be_registered)
{
#ifdef HAVE_WINDOWS
  GumModuleRegistry * registry;
  gboolean seen_add = FALSE;
  gulong handler;
  WCHAR path[MAX_PATH];
  HMODULE handle;
  GumModule * module;
  const GumMemoryRange * range;

  if (GetModuleHandleA (GUM_DELAY_LOADED_MODULE_FILENAME) != NULL)
  {
    g_test_skip ("delay-loaded module already present");
    return;
  }

  registry = gum_module_registry_obtain ();
  handler = g_signal_connect (registry, "module-added",
      G_CALLBACK (on_delay_loaded_module_added), &seen_add);

  g_assert_cmphex (SHGetFolderPathW (NULL, CSIDL_LOCAL_APPDATA, NULL, 0,
      path), ==, S_OK);

  g_signal_handler_disconnect (registry, handler);

  handle = GetModuleHandleA (GUM_DELAY_LOADED_MODULE_FILENAME);
  if (handle == NULL)
  {
    g_test_skip ("delay-loaded module not used by this Windows version");
    return;
  }

  g_assert_true (seen_add);

  module = find_registered_module (GUM_DELAY_LOADED_MODULE_FILENAME);
  g_assert_nonnull (module);
  range = gum_module_get_range (module);
  g_assert_cmphex (range->base_address, ==, GUM_ADDRESS (handle));
  g_assert_cmpuint (range->size, !=, 0);
  g_object_unref (module);
#else
  g_test_skip ("only supported on Windows");
#endif
}

TESTCASE (executable_images_should_be_registered)
{
#ifdef HAVE_WINDOWS
  gchar * data_dir, * program_path;
  gunichar2 * program_path_utf16;
  HMODULE handle;
  GumModule * module;

  gum_module_registry_obtain ();

  data_dir = test_util_get_data_dir ();
  program_path = g_build_filename (data_dir, GUM_PROGRAM_MODULE_FILENAME,
      NULL);
  program_path_utf16 = g_utf8_to_utf16 (program_path, -1, NULL, NULL, NULL);

  handle = LoadLibraryExW ((LPCWSTR) program_path_utf16, NULL, 0);
  g_assert_nonnull (handle);

  module = find_registered_module (GUM_PROGRAM_MODULE_FILENAME);
  g_assert_nonnull (module);
  g_assert_cmphex (gum_module_get_range (module)->base_address, ==,
      GUM_ADDRESS (handle));
  g_object_unref (module);

  FreeLibrary (handle);

  module = find_registered_module (GUM_PROGRAM_MODULE_FILENAME);
  g_assert_null (module);

  g_free (program_path_utf16);
  g_free (program_path);
  g_free (data_dir);
#else
  g_test_skip ("only supported on Windows");
#endif
}

TESTCASE (global_export_lookup_should_survive_module_loading)
{
#ifdef HAVE_WINDOWS
  gchar * data_dir, * target_path;
  gunichar2 * target_path_utf16;
  TestLoaderRace race;
  HANDLE threads[2];

  gum_module_registry_obtain ();

  data_dir = test_util_get_data_dir ();
  target_path = g_build_filename (data_dir, GUM_DEPENDENT_MODULE_FILENAME,
      NULL);
  target_path_utf16 = g_utf8_to_utf16 (target_path, -1, NULL, NULL, NULL);

  race.module_path = target_path_utf16;
  race.num_loads = 0;
  race.lookups_done = FALSE;

  threads[0] = CreateThread (NULL, 0, look_up_missing_exports, &race, 0, NULL);
  threads[1] = CreateThread (NULL, 0, load_and_unload_module, &race, 0, NULL);

  if (WaitForMultipleObjects (G_N_ELEMENTS (threads), threads, TRUE, 10000) !=
      WAIT_OBJECT_0)
  {
    g_printerr ("\nFAIL: lookup and module loading are deadlocked\n\n");
    TerminateProcess (GetCurrentProcess (), 1);
  }
  g_assert_cmpuint (race.num_loads, >, 0);

  CloseHandle (threads[1]);
  CloseHandle (threads[0]);

  g_free (target_path_utf16);
  g_free (target_path);
  g_free (data_dir);
#else
  g_test_skip ("only supported on Windows");
#endif
}

TESTCASE (registry_should_have_modules_for_every_thread_obtaining_it)
{
#ifdef GUM_HAVE_MODULE_REGISTRY_RACER
  guint i;

  for (i = 0; i != 20; i++)
    g_assert_true (run_module_registry_racer ());
#else
  g_test_skip ("only supported on Windows and Linux");
#endif
}

TESTCASE (nonzero_vaddr_module_should_be_found_at_its_header)
{
#ifdef HAVE_LINUX
  assert_nonzero_vaddr_module_found_at_its_header (FALSE);
#else
  g_test_skip ("only supported on Linux");
#endif
}

TESTCASE (displaced_nonzero_vaddr_module_should_be_found_at_its_header)
{
#ifdef HAVE_LINUX
  if (g_test_subprocess ())
  {
    assert_nonzero_vaddr_module_found_at_its_header (TRUE);
  }
  else
  {
    g_test_trap_subprocess (NULL, 0, (GTestSubprocessFlags) 0);
    g_test_trap_assert_passed ();
  }
#else
  g_test_skip ("only supported on Linux");
#endif
}

TESTCASE (relocated_program_headers_can_be_parsed)
{
#ifdef GUM_HAVE_RELOCATED_PHDR_TARGET
  gchar * data_dir, * target_path;
  GumModuleRegistry * registry;
  TestRelocatedPhdrContext ctx = { 0, };
  gulong handler;
  void * handle, * expected_export;

  data_dir = test_util_get_data_dir ();
  target_path = g_build_filename (data_dir,
      GUM_RELOCATED_PHDR_TARGET_FILENAME, NULL);
  assert_relocated_phdr_layout (target_path);

  registry = gum_module_registry_obtain ();
  handler = g_signal_connect (registry, "module-added",
      G_CALLBACK (on_relocated_phdr_module_added), &ctx);

  handle = dlopen (target_path, RTLD_NOW | RTLD_LOCAL);
  g_assert_nonnull (handle);

  g_signal_handler_disconnect (registry, handler);

  g_assert_true (ctx.seen);
  expected_export = dlsym (handle, GUM_TARGET_MODULE_EXPORT);
  g_assert_nonnull (expected_export);
  g_assert_cmphex (ctx.export_address, ==, GUM_ADDRESS (expected_export));

  dlclose (handle);
  g_free (target_path);
  g_free (data_dir);
#else
  g_test_skip ("only supported on Linux/x86-64");
#endif
}

TESTCASE (online_elf_should_allow_padded_inline_program_headers)
{
#ifdef HAVE_LINUX
  guint page_size;
  guint8 * page;
  ElfW(Ehdr) * ehdr;
  ElfW(Phdr) * phdr;
  GumElfModule * module;
  GError * error = NULL;

  page_size = gum_query_page_size ();
  page = gum_memory_allocate (NULL, page_size, page_size, GUM_PAGE_RW);
  g_assert_nonnull (page);

  memset (page, 0, page_size);
  ehdr = (ElfW(Ehdr) *) page;
  memcpy (ehdr->e_ident, ELFMAG, SELFMAG);
  ehdr->e_ident[EI_CLASS] = GUM_TEST_ELF_CLASS;
  ehdr->e_ident[EI_DATA] = GUM_TEST_ELF_ENCODING;
  ehdr->e_ident[EI_VERSION] = EV_CURRENT;
  ehdr->e_type = ET_DYN;
  ehdr->e_version = EV_CURRENT;
  ehdr->e_ehsize = sizeof (ElfW(Ehdr));
  ehdr->e_phoff = ehdr->e_ehsize + 16;
  ehdr->e_phentsize = sizeof (ElfW(Phdr));
  ehdr->e_phnum = 1;

  phdr = (ElfW(Phdr) *) (page + ehdr->e_phoff);
  phdr->p_type = PT_LOAD;
  phdr->p_flags = PF_R | PF_W;
  phdr->p_filesz = page_size;
  phdr->p_memsz = page_size;
  phdr->p_align = page_size;

  g_assert_cmpuint (ehdr->e_phoff, !=, ehdr->e_ehsize);
  g_assert_cmpuint (ehdr->e_phoff + ehdr->e_phentsize, <=, page_size);

  module = gum_elf_module_new_from_memory (GUM_TEST_UNOPENABLE_PATH,
      GUM_ADDRESS (page), &error);
  g_assert_no_error (error);
  g_assert_nonnull (module);
  g_assert_cmpuint (gum_elf_module_get_mapped_size (module), ==, page_size);

  g_object_unref (module);
  gum_memory_free (page, page_size);
#else
  g_test_skip ("only supported on Linux");
#endif
}

TESTCASE (online_elf_should_bound_inline_program_headers)
{
#ifdef HAVE_LINUX
  if (g_test_subprocess ())
  {
    guint page_size;
    guint8 * pages;
    ElfW(Ehdr) * ehdr;
    GumElfModule * module;
    GError * error = NULL;

    page_size = gum_query_page_size ();
    pages = gum_memory_allocate (NULL, 2 * page_size, page_size,
        GUM_PAGE_RW);
    g_assert_nonnull (pages);
    gum_mprotect (pages + page_size, page_size, GUM_PAGE_NO_ACCESS);

    memset (pages, 0, page_size);
    ehdr = (ElfW(Ehdr) *) pages;
    memcpy (ehdr->e_ident, ELFMAG, SELFMAG);
    ehdr->e_ident[EI_CLASS] = GUM_TEST_ELF_CLASS;
    ehdr->e_ident[EI_DATA] = GUM_TEST_ELF_ENCODING;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_type = ET_DYN;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_ehsize = sizeof (ElfW(Ehdr));
    ehdr->e_phoff = ehdr->e_ehsize;
    ehdr->e_phentsize = (guint16) (page_size - ehdr->e_ehsize);
    ehdr->e_phnum = 2;
    g_assert_cmpuint (ehdr->e_phoff, ==, ehdr->e_ehsize);
    g_assert_cmpuint (ehdr->e_phoff + ehdr->e_phentsize, ==, page_size);

    module = gum_elf_module_new_from_memory (GUM_TEST_UNOPENABLE_PATH,
        GUM_ADDRESS (pages), &error);
    g_assert_null (module);
    g_assert_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT);

    g_clear_error (&error);
    gum_memory_free (pages, 2 * page_size);
  }
  else
  {
    g_test_trap_subprocess (NULL, 0, (GTestSubprocessFlags) 0);
    g_test_trap_assert_passed ();
  }
#else
  g_test_skip ("only supported on Linux");
#endif
}

TESTCASE (online_elf_should_skip_unreadable_section_headers)
{
#ifdef HAVE_LINUX
  if (g_test_subprocess ())
  {
    assert_online_elf_skips_unreadable_section_data (FALSE);
    return;
  }

  g_test_trap_subprocess (NULL, 0, (GTestSubprocessFlags) 0);
  g_test_trap_assert_passed ();
#else
  g_test_skip ("only supported on Linux");
#endif
}

TESTCASE (online_elf_should_skip_unreadable_section_names)
{
#ifdef HAVE_LINUX
  if (g_test_subprocess ())
  {
    assert_online_elf_skips_unreadable_section_data (TRUE);
    return;
  }

  g_test_trap_subprocess (NULL, 0, (GTestSubprocessFlags) 0);
  g_test_trap_assert_passed ();
#else
  g_test_skip ("only supported on Linux");
#endif
}

static void
on_module_added (GumModuleRegistry * registry,
                 GumModule * module,
                 gpointer user_data)
{
  g_printerr ("%s: path=\"%s\"\n", G_STRFUNC, gum_module_get_path (module));
}

static void
on_module_removed (GumModuleRegistry * registry,
                   GumModule * module,
                   gpointer user_data)
{
  g_printerr ("%s: path=\"%s\"\n", G_STRFUNC, gum_module_get_path (module));
}

static void
assert_module_unloads_after_use (TestModuleUse use)
{
#ifdef G_OS_NONE
  g_test_skip ("dynamic libraries are not supported by the Barebone backend");
#else
  gchar * data_dir, * path;
  GumModuleRegistry * registry;
  TestModuleRemoval removal = { GUM_OBSERVER_TARGET_MODULE_FILENAME, 0 };
  gulong handler;
  gpointer handle;
  GumModule * module, * reloaded_module;

  data_dir = test_util_get_data_dir ();
  path = g_build_filename (data_dir, GUM_OBSERVER_TARGET_MODULE_FILENAME,
      NULL);

  registry = gum_module_registry_obtain ();
  handler = g_signal_connect (registry, "module-removed",
      G_CALLBACK (on_observer_target_removed), &removal);

  handle = load_library (path);
  module =
      gum_process_find_module_by_name (GUM_OBSERVER_TARGET_MODULE_FILENAME);
  g_assert_nonnull (module);

  if (use == TEST_MODULE_USE_EXPORT_LOOKUP)
  {
    g_assert_cmphex (gum_module_find_export_by_name (module,
        GUM_OBSERVER_TARGET_MODULE_EXPORT), !=, 0);
  }
  else
  {
    gum_module_ensure_initialized (module);
  }

  unload_library (handle);

  g_assert_cmpuint (removal.count, ==, 1);
#ifndef HAVE_QNX
  g_assert_false (library_is_loaded (path));
#endif
  g_assert_null (
      gum_process_find_module_by_name (GUM_OBSERVER_TARGET_MODULE_FILENAME));
  g_assert_cmphex (gum_module_find_export_by_name (module,
      GUM_OBSERVER_TARGET_MODULE_EXPORT), ==, 0);

  handle = load_library (path);
  reloaded_module =
      gum_process_find_module_by_name (GUM_OBSERVER_TARGET_MODULE_FILENAME);
  g_assert_nonnull (reloaded_module);
  g_assert_true (reloaded_module != module);
  unload_library (handle);

  g_assert_cmpuint (removal.count, ==, 2);

  g_object_unref (reloaded_module);
  g_object_unref (module);
  g_signal_handler_disconnect (registry, handler);
  g_free (path);
  g_free (data_dir);
#endif
}

static void
on_observer_target_removed (GumModuleRegistry * registry,
                            GumModule * module,
                            gpointer user_data)
{
  TestModuleRemoval * removal = user_data;

  if (strcmp (gum_module_get_name (module), removal->name) == 0)
    removal->count++;
}

#ifndef G_OS_NONE

static gpointer
load_library (const gchar * path)
{
  gpointer handle;
#ifdef HAVE_WINDOWS
  gunichar2 * path_utf16;

  path_utf16 = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  handle = LoadLibraryW ((LPCWSTR) path_utf16);
  g_free (path_utf16);
#else
  handle = dlopen (path, RTLD_NOW | RTLD_LOCAL);
#endif
  g_assert_nonnull (handle);

  return handle;
}

static void
unload_library (gpointer handle)
{
#ifdef HAVE_WINDOWS
  FreeLibrary (handle);
#else
  dlclose (handle);
#endif
}

#ifndef HAVE_QNX

static gboolean
library_is_loaded (const gchar * path)
{
  gboolean loaded;
#ifdef HAVE_WINDOWS
  gunichar2 * path_utf16;

  path_utf16 = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  loaded = GetModuleHandleW ((LPCWSTR) path_utf16) != NULL;
  g_free (path_utf16);
#else
  gpointer handle;

  handle = dlopen (path, RTLD_LAZY | RTLD_NOLOAD);
  loaded = handle != NULL;
  if (loaded)
    dlclose (handle);
#endif

  return loaded;
}

#endif

#endif

#ifdef HAVE_WINDOWS

static void
on_delay_loaded_module_added (GumModuleRegistry * registry,
                              GumModule * module,
                              gpointer user_data)
{
  gboolean * seen_add = user_data;

  if (g_ascii_strcasecmp (gum_module_get_name (module),
      GUM_DELAY_LOADED_MODULE_FILENAME) == 0)
  {
    *seen_add = TRUE;
  }
}

static GumModule *
find_registered_module (const gchar * name)
{
  TestFindModuleContext ctx = { name, NULL };

  gum_process_enumerate_modules (store_module_if_named, &ctx);

  return ctx.module;
}

static gboolean
store_module_if_named (GumModule * module,
                       gpointer user_data)
{
  TestFindModuleContext * ctx = user_data;

  if (g_ascii_strcasecmp (gum_module_get_name (module), ctx->name) != 0)
    return TRUE;

  ctx->module = g_object_ref (module);

  return FALSE;
}

static DWORD WINAPI
look_up_missing_exports (LPVOID data)
{
  TestLoaderRace * race = data;
  guint i;

  for (i = 0; i != 2000; i++)
  {
    g_assert_cmphex (
        gum_module_find_global_export_by_name ("gum_test_no_such_export"),
        ==, 0);
  }

  g_atomic_int_set (&race->lookups_done, TRUE);

  return 0;
}

static DWORD WINAPI
load_and_unload_module (LPVOID data)
{
  TestLoaderRace * race = data;

  do
  {
    HMODULE handle;

    handle = LoadLibraryExW ((LPCWSTR) race->module_path, NULL,
        LOAD_WITH_ALTERED_SEARCH_PATH);
    g_assert_nonnull (handle);
    FreeLibrary (handle);

    race->num_loads++;
  }
  while (!g_atomic_int_get (&race->lookups_done));

  return 0;
}

#endif

#ifdef HAVE_LINUX

static void
on_target_module_added (GumModuleRegistry * registry,
                        GumModule * module,
                        gpointer user_data)
{
  TestModuleHooks * hooks = user_data;

  if (is_target_module (module))
    hooks->seen_add = TRUE;
}

static void
on_target_module_removed (GumModuleRegistry * registry,
                          GumModule * module,
                          gpointer user_data)
{
  TestModuleHooks * hooks = user_data;

  if (is_target_module (module))
    hooks->seen_remove = TRUE;
}

static gboolean
is_target_module (GumModule * module)
{
  return g_str_has_suffix (gum_module_get_path (module),
      G_DIR_SEPARATOR_S GUM_TARGET_MODULE_FILENAME);
}

static void
assert_nonzero_vaddr_module_found_at_its_header (gboolean occupy_link_address)
{
  gchar * data_dir, * target_path;
  gpointer reservation = NULL;
  GumModuleRegistry * registry;
  TestNonzeroVaddrContext ctx = { 0, };
  gulong handler;
  void * handle, * function;
  Dl_info info;

  data_dir = test_util_get_data_dir ();
  target_path = g_build_filename (data_dir,
      GUM_NONZERO_VADDR_MODULE_FILENAME, NULL);

  if (!g_file_test (target_path, G_FILE_TEST_EXISTS))
  {
    g_test_skip ("linker does not support -Ttext-segment");
    goto beach;
  }

  if (occupy_link_address)
  {
    reservation = mmap (GSIZE_TO_POINTER (
        GUM_NONZERO_VADDR_MODULE_LINK_ADDRESS), gum_query_page_size (),
        PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_assert_true (reservation != MAP_FAILED);
  }

  registry = gum_module_registry_obtain ();
  handler = g_signal_connect (registry, "module-added",
      G_CALLBACK (on_nonzero_vaddr_module_added), &ctx);

  handle = dlopen (target_path, RTLD_NOW | RTLD_LOCAL);
  g_assert_nonnull (handle);

  g_signal_handler_disconnect (registry, handler);

  function = dlsym (handle, "gum_module_registry_target_function");
  g_assert_nonnull (function);
  g_assert_true (dladdr (function, &info) != 0);

  if (occupy_link_address)
  {
    g_assert_cmphex (GUM_ADDRESS (info.dli_fbase), !=,
        GUM_NONZERO_VADDR_MODULE_LINK_ADDRESS);
  }

  g_assert_true (ctx.seen);
  g_assert_cmphex (ctx.range.base_address, ==, GUM_ADDRESS (info.dli_fbase));
  g_assert_true (GUM_MEMORY_RANGE_INCLUDES (&ctx.range,
      GUM_ADDRESS (function)));

  dlclose (handle);

  if (reservation != NULL)
    munmap (reservation, gum_query_page_size ());

beach:
  g_free (target_path);
  g_free (data_dir);
}

static void
on_nonzero_vaddr_module_added (GumModuleRegistry * registry,
                               GumModule * module,
                               gpointer user_data)
{
  TestNonzeroVaddrContext * ctx = user_data;

  if (!g_str_has_suffix (gum_module_get_path (module),
      G_DIR_SEPARATOR_S GUM_NONZERO_VADDR_MODULE_FILENAME))
    return;

  ctx->seen = TRUE;
  ctx->range = *gum_module_get_range (module);
}

static void
assert_online_elf_skips_unreadable_section_data (gboolean names)
{
  guint page_size;
  gsize offset;
  guint8 * pages;
  ElfW(Ehdr) * ehdr;
  ElfW(Phdr) * phdr;
  ElfW(Shdr) * shdr;
  GumElfModule * module;
  GError * error = NULL;

  page_size = gum_query_page_size ();
  offset = page_size;
  pages = gum_memory_allocate (NULL, 2 * page_size, page_size, GUM_PAGE_RW);
  g_assert_nonnull (pages);
  memset (pages, 0, page_size);
  gum_mprotect (pages + offset, page_size, GUM_PAGE_NO_ACCESS);

  ehdr = (ElfW(Ehdr) *) pages;
  memcpy (ehdr->e_ident, ELFMAG, SELFMAG);
  ehdr->e_ident[EI_CLASS] = GUM_TEST_ELF_CLASS;
  ehdr->e_ident[EI_DATA] = GUM_TEST_ELF_ENCODING;
  ehdr->e_ident[EI_VERSION] = EV_CURRENT;
  ehdr->e_type = ET_DYN;
  ehdr->e_version = EV_CURRENT;
  ehdr->e_ehsize = sizeof (ElfW(Ehdr));
  ehdr->e_phoff = ehdr->e_ehsize;
  ehdr->e_phentsize = sizeof (ElfW(Phdr));
  ehdr->e_phnum = 1;
  ehdr->e_shentsize = sizeof (ElfW(Shdr));

  phdr = (ElfW(Phdr) *) (pages + ehdr->e_phoff);
  phdr->p_type = PT_LOAD;
  phdr->p_flags = PF_R | PF_W;
  phdr->p_filesz = 2 * page_size;
  phdr->p_memsz = 2 * page_size;
  phdr->p_align = page_size;

  if (names)
  {
    ehdr->e_shoff = GUM_ALIGN_SIZE (
        ehdr->e_phoff + ehdr->e_phentsize, sizeof (gpointer));
    ehdr->e_shnum = 2;
    ehdr->e_shstrndx = 1;

    shdr = (ElfW(Shdr) *) (pages + ehdr->e_shoff) + 1;
    shdr->sh_type = SHT_STRTAB;
    shdr->sh_offset = offset;
    shdr->sh_size = 1;
  }
  else
  {
    ehdr->e_shoff = offset;
    ehdr->e_shnum = 1;
  }

  module = gum_elf_module_new_from_memory (GUM_TEST_UNOPENABLE_PATH,
      GUM_ADDRESS (pages), &error);
  g_assert_no_error (error);
  g_assert_nonnull (module);

  g_object_unref (module);
  gum_memory_free (pages, 2 * page_size);
}

#endif

#ifdef GUM_HAVE_MODULE_REGISTRY_RACER

static gboolean
run_module_registry_racer (void)
{
  gboolean passed;
  gchar * data_dir, * racer_path;

  data_dir = test_util_get_data_dir ();
  racer_path = g_build_filename (data_dir, GUM_RACER_PROGRAM_FILENAME, NULL);

#ifdef HAVE_WINDOWS
  {
    gunichar2 * racer_path_utf16;
    STARTUPINFOW si = { 0, };
    PROCESS_INFORMATION pi;
    DWORD exit_code = 1;

    racer_path_utf16 = g_utf8_to_utf16 (racer_path, -1, NULL, NULL, NULL);

    si.cb = sizeof (si);
    g_assert_true (CreateProcessW ((LPCWSTR) racer_path_utf16, NULL, NULL,
        NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi));
    CloseHandle (pi.hThread);

    WaitForSingleObject (pi.hProcess, INFINITE);
    GetExitCodeProcess (pi.hProcess, &exit_code);
    CloseHandle (pi.hProcess);

    g_free (racer_path_utf16);

    passed = exit_code == 0;
  }
#else
  {
    gchar * argv[2];
    gint wait_status = -1;

    argv[0] = racer_path;
    argv[1] = NULL;

    g_assert_true (g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL,
        NULL, NULL, &wait_status, NULL));

    passed = wait_status == 0;
  }
#endif

  g_free (racer_path);
  g_free (data_dir);

  return passed;
}

#endif

#ifdef GUM_HAVE_RELOCATED_PHDR_TARGET

static void
on_relocated_phdr_module_added (GumModuleRegistry * registry,
                                GumModule * module,
                                gpointer user_data)
{
  TestRelocatedPhdrContext * ctx = user_data;

  if (!g_str_has_suffix (gum_module_get_path (module),
      G_DIR_SEPARATOR_S GUM_RELOCATED_PHDR_TARGET_FILENAME))
    return;

  ctx->seen = TRUE;
  gum_module_enumerate_exports (module, on_relocated_phdr_export_found, ctx);
}

static gboolean
on_relocated_phdr_export_found (const GumExportDetails * details,
                                gpointer user_data)
{
  TestRelocatedPhdrContext * ctx = user_data;

  if (g_strcmp0 (details->name, GUM_TARGET_MODULE_EXPORT) != 0)
    return TRUE;

  ctx->export_address = details->address;

  return FALSE;
}

static void
assert_relocated_phdr_layout (const gchar * path)
{
  gchar * data;
  gsize size;
  const ElfW(Ehdr) * ehdr;
  const ElfW(Phdr) * phdrs, * pt_phdr;
  guint i;

  pt_phdr = NULL;

  g_assert_true (g_file_get_contents (path, &data, &size, NULL));
  g_assert_cmpuint (size, >=, sizeof (ElfW(Ehdr)));

  ehdr = (const ElfW(Ehdr) *) data;
  g_assert_cmpmem (ehdr->e_ident, SELFMAG, ELFMAG, SELFMAG);
  g_assert_cmpuint (ehdr->e_phentsize, ==, sizeof (ElfW(Phdr)));
  g_assert_cmpuint (ehdr->e_phoff +
      ((gsize) ehdr->e_phnum * ehdr->e_phentsize), <=, size);

  phdrs = (const ElfW(Phdr) *) (data + ehdr->e_phoff);
  for (i = 0; i != ehdr->e_phnum; i++)
  {
    if (phdrs[i].p_type == PT_PHDR)
    {
      pt_phdr = &phdrs[i];
      break;
    }
  }

  g_assert_nonnull (pt_phdr);
  g_assert_cmphex (pt_phdr->p_offset, ==, ehdr->e_phoff);
  g_assert_cmphex (pt_phdr->p_vaddr, !=, ehdr->e_phoff);

  g_free (data);
}

#endif
