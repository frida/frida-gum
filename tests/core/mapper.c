/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gummapper.h"

#include "testutil.h"
#include "gum/gumelfmoduleresolver.h"
#include "gum/gumnativeprocessmemory.h"
#ifdef HAVE_WINDOWS
# include "gum/gumwindows.h"
#endif
#ifdef HAVE_DARWIN
# include "gum/gumdarwin.h"
#else
# include "gum/gumnativemoduleresolver.h"
#endif

#include <string.h>
#ifdef HAVE_WINDOWS
# include <windows.h>
# include <psapi.h>
#else
# include <dlfcn.h>
# include <signal.h>
# include <unistd.h>
# include <sys/wait.h>
# if defined (HAVE_LINUX) && defined (HAVE_ARM64)
#  include <sys/auxv.h>
# endif
#endif

#define TESTCASE(NAME) \
    void test_mapper_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/Mapper", test_mapper, NAME)

#if defined (HAVE_WINDOWS)
# define GUM_TEST_MAPPER_TARGET "mapper-target.dll"
#elif defined (HAVE_DARWIN)
# define GUM_TEST_MAPPER_TARGET "mapper-target.dylib"
#else
# define GUM_TEST_MAPPER_TARGET "mapper-target.so"
#endif

#if !defined (HAVE_WINDOWS) && !defined (HAVE_DARWIN)
# define GUM_TEST_HAVE_POOL_MEMORY 1
# define GUM_TEST_POOL_SIZE (16 * 1024 * 1024)

# define GUM_TEST_TYPE_POOL_MEMORY (gum_test_pool_memory_get_type ())
G_DECLARE_FINAL_TYPE (GumTestPoolMemory, gum_test_pool_memory, GUM_TEST,
    POOL_MEMORY, GObject)
#endif

#ifdef HAVE_LINUX
# define GUM_TEST_IFUNC_ARG_HWCAP (G_GUINT64_CONSTANT (1) << 62)

# define GUM_TEST_TYPE_INDIRECT_RESOLVER \
    (gum_test_indirect_resolver_get_type ())
G_DECLARE_FINAL_TYPE (GumTestIndirectResolver, gum_test_indirect_resolver,
    GUM_TEST, INDIRECT_RESOLVER, GObject)
#endif

TESTLIST_BEGIN (mapper)
  TESTENTRY (exports_can_be_resolved_and_called)
  TESTENTRY (extra_memory_follows_mapping)
  TESTENTRY (exports_can_be_enumerated)
  TESTENTRY (constructor_runs_initializers)
  TESTENTRY (destructor_runs_finalizers)
  TESTENTRY (imports_are_resolved)
  TESTENTRY (tls_storage_is_per_thread)
  TESTENTRY (tls_storage_for_multiple_modules)
  TESTENTRY (tls_storage_survives_remapping)
  TESTENTRY (maps_into_another_process)
  TESTENTRY (maps_tls_into_another_process)
#ifdef HAVE_LINUX
  TESTENTRY (indirect_imports_are_resolved)
#endif
#if defined (HAVE_LINUX) && defined (__GLIBC__)
  TESTENTRY (elf_resolver_agrees_with_loader)
  TESTENTRY (elf_resolver_supports_memory_snapshot)
#endif
#ifdef HAVE_WINDOWS
  TESTENTRY (code_is_shared_section_view)
  TESTENTRY (windows_resolver_agrees_with_loader)
  TESTENTRY (windows_resolver_supports_suspended_process)
#endif
TESTLIST_END ()

typedef struct _GumTestTarget GumTestTarget;
typedef struct _GumTestExportSearch GumTestExportSearch;
typedef struct _GumTestTlsThreadContext GumTestTlsThreadContext;
typedef struct _GumTestMultiTlsContext GumTestMultiTlsContext;
typedef struct _GumTestRemote GumTestRemote;
#if defined (HAVE_LINUX) && defined (__GLIBC__)
typedef struct _GumTestSnapshot GumTestSnapshot;
#endif
#ifdef HAVE_WINDOWS
typedef struct _GumTestLoaderComparison GumTestLoaderComparison;
#endif
#ifdef HAVE_DARWIN
typedef struct _GumTestTaskPortMessage GumTestTaskPortMessage;
typedef struct _GumTestTaskPortReceipt GumTestTaskPortReceipt;
#endif

struct _GumTestTarget
{
  GumModuleResolver * resolver;
  GumMapper * mapper;

  void (* constructor) (void);
  void (* destructor) (void);
};

struct _GumTestExportSearch
{
  const gchar * name;
  GumAddress address;
};

struct _GumTestTlsThreadContext
{
  int (* get) (void);
  void (* set) (int value);
  int observed_initial;
};

struct _GumTestMultiTlsContext
{
  int (* get_a) (void);
  int (* get_b) (void);
  int observed_a;
  int observed_b;
};

struct _GumTestRemote
{
  GumModuleResolver * resolver;
  GumMapper * mapper;

  GumProcessMemory * memory;
#ifdef GUM_TEST_HAVE_POOL_MEMORY
  gpointer pool;
#endif
#ifdef HAVE_WINDOWS
  HANDLE process;
#else
  GumProcessId pid;
  int to_victim;
  int from_victim;
#endif
#ifdef HAVE_DARWIN
  mach_port_t task;
#endif
};

#ifdef HAVE_WINDOWS
struct _GumTestLoaderComparison
{
  HMODULE local;
  GumModule * resolved;
};
#endif

#ifdef GUM_TEST_HAVE_POOL_MEMORY
struct _GumTestPoolMemory
{
  GObject parent;

  GumProcessMemory * inner;
  GumAddress cursor;
  GumAddress end;
};
#endif

#if defined (HAVE_LINUX) && defined (__GLIBC__)
struct _GumTestSnapshot
{
  GumAddress base;
  guint8 * data;
};
#endif

#ifdef HAVE_LINUX
struct _GumTestIndirectResolver
{
  GObject parent;

  GumModuleResolver * inner;
};
#endif

#ifdef HAVE_DARWIN
struct _GumTestTaskPortMessage
{
  mach_msg_header_t header;
  mach_msg_body_t body;
  mach_msg_port_descriptor_t task;
};

struct _GumTestTaskPortReceipt
{
  GumTestTaskPortMessage message;
  mach_msg_trailer_t trailer;
};
#endif

static void gum_test_target_open (GumTestTarget * target);
static void gum_test_target_close (GumTestTarget * target);
static gboolean gum_test_store_export (const GumExportDetails * details,
    gpointer user_data);
static gpointer gum_test_tls_thread (gpointer data);
static gpointer gum_test_multi_tls_thread (gpointer data);
static gboolean gum_test_remote_open (GumTestRemote * remote);
static GBytes * gum_test_target_read (void);
static GumModuleResolver * gum_test_resolver_new (void);
static void gum_test_remote_close (GumTestRemote * remote);
static void gum_test_remote_spawn_victim (GumTestRemote * remote);
static gboolean gum_test_remote_is_accessible (GumTestRemote * remote);
static int gum_test_remote_call (GumTestRemote * remote, GumAddress function);
static void gum_test_remote_kill_victim (GumTestRemote * remote);
#if defined (HAVE_LINUX) && defined (__GLIBC__)
static gboolean gum_test_copy_range (const GumRangeDetails * details,
    gpointer user_data);
#endif
#ifdef HAVE_WINDOWS
static gboolean gum_test_compare_with_loader (
    const GumPeExportDetails * details, gpointer user_data);
#endif
#ifdef HAVE_DARWIN
static void gum_test_send_task_port (void);
static mach_port_t gum_test_receive_task_port (mach_port_t channel);
#endif

#ifdef GUM_TEST_HAVE_POOL_MEMORY
static void gum_test_pool_memory_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_test_pool_memory_dispose (GObject * object);
static GumProcessMemory * gum_test_pool_memory_new (GumProcessMemory * inner,
    gpointer pool, gsize size);
static GumProcessId gum_test_pool_memory_get_pid (GumProcessMemory * memory);
static GumAddress gum_test_pool_memory_alloc (GumProcessMemory * memory,
    gsize size, gsize alignment);
static void gum_test_pool_memory_free (GumProcessMemory * memory,
    GumAddress address, gsize size);
static gboolean gum_test_pool_memory_read (GumProcessMemory * memory,
    GumAddress address, gpointer buffer, gsize size);
static gboolean gum_test_pool_memory_write (GumProcessMemory * memory,
    GumAddress address, gconstpointer data, gsize size);
static gboolean gum_test_pool_memory_protect (GumProcessMemory * memory,
    GumAddress address, gsize size, GumPageProtection prot);
static gboolean gum_test_pool_memory_mark_code (GumProcessMemory * memory,
    GumAddress address, gsize size);

G_DEFINE_TYPE_WITH_CODE (GumTestPoolMemory,
                         gum_test_pool_memory,
                         G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GUM_TYPE_PROCESS_MEMORY,
                             gum_test_pool_memory_iface_init))
#endif

#ifdef HAVE_LINUX
static void gum_test_indirect_resolver_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_test_indirect_resolver_dispose (GObject * object);
static GumModule * gum_test_indirect_resolver_find_module_by_name (
    GumModuleResolver * resolver, const gchar * name);
static GumAddress gum_test_indirect_resolver_find_dynamic_address (
    GumModuleResolver * resolver, const gchar * symbol);
static gboolean gum_test_indirect_resolver_find_dynamic_symbol (
    GumModuleResolver * resolver, const gchar * symbol,
    GumDynamicSymbolDetails * details);
static gpointer gum_test_resolve_getpid (guint64 hwcap, const guint64 * arg);
static gpointer gum_test_resolve_memcpy (guint64 hwcap, const guint64 * arg);
static void gum_test_check_ifunc_arguments (guint64 hwcap,
    const guint64 * arg);
static unsigned int gum_test_indirect_getpid (void);

G_DEFINE_TYPE_WITH_CODE (GumTestIndirectResolver,
                         gum_test_indirect_resolver,
                         G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (GUM_TYPE_MODULE_RESOLVER,
                             gum_test_indirect_resolver_iface_init))

static guint gum_test_ifunc_resolver_calls;
#endif

TESTCASE (exports_can_be_resolved_and_called)
{
  GumTestTarget target;
  int (* sum) (int a, int b);

  gum_test_target_open (&target);

  sum = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_mapper_sum"));
  g_assert_nonnull (sum);
  g_assert_cmpint (sum (3, 4), ==, 7);

  gum_test_target_close (&target);
}

TESTCASE (extra_memory_follows_mapping)
{
  GumModuleResolver * resolver;
  GumMapper * mapper;
  GError * error = NULL;
  GumAddress extra;
  const GumMemoryRange * range;
  gsize page_size;
  GumMapperConstructor constructor;
  int (* sum) (int a, int b);
  GumMapperDestructor destructor;

  resolver = gum_test_resolver_new ();

  mapper = gum_mapper_new_take_blob (GUM_TEST_MAPPER_TARGET,
      gum_test_target_read (), resolver, &error);
  g_assert_no_error (error);

  gum_mapper_map (mapper, 1, &extra, &error);
  g_assert_no_error (error);

  range = gum_mapper_get_range (mapper);
  page_size = gum_query_page_size ();
  g_assert_cmphex (extra + page_size, ==,
      range->base_address + range->size);

  memset (GSIZE_TO_POINTER (extra), 0xcc, page_size);

  constructor = GSIZE_TO_POINTER (gum_mapper_constructor (mapper));
  g_assert_cmphex (gum_strip_code_address (GUM_ADDRESS (constructor)), <,
      extra);
  constructor ();

  sum = GSIZE_TO_POINTER (gum_mapper_resolve (mapper, "gum_test_mapper_sum"));
  g_assert_cmpint (sum (3, 4), ==, 7);

  destructor = GSIZE_TO_POINTER (gum_mapper_destructor (mapper));
  destructor ();

  gum_mapper_unmap (mapper);
  g_object_unref (mapper);
  g_object_unref (resolver);
}

TESTCASE (exports_can_be_enumerated)
{
  GumTestTarget target;
  GumTestExportSearch search;

  gum_test_target_open (&target);

  search.name = "gum_test_mapper_sum";
  search.address = 0;
  gum_mapper_enumerate_exports (target.mapper, gum_test_store_export, &search);

  g_assert_cmphex (search.address, !=, 0);
  g_assert_cmphex (gum_strip_code_address (search.address), ==,
      gum_strip_code_address (
          gum_mapper_resolve (target.mapper, "gum_test_mapper_sum")));

  gum_test_target_close (&target);
}

TESTCASE (constructor_runs_initializers)
{
  GumTestTarget target;
  int (* get_magic) (void);

  gum_test_target_open (&target);

  get_magic = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_mapper_get_magic"));
  g_assert_nonnull (get_magic);
  g_assert_cmphex (get_magic (), ==, 0x1337);

  gum_test_target_close (&target);
}

TESTCASE (destructor_runs_finalizers)
{
  GumTestTarget target;
  int (* get_magic) (void);

  gum_test_target_open (&target);

  get_magic = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_mapper_get_magic"));
  g_assert_cmpint (get_magic (), ==, 0x1337);

  target.destructor ();
  g_assert_cmpint (get_magic (), ==, 0);

  gum_mapper_unmap (target.mapper);
  g_object_unref (target.mapper);
  g_object_unref (target.resolver);
}

TESTCASE (imports_are_resolved)
{
  GumTestTarget target;
  unsigned int (* get_pid) (void);

  gum_test_target_open (&target);

  get_pid = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_mapper_get_pid"));
  g_assert_nonnull (get_pid);
  g_assert_cmpuint (get_pid (), ==, gum_process_get_id ());

  gum_test_target_close (&target);
}

TESTCASE (tls_storage_is_per_thread)
{
  GumTestTarget target;
  GumTestTlsThreadContext ctx;
  GThread * thread;

  gum_test_target_open (&target);

  ctx.get = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_mapper_tls_get"));
  ctx.set = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_mapper_tls_set"));
  g_assert_nonnull (ctx.get);
  g_assert_nonnull (ctx.set);

  g_assert_cmphex (ctx.get (), ==, 0x1234);
  ctx.set (0xaaaa);
  g_assert_cmphex (ctx.get (), ==, 0xaaaa);

  ctx.observed_initial = 0;
  thread = g_thread_new ("tls-probe", gum_test_tls_thread, &ctx);
  g_thread_join (thread);

  g_assert_cmphex (ctx.observed_initial, ==, 0x1234);
  g_assert_cmphex (ctx.get (), ==, 0xaaaa);

  gum_test_target_close (&target);
}

TESTCASE (tls_storage_for_multiple_modules)
{
  GumTestTarget a, b;
  GumTestMultiTlsContext multi;
  GThread * thread;
  GumTestTlsThreadContext solo;

  gum_test_target_open (&a);
  gum_test_target_open (&b);

  multi.get_a = GSIZE_TO_POINTER (
      gum_mapper_resolve (a.mapper, "gum_test_mapper_tls_get"));
  multi.get_b = GSIZE_TO_POINTER (
      gum_mapper_resolve (b.mapper, "gum_test_mapper_tls_get"));
  g_assert_nonnull (multi.get_a);
  g_assert_nonnull (multi.get_b);

  g_assert_cmphex (multi.get_a (), ==, 0x1234);
  g_assert_cmphex (multi.get_b (), ==, 0x1234);

  multi.observed_a = 0;
  multi.observed_b = 0;
  thread = g_thread_new ("tls-multi", gum_test_multi_tls_thread, &multi);
  g_thread_join (thread);
  g_assert_cmphex (multi.observed_a, ==, 0x1234);
  g_assert_cmphex (multi.observed_b, ==, 0x1234);

  gum_test_target_close (&a);

  solo.get = multi.get_b;
  solo.set = GSIZE_TO_POINTER (
      gum_mapper_resolve (b.mapper, "gum_test_mapper_tls_set"));
  solo.observed_initial = 0;
  thread = g_thread_new ("tls-solo", gum_test_tls_thread, &solo);
  g_thread_join (thread);
  g_assert_cmphex (solo.observed_initial, ==, 0x1234);

  gum_test_target_close (&b);
}

TESTCASE (tls_storage_survives_remapping)
{
  GumTestTarget target;
  int (* get) (void);

  gum_test_target_open (&target);
  gum_test_target_close (&target);

  gum_test_target_open (&target);

  get = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_mapper_tls_get"));
  g_assert_cmphex (get (), ==, 0x1234);

  gum_test_target_close (&target);
}

#ifdef HAVE_LINUX

TESTCASE (indirect_imports_are_resolved)
{
  GumModuleResolver * resolver;
  GumMapper * mapper;
  GError * error = NULL;
  GumMapperConstructor constructor;
  unsigned int (* get_pid) (void);
  int (* tls_get) (void);
  GumMapperDestructor destructor;

  gum_test_ifunc_resolver_calls = 0;

  resolver = g_object_new (GUM_TEST_TYPE_INDIRECT_RESOLVER, NULL);

  mapper = gum_mapper_new_take_blob (GUM_TEST_MAPPER_TARGET,
      gum_test_target_read (), resolver, &error);
  g_assert_no_error (error);

  gum_mapper_map (mapper, 0, NULL, &error);
  g_assert_no_error (error);

  constructor = GSIZE_TO_POINTER (gum_mapper_constructor (mapper));
  constructor ();
  g_assert_cmpuint (gum_test_ifunc_resolver_calls, ==, 2);

  get_pid = GSIZE_TO_POINTER (
      gum_mapper_resolve (mapper, "gum_test_mapper_get_pid"));
  g_assert_cmpuint (get_pid (), ==, 0x4242);

  tls_get = GSIZE_TO_POINTER (
      gum_mapper_resolve (mapper, "gum_test_mapper_tls_get"));
  g_assert_cmphex (tls_get (), ==, 0x1234);

  destructor = GSIZE_TO_POINTER (gum_mapper_destructor (mapper));
  destructor ();

  gum_mapper_unmap (mapper);
  g_object_unref (mapper);
  g_object_unref (resolver);
}

#endif

#if defined (HAVE_LINUX) && defined (__GLIBC__)

TESTCASE (elf_resolver_agrees_with_loader)
{
  GumModule * libc;
  void * libc_handle;
  GumElfModule * elf;
  GumElfModuleResolver * resolver;
  GumDynamicSymbolDetails details;

  libc = gum_process_get_libc_module ();
  libc_handle = dlopen (gum_module_get_path (libc), RTLD_LAZY | RTLD_NOLOAD);
  g_assert_nonnull (libc_handle);
  elf = gum_elf_module_new_from_file (gum_module_get_path (libc), NULL);
  g_assert_nonnull (elf);

  resolver = gum_elf_module_resolver_new ();
  gum_elf_module_resolver_add_module (resolver, elf,
      gum_module_get_range (libc)->base_address);

  g_assert_true (gum_module_resolver_find_dynamic_symbol (
      GUM_MODULE_RESOLVER (resolver), "getpid", &details));
  g_assert_false (details.indirect);
  g_assert_cmphex (details.address, ==,
      GUM_ADDRESS (dlsym (libc_handle, "getpid")));

  g_assert_true (gum_module_resolver_find_dynamic_symbol (
      GUM_MODULE_RESOLVER (resolver), "pthread_cond_wait", &details));
  g_assert_cmphex (details.address, ==,
      GUM_ADDRESS (dlsym (libc_handle, "pthread_cond_wait")));

#ifdef HAVE_I386
  if (GLIB_SIZEOF_VOID_P == 8)
  {
    gpointer (* resolve_strlen) (void);

    g_assert_true (gum_module_resolver_find_dynamic_symbol (
        GUM_MODULE_RESOLVER (resolver), "strlen", &details));
    g_assert_true (details.indirect);
    g_assert_cmphex (gum_module_resolver_find_dynamic_address (
        GUM_MODULE_RESOLVER (resolver), "strlen"), ==, 0);

    resolve_strlen = GSIZE_TO_POINTER (details.address);
    g_assert_true (resolve_strlen () == dlsym (libc_handle, "strlen"));
  }
#endif

  g_object_unref (resolver);
  g_object_unref (elf);
  dlclose (libc_handle);
}

TESTCASE (elf_resolver_supports_memory_snapshot)
{
  GumModule * libc;
  const GumMemoryRange * range;
  void * libc_handle;
  GumTestSnapshot snapshot;
  GBytes * blob;
  GumElfModule * elf;
  GError * error = NULL;
  const gchar * soname;
  GumElfModuleResolver * resolver;
  GumDynamicSymbolDetails details;

  libc = gum_process_get_libc_module ();
  range = gum_module_get_range (libc);
  libc_handle = dlopen (gum_module_get_path (libc), RTLD_LAZY | RTLD_NOLOAD);
  g_assert_nonnull (libc_handle);

  snapshot.base = range->base_address;
  snapshot.data = g_malloc0 (range->size);
  gum_module_enumerate_ranges (libc, GUM_PAGE_READ, gum_test_copy_range,
      &snapshot);
  blob = g_bytes_new_take (snapshot.data, range->size);

  elf = g_object_new (GUM_TYPE_ELF_MODULE,
      "base-address", range->base_address,
      "source-path", gum_module_get_path (libc),
      "source-blob", blob,
      "source-mode", GUM_ELF_SOURCE_MODE_ONLINE,
      NULL);
  g_assert_true (gum_elf_module_load (elf, &error));
  g_assert_no_error (error);

  soname = gum_elf_module_get_soname (elf);
  g_assert_true ((const guint8 *) soname >= snapshot.data &&
      (const guint8 *) soname < snapshot.data + range->size);

  resolver = gum_elf_module_resolver_new ();
  gum_elf_module_resolver_add_module (resolver, elf, range->base_address);

  g_assert_true (gum_module_resolver_find_dynamic_symbol (
      GUM_MODULE_RESOLVER (resolver), "getpid", &details));
  g_assert_cmphex (details.address, ==,
      GUM_ADDRESS (dlsym (libc_handle, "getpid")));

  g_object_unref (resolver);
  g_object_unref (elf);
  g_bytes_unref (blob);
  dlclose (libc_handle);
}

#endif

TESTCASE (maps_into_another_process)
{
  GumTestRemote remote;
  GumAddress get_magic;

  if (!gum_test_remote_open (&remote))
    return;

  get_magic = gum_mapper_resolve (remote.mapper, "gum_test_mapper_get_magic");
  g_assert_cmphex (get_magic, !=, 0);
  g_assert_cmphex (gum_test_remote_call (&remote, get_magic), ==, 0x1337);

  gum_test_remote_close (&remote);
}

TESTCASE (maps_tls_into_another_process)
{
  GumTestRemote remote;
  GumAddress tls_get;

  if (!gum_test_remote_open (&remote))
    return;

  tls_get = gum_mapper_resolve (remote.mapper, "gum_test_mapper_tls_get");
  g_assert_cmphex (tls_get, !=, 0);
  g_assert_cmphex (gum_test_remote_call (&remote, tls_get), ==, 0x1234);

  gum_test_remote_close (&remote);
}

#ifdef HAVE_WINDOWS

TESTCASE (code_is_shared_section_view)
{
  GumTestTarget local;
  GumTestRemote remote;
  int (* sum) (int a, int b);
  MEMORY_BASIC_INFORMATION mbi;
  BOOL (WINAPI * query_working_set_ex) (HANDLE process, PVOID info, DWORD size);
  PSAPI_WORKING_SET_EX_INFORMATION page;

  gum_test_target_open (&local);
  if (!gum_test_remote_open (&remote))
    return;

  sum = GSIZE_TO_POINTER (
      gum_mapper_resolve (local.mapper, "gum_test_mapper_sum"));
  g_assert_cmpint (sum (3, 4), ==, 7);

  g_assert_cmpuint (VirtualQuery (sum, &mbi, sizeof (mbi)), ==, sizeof (mbi));
  g_assert_cmphex (mbi.Type, ==, MEM_MAPPED);

  query_working_set_ex = GSIZE_TO_POINTER (GetProcAddress (
      GetModuleHandleW (L"kernel32.dll"), "K32QueryWorkingSetEx"));
  page.VirtualAddress = sum;
  g_assert_true (query_working_set_ex (GetCurrentProcess (), &page,
      sizeof (page)));
  g_assert_true (page.VirtualAttributes.Valid);
  g_assert_true (page.VirtualAttributes.Shared);

  g_assert_cmpuint (VirtualQueryEx (remote.process, GSIZE_TO_POINTER (
      gum_mapper_resolve (remote.mapper, "gum_test_mapper_sum")),
      &mbi, sizeof (mbi)), ==, sizeof (mbi));
  g_assert_cmphex (mbi.Type, ==, MEM_MAPPED);

  gum_test_remote_close (&remote);
  gum_test_target_close (&local);
}

TESTCASE (windows_resolver_agrees_with_loader)
{
  GumWindowsModuleResolver * resolver;
  GumTestLoaderComparison comparison;
  GumPeModule * pe;

  resolver = gum_windows_module_resolver_new (GetCurrentProcess ());

  comparison.local = GetModuleHandleW (L"kernel32.dll");
  comparison.resolved = gum_module_resolver_find_module_by_name (
      GUM_MODULE_RESOLVER (resolver), "kernel32.dll");
  g_assert_nonnull (comparison.resolved);

  pe = gum_pe_module_new_from_memory (GUM_ADDRESS (comparison.local), NULL);
  gum_pe_module_enumerate_exports (pe, gum_test_compare_with_loader,
      &comparison);
  g_object_unref (pe);

  g_object_unref (comparison.resolved);
  g_object_unref (resolver);
}

TESTCASE (windows_resolver_supports_suspended_process)
{
  STARTUPINFOA si = { 0, };
  PROCESS_INFORMATION pi;
  GumWindowsModuleResolver * resolver;
  GumModule * kernel32;

  si.cb = sizeof (si);
  g_assert_true (CreateProcessA (GUM_TESTS_MAPPER_VICTIM, NULL, NULL, NULL,
      FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL, &si, &pi));
  CloseHandle (pi.hThread);

  resolver = gum_windows_module_resolver_new (pi.hProcess);

  kernel32 = gum_module_resolver_find_module_by_name (
      GUM_MODULE_RESOLVER (resolver), "kernel32.dll");
  g_assert_nonnull (kernel32);
  g_assert_cmphex (gum_module_get_range (kernel32)->base_address, ==,
      GUM_ADDRESS (GetModuleHandleW (L"kernel32.dll")));

  g_object_unref (kernel32);
  g_object_unref (resolver);

  TerminateProcess (pi.hProcess, 0);
  CloseHandle (pi.hProcess);
}

#endif

static void
gum_test_target_open (GumTestTarget * target)
{
  GBytes * blob;
  GError * error = NULL;

  blob = gum_test_target_read ();

  target->resolver = gum_test_resolver_new ();

  target->mapper = gum_mapper_new_take_blob (GUM_TEST_MAPPER_TARGET, blob,
      target->resolver, &error);
  g_assert_no_error (error);

  gum_mapper_map (target->mapper, 0, NULL, &error);
  g_assert_no_error (error);

  target->constructor =
      GSIZE_TO_POINTER (gum_mapper_constructor (target->mapper));
  target->destructor =
      GSIZE_TO_POINTER (gum_mapper_destructor (target->mapper));

  target->constructor ();
}

static void
gum_test_target_close (GumTestTarget * target)
{
  target->destructor ();

  gum_mapper_unmap (target->mapper);
  g_object_unref (target->mapper);
  g_object_unref (target->resolver);
}

static gboolean
gum_test_store_export (const GumExportDetails * details,
                       gpointer user_data)
{
  GumTestExportSearch * search = user_data;

  if (strcmp (details->name, search->name) != 0)
    return TRUE;

  search->address = details->address;

  return FALSE;
}

static gpointer
gum_test_tls_thread (gpointer data)
{
  GumTestTlsThreadContext * ctx = data;

  ctx->observed_initial = ctx->get ();
  ctx->set (0xbbbb);

  return NULL;
}

static gpointer
gum_test_multi_tls_thread (gpointer data)
{
  GumTestMultiTlsContext * ctx = data;

  ctx->observed_a = ctx->get_a ();
  ctx->observed_b = ctx->get_b ();

  return NULL;
}

static gboolean
gum_test_remote_open (GumTestRemote * remote)
{
  GBytes * blob;
  GError * error = NULL;

  gum_test_remote_spawn_victim (remote);
  if (!gum_test_remote_is_accessible (remote))
    goto inaccessible;

  blob = gum_test_target_read ();

#ifdef HAVE_WINDOWS
  remote->resolver =
      GUM_MODULE_RESOLVER (gum_windows_module_resolver_new (remote->process));
#else
  remote->resolver = gum_test_resolver_new ();
#endif

  remote->mapper = gum_mapper_new_take_blob (GUM_TEST_MAPPER_TARGET, blob,
      remote->resolver, &error);
  g_assert_no_error (error);

  gum_mapper_set_target (remote->mapper, remote->memory);

  gum_mapper_map (remote->mapper, 0, NULL, &error);
  g_assert_no_error (error);

  gum_test_remote_call (remote, gum_mapper_constructor (remote->mapper));

  return TRUE;

inaccessible:
  {
    gum_test_remote_kill_victim (remote);
    g_object_unref (remote->memory);

    g_print ("<skipping, not supported on this system> ");
    return FALSE;
  }
}

static GBytes *
gum_test_target_read (void)
{
  gchar * data_dir, * path;
  gchar * contents;
  gsize length;

  data_dir = test_util_get_data_dir ();
  path = g_build_filename (data_dir, GUM_TEST_MAPPER_TARGET, NULL);
  g_assert_true (g_file_get_contents (path, &contents, &length, NULL));
  g_free (path);
  g_free (data_dir);

#ifdef HAVE_WINDOWS
  {
    HANDLE section;
    gpointer view;
    GBytes * blob;

    section = CreateFileMappingW (INVALID_HANDLE_VALUE, NULL,
        PAGE_EXECUTE_READWRITE, 0, (DWORD) length, NULL);
    g_assert_nonnull (section);

    view = MapViewOfFile (section, FILE_MAP_WRITE, 0, 0, length);
    memcpy (view, contents, length);
    UnmapViewOfFile (view);
    g_free (contents);

    blob = gum_windows_bytes_new_from_section (section, 0, length, NULL);
    CloseHandle (section);
    g_assert_nonnull (blob);

    return blob;
  }
#else
  return g_bytes_new_take (contents, length);
#endif
}

static GumModuleResolver *
gum_test_resolver_new (void)
{
#ifdef HAVE_DARWIN
  return GUM_MODULE_RESOLVER (
      gum_darwin_module_resolver_new (mach_task_self (), NULL));
#else
  return GUM_MODULE_RESOLVER (gum_native_module_resolver_new ());
#endif
}

static void
gum_test_remote_close (GumTestRemote * remote)
{
  gum_test_remote_kill_victim (remote);

  g_object_unref (remote->memory);
  g_object_unref (remote->mapper);
  g_object_unref (remote->resolver);
}

#ifdef HAVE_WINDOWS

static void
gum_test_remote_spawn_victim (GumTestRemote * remote)
{
  STARTUPINFOA si = { 0, };
  PROCESS_INFORMATION pi;
  gchar name[64];
  HANDLE ready;

  si.cb = sizeof (si);
  g_assert_true (CreateProcessA (GUM_TESTS_MAPPER_VICTIM, NULL, NULL, NULL,
      FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi));
  CloseHandle (pi.hThread);
  remote->process = pi.hProcess;

  g_snprintf (name, sizeof (name), "frida-mapper-victim-%lu",
      (gulong) pi.dwProcessId);
  ready = CreateEventA (NULL, TRUE, FALSE, name);
  WaitForSingleObject (ready, INFINITE);
  CloseHandle (ready);

  remote->memory = GUM_PROCESS_MEMORY (
      gum_native_process_memory_new_remote (pi.dwProcessId, pi.hProcess));
}

static gboolean
gum_test_remote_is_accessible (GumTestRemote * remote)
{
  return TRUE;
}

static int
gum_test_remote_call (GumTestRemote * remote,
                      GumAddress function)
{
  DWORD result = 0;
  HANDLE thread;

  thread = CreateRemoteThread (remote->process, NULL, 0,
      (LPTHREAD_START_ROUTINE) GSIZE_TO_POINTER (function), NULL, 0, NULL);
  g_assert_nonnull (thread);
  WaitForSingleObject (thread, INFINITE);
  GetExitCodeThread (thread, &result);
  CloseHandle (thread);

  return result;
}

static void
gum_test_remote_kill_victim (GumTestRemote * remote)
{
  TerminateProcess (remote->process, 0);
  CloseHandle (remote->process);
}

#else

static void
gum_test_remote_spawn_victim (GumTestRemote * remote)
{
  int to_victim[2], from_victim[2];
#ifdef HAVE_DARWIN
  mach_port_t self, bootstrap, channel;
#endif
  gpointer handle;
  GumProcessMemory * memory;

  g_assert_cmpint (pipe (to_victim), ==, 0);
  g_assert_cmpint (pipe (from_victim), ==, 0);

#ifdef GUM_TEST_HAVE_POOL_MEMORY
  remote->pool = gum_memory_allocate (NULL, GUM_TEST_POOL_SIZE,
      gum_query_page_size (), GUM_PAGE_RWX);
#endif

#ifdef HAVE_DARWIN
  self = mach_task_self ();
  task_get_special_port (self, TASK_BOOTSTRAP_PORT, &bootstrap);
  mach_port_allocate (self, MACH_PORT_RIGHT_RECEIVE, &channel);
  mach_port_insert_right (self, channel, channel, MACH_MSG_TYPE_MAKE_SEND);
  task_set_special_port (self, TASK_BOOTSTRAP_PORT, channel);
#endif

  remote->pid = fork ();
  g_assert_cmpint (remote->pid, >=, 0);

  if (remote->pid == 0)
  {
    GumAddress function;

#ifdef HAVE_DARWIN
    gum_test_send_task_port ();
#endif

    close (to_victim[1]);
    close (from_victim[0]);

    while (read (to_victim[0], &function, sizeof (function)) ==
        sizeof (function))
    {
      int (* f) (void) = GSIZE_TO_POINTER (function);
      int result = f ();

      if (write (from_victim[1], &result, sizeof (result)) != sizeof (result))
        _exit (1);
    }

    _exit (0);
  }

  close (to_victim[0]);
  close (from_victim[1]);

  remote->to_victim = to_victim[1];
  remote->from_victim = from_victim[0];

#ifdef HAVE_DARWIN
  task_set_special_port (self, TASK_BOOTSTRAP_PORT, bootstrap);
  remote->task = gum_test_receive_task_port (channel);
  mach_port_mod_refs (self, channel, MACH_PORT_RIGHT_RECEIVE, -1);
  mach_port_deallocate (self, channel);
  mach_port_deallocate (self, bootstrap);
  handle = GSIZE_TO_POINTER (remote->task);
#else
  handle = NULL;
#endif

  memory = GUM_PROCESS_MEMORY (
      gum_native_process_memory_new_remote (remote->pid, handle));
#ifdef GUM_TEST_HAVE_POOL_MEMORY
  remote->memory =
      gum_test_pool_memory_new (memory, remote->pool, GUM_TEST_POOL_SIZE);
  g_object_unref (memory);
#else
  remote->memory = memory;
#endif
}

static gboolean
gum_test_remote_is_accessible (GumTestRemote * remote)
{
  static const guint32 probe = 0x1337;
  guint32 value = 0;

  return gum_process_memory_read (remote->memory, GUM_ADDRESS (&probe), &value,
      sizeof (value)) && value == probe;
}

static int
gum_test_remote_call (GumTestRemote * remote,
                      GumAddress function)
{
  int result;

  g_assert_cmpint (write (remote->to_victim, &function, sizeof (function)),
      ==, sizeof (function));
  g_assert_cmpint (read (remote->from_victim, &result, sizeof (result)),
      ==, sizeof (result));

  return result;
}

static void
gum_test_remote_kill_victim (GumTestRemote * remote)
{
  close (remote->to_victim);
  close (remote->from_victim);
  kill (remote->pid, SIGKILL);
  waitpid (remote->pid, NULL, 0);

#ifdef HAVE_DARWIN
  mach_port_deallocate (mach_task_self (), remote->task);
#endif
#ifdef GUM_TEST_HAVE_POOL_MEMORY
  gum_memory_free (remote->pool, GUM_TEST_POOL_SIZE);
#endif
}

#ifdef HAVE_DARWIN

static void
gum_test_send_task_port (void)
{
  mach_port_t bootstrap;
  GumTestTaskPortMessage message = { { 0, }, };

  task_get_special_port (mach_task_self (), TASK_BOOTSTRAP_PORT, &bootstrap);

  message.header.msgh_bits =
      MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
  message.header.msgh_size = sizeof (message);
  message.header.msgh_remote_port = bootstrap;
  message.body.msgh_descriptor_count = 1;
  message.task.name = mach_task_self ();
  message.task.disposition = MACH_MSG_TYPE_COPY_SEND;
  message.task.type = MACH_MSG_PORT_DESCRIPTOR;

  if (mach_msg (&message.header, MACH_SEND_MSG, sizeof (message), 0,
      MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != KERN_SUCCESS)
  {
    _exit (1);
  }
}

static mach_port_t
gum_test_receive_task_port (mach_port_t channel)
{
  GumTestTaskPortReceipt receipt;

  g_assert_cmpint (mach_msg (&receipt.message.header, MACH_RCV_MSG, 0,
      sizeof (receipt), channel, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL), ==,
      KERN_SUCCESS);

  return receipt.message.task.name;
}

#endif

#endif

#if defined (HAVE_LINUX) && defined (__GLIBC__)

static gboolean
gum_test_copy_range (const GumRangeDetails * details,
                     gpointer user_data)
{
  GumTestSnapshot * snapshot = user_data;
  const GumMemoryRange * range = details->range;

  memcpy (snapshot->data + (range->base_address - snapshot->base),
      GSIZE_TO_POINTER (range->base_address), range->size);

  return TRUE;
}

#endif

#ifdef HAVE_WINDOWS

static gboolean
gum_test_compare_with_loader (const GumPeExportDetails * details,
                              gpointer user_data)
{
  GumTestLoaderComparison * comparison = user_data;

  if (details->name == NULL)
    return TRUE;

  g_assert_cmphex (gum_module_find_export_by_name (comparison->resolved,
      details->name), ==,
      GUM_ADDRESS (GetProcAddress (comparison->local, details->name)));

  return TRUE;
}

#endif

#ifdef GUM_TEST_HAVE_POOL_MEMORY

static void
gum_test_pool_memory_class_init (GumTestPoolMemoryClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_test_pool_memory_dispose;
}

static void
gum_test_pool_memory_iface_init (gpointer g_iface,
                                 gpointer iface_data)
{
  GumProcessMemoryInterface * iface = g_iface;

  iface->get_pid = gum_test_pool_memory_get_pid;
  iface->alloc = gum_test_pool_memory_alloc;
  iface->free = gum_test_pool_memory_free;
  iface->read = gum_test_pool_memory_read;
  iface->write = gum_test_pool_memory_write;
  iface->protect = gum_test_pool_memory_protect;
  iface->mark_code = gum_test_pool_memory_mark_code;
}

static void
gum_test_pool_memory_init (GumTestPoolMemory * self)
{
}

static void
gum_test_pool_memory_dispose (GObject * object)
{
  GumTestPoolMemory * self = GUM_TEST_POOL_MEMORY (object);

  g_clear_object (&self->inner);

  G_OBJECT_CLASS (gum_test_pool_memory_parent_class)->dispose (object);
}

static GumProcessMemory *
gum_test_pool_memory_new (GumProcessMemory * inner,
                          gpointer pool,
                          gsize size)
{
  GumTestPoolMemory * self;

  self = g_object_new (GUM_TEST_TYPE_POOL_MEMORY, NULL);
  self->inner = g_object_ref (inner);
  self->cursor = GUM_ADDRESS (pool);
  self->end = self->cursor + size;

  return GUM_PROCESS_MEMORY (self);
}

static GumProcessId
gum_test_pool_memory_get_pid (GumProcessMemory * memory)
{
  GumTestPoolMemory * self = GUM_TEST_POOL_MEMORY (memory);

  return gum_process_memory_get_pid (self->inner);
}

static GumAddress
gum_test_pool_memory_alloc (GumProcessMemory * memory,
                            gsize size,
                            gsize alignment)
{
  GumTestPoolMemory * self = GUM_TEST_POOL_MEMORY (memory);
  GumAddress address;

  address = GUM_ALIGN_SIZE (self->cursor, alignment);
  self->cursor = address + GUM_ALIGN_SIZE (size, gum_query_page_size ());
  g_assert_cmphex (self->cursor, <=, self->end);

  return address;
}

static void
gum_test_pool_memory_free (GumProcessMemory * memory,
                           GumAddress address,
                           gsize size)
{
}

static gboolean
gum_test_pool_memory_read (GumProcessMemory * memory,
                           GumAddress address,
                           gpointer buffer,
                           gsize size)
{
  GumTestPoolMemory * self = GUM_TEST_POOL_MEMORY (memory);

  return gum_process_memory_read (self->inner, address, buffer, size);
}

static gboolean
gum_test_pool_memory_write (GumProcessMemory * memory,
                            GumAddress address,
                            gconstpointer data,
                            gsize size)
{
  GumTestPoolMemory * self = GUM_TEST_POOL_MEMORY (memory);

  return gum_process_memory_write (self->inner, address, data, size);
}

static gboolean
gum_test_pool_memory_protect (GumProcessMemory * memory,
                              GumAddress address,
                              gsize size,
                              GumPageProtection prot)
{
  return TRUE;
}

static gboolean
gum_test_pool_memory_mark_code (GumProcessMemory * memory,
                                GumAddress address,
                                gsize size)
{
  return TRUE;
}

#endif

#ifdef HAVE_LINUX

static void
gum_test_indirect_resolver_class_init (GumTestIndirectResolverClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_test_indirect_resolver_dispose;
}

static void
gum_test_indirect_resolver_iface_init (gpointer g_iface,
                                       gpointer iface_data)
{
  GumModuleResolverInterface * iface = g_iface;

  iface->find_module_by_name = gum_test_indirect_resolver_find_module_by_name;
  iface->find_dynamic_address =
      gum_test_indirect_resolver_find_dynamic_address;
  iface->find_dynamic_symbol = gum_test_indirect_resolver_find_dynamic_symbol;
}

static void
gum_test_indirect_resolver_init (GumTestIndirectResolver * self)
{
  self->inner = gum_test_resolver_new ();
}

static void
gum_test_indirect_resolver_dispose (GObject * object)
{
  GumTestIndirectResolver * self = GUM_TEST_INDIRECT_RESOLVER (object);

  g_clear_object (&self->inner);

  G_OBJECT_CLASS (gum_test_indirect_resolver_parent_class)->dispose (object);
}

static GumModule *
gum_test_indirect_resolver_find_module_by_name (GumModuleResolver * resolver,
                                                const gchar * name)
{
  GumTestIndirectResolver * self = GUM_TEST_INDIRECT_RESOLVER (resolver);

  return gum_module_resolver_find_module_by_name (self->inner, name);
}

static GumAddress
gum_test_indirect_resolver_find_dynamic_address (GumModuleResolver * resolver,
                                                 const gchar * symbol)
{
  GumTestIndirectResolver * self = GUM_TEST_INDIRECT_RESOLVER (resolver);

  return gum_module_resolver_find_dynamic_address (self->inner, symbol);
}

static gboolean
gum_test_indirect_resolver_find_dynamic_symbol (
    GumModuleResolver * resolver,
    const gchar * symbol,
    GumDynamicSymbolDetails * details)
{
  GumTestIndirectResolver * self = GUM_TEST_INDIRECT_RESOLVER (resolver);

  if (strcmp (symbol, "getpid") == 0)
  {
    details->address = GUM_ADDRESS (gum_test_resolve_getpid);
    details->indirect = TRUE;
    return TRUE;
  }

  if (strcmp (symbol, "memcpy") == 0)
  {
    details->address = GUM_ADDRESS (gum_test_resolve_memcpy);
    details->indirect = TRUE;
    return TRUE;
  }

  return gum_module_resolver_find_dynamic_symbol (self->inner, symbol,
      details);
}

static gpointer
gum_test_resolve_getpid (guint64 hwcap,
                         const guint64 * arg)
{
  gum_test_check_ifunc_arguments (hwcap, arg);
  gum_test_ifunc_resolver_calls++;

  return gum_test_indirect_getpid;
}

static gpointer
gum_test_resolve_memcpy (guint64 hwcap,
                         const guint64 * arg)
{
  gum_test_check_ifunc_arguments (hwcap, arg);
  gum_test_ifunc_resolver_calls++;

  return memcpy;
}

static void
gum_test_check_ifunc_arguments (guint64 hwcap,
                                const guint64 * arg)
{
#ifdef HAVE_ARM64
  g_assert_true ((hwcap & GUM_TEST_IFUNC_ARG_HWCAP) != 0);
  g_assert_cmpuint (arg[0], ==, 24);
  g_assert_cmphex (arg[1], ==, getauxval (AT_HWCAP));
  g_assert_cmphex (arg[2], ==, getauxval (AT_HWCAP2));
#endif
}

static unsigned int
gum_test_indirect_getpid (void)
{
  return 0x4242;
}

#endif
