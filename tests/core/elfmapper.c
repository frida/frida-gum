/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gummapper.h"

#include "testutil.h"
#include "gum/gumnativemoduleresolver.h"
#include "gum/gumnativeprocessmemory.h"

#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

#define TESTCASE(NAME) \
    void test_elf_mapper_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/ElfMapper", test_elf_mapper, NAME)

TESTLIST_BEGIN (elf_mapper)
  TESTENTRY (exports_can_be_resolved_and_called)
  TESTENTRY (constructor_runs_init_array)
  TESTENTRY (imports_are_resolved)
  TESTENTRY (destructor_runs_fini_array)
  TESTENTRY (tls_storage_is_per_thread)
  TESTENTRY (tls_storage_for_multiple_modules)
  TESTENTRY (maps_into_another_process)
  TESTENTRY (maps_tls_into_another_process)
TESTLIST_END ()

typedef struct _GumTestElfTarget GumTestElfTarget;
typedef struct _GumTestElfRemote GumTestElfRemote;
typedef struct _GumElfTlsThreadContext GumElfTlsThreadContext;
typedef struct _GumElfMultiTlsContext GumElfMultiTlsContext;

struct _GumTestElfTarget
{
  GumNativeModuleResolver * resolver;
  GumMapper * mapper;
  gpointer base;
  gsize size;

  void (* constructor) (void);
  void (* destructor) (void);
};

struct _GumTestElfRemote
{
  GumNativeModuleResolver * resolver;
  GumMapper * mapper;
  GumProcessMemory * target;
  gpointer base;
  gsize size;

  pid_t pid;
  int to_victim;
  int from_victim;
};

struct _GumElfTlsThreadContext
{
  int (* get) (void);
  void (* set) (int value);
  int observed_initial;
};

struct _GumElfMultiTlsContext
{
  int (* get_a) (void);
  int (* get_b) (void);
  int observed_a;
  int observed_b;
};

static gboolean gum_test_elf_target_open (GumTestElfTarget * target);
static GBytes * gum_test_elf_target_read (void);
static void gum_test_elf_target_close (GumTestElfTarget * target);
static gpointer gum_test_elf_tls_thread (gpointer data);
static gpointer gum_test_elf_multi_tls_thread (gpointer data);
static gboolean gum_test_elf_remote_open (GumTestElfRemote * remote);
static void gum_test_elf_remote_spawn_victim (GumTestElfRemote * remote);
static void gum_test_elf_remote_close (GumTestElfRemote * remote);
static int gum_test_elf_remote_call (GumTestElfRemote * remote,
    GumAddress function);

TESTCASE (exports_can_be_resolved_and_called)
{
  GumTestElfTarget target;
  int (* sum) (int a, int b);

  if (!gum_test_elf_target_open (&target))
    return;

  sum = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_elf_sum"));
  g_assert_nonnull (sum);
  g_assert_cmpint (sum (3, 4), ==, 7);

  gum_test_elf_target_close (&target);
}

TESTCASE (constructor_runs_init_array)
{
  GumTestElfTarget target;
  int (* get_magic) (void);

  if (!gum_test_elf_target_open (&target))
    return;

  get_magic = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_elf_get_magic"));
  g_assert_nonnull (get_magic);
  g_assert_cmphex (get_magic (), ==, 0x1337);

  gum_test_elf_target_close (&target);
}

TESTCASE (imports_are_resolved)
{
  GumTestElfTarget target;
  unsigned int (* get_pid) (void);

  if (!gum_test_elf_target_open (&target))
    return;

  get_pid = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_elf_get_pid"));
  g_assert_nonnull (get_pid);
  g_assert_cmpuint (get_pid (), ==, getpid ());

  gum_test_elf_target_close (&target);
}

TESTCASE (destructor_runs_fini_array)
{
  GumTestElfTarget target;
  int (* get_magic) (void);

  if (!gum_test_elf_target_open (&target))
    return;

  get_magic = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_elf_get_magic"));
  g_assert_cmpint (get_magic (), ==, 0x1337);

  target.destructor ();
  g_assert_cmpint (get_magic (), ==, 0);

  gum_memory_free (target.base, target.size);
  g_object_unref (target.mapper);
  g_object_unref (target.resolver);
}

TESTCASE (tls_storage_is_per_thread)
{
  GumTestElfTarget target;
  GumElfTlsThreadContext ctx;
  GThread * thread;

  if (!gum_test_elf_target_open (&target))
    return;

  ctx.get = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_elf_tls_get"));
  ctx.set = GSIZE_TO_POINTER (
      gum_mapper_resolve (target.mapper, "gum_test_elf_tls_set"));
  g_assert_nonnull (ctx.get);
  g_assert_nonnull (ctx.set);

  g_assert_cmphex (ctx.get (), ==, 0x1234);
  ctx.set (0xaaaa);
  g_assert_cmphex (ctx.get (), ==, 0xaaaa);

  ctx.observed_initial = 0;
  thread = g_thread_new ("tls-probe", gum_test_elf_tls_thread, &ctx);
  g_thread_join (thread);

  g_assert_cmphex (ctx.observed_initial, ==, 0x1234);
  g_assert_cmphex (ctx.get (), ==, 0xaaaa);

  gum_test_elf_target_close (&target);
}

TESTCASE (tls_storage_for_multiple_modules)
{
  GumTestElfTarget a, b;
  GumElfMultiTlsContext multi;
  GThread * thread;
  GumElfTlsThreadContext solo;

  if (!gum_test_elf_target_open (&a))
    return;
  gum_test_elf_target_open (&b);

  multi.get_a = GSIZE_TO_POINTER (
      gum_mapper_resolve (a.mapper, "gum_test_elf_tls_get"));
  multi.get_b = GSIZE_TO_POINTER (
      gum_mapper_resolve (b.mapper, "gum_test_elf_tls_get"));
  g_assert_nonnull (multi.get_a);
  g_assert_nonnull (multi.get_b);

  g_assert_cmphex (multi.get_a (), ==, 0x1234);
  g_assert_cmphex (multi.get_b (), ==, 0x1234);

  multi.observed_a = 0;
  multi.observed_b = 0;
  thread = g_thread_new ("tls-multi", gum_test_elf_multi_tls_thread, &multi);
  g_thread_join (thread);
  g_assert_cmphex (multi.observed_a, ==, 0x1234);
  g_assert_cmphex (multi.observed_b, ==, 0x1234);

  gum_test_elf_target_close (&a);

  solo.get = multi.get_b;
  solo.set = GSIZE_TO_POINTER (
      gum_mapper_resolve (b.mapper, "gum_test_elf_tls_set"));
  solo.observed_initial = 0;
  thread = g_thread_new ("tls-solo", gum_test_elf_tls_thread, &solo);
  g_thread_join (thread);
  g_assert_cmphex (solo.observed_initial, ==, 0x1234);

  gum_test_elf_target_close (&b);
}

TESTCASE (maps_into_another_process)
{
  GumTestElfRemote remote;
  GumAddress get_magic;

  if (!gum_test_elf_remote_open (&remote))
    return;

  get_magic = gum_mapper_resolve (remote.mapper, "gum_test_elf_get_magic");
  g_assert_cmphex (get_magic, !=, 0);
  g_assert_cmphex (gum_test_elf_remote_call (&remote, get_magic), ==, 0x1337);

  gum_test_elf_remote_close (&remote);
}

TESTCASE (maps_tls_into_another_process)
{
  GumTestElfRemote remote;
  GumAddress tls_get;

  if (!gum_test_elf_remote_open (&remote))
    return;

  tls_get = gum_mapper_resolve (remote.mapper, "gum_test_elf_tls_get");
  g_assert_cmphex (tls_get, !=, 0);
  g_assert_cmphex (gum_test_elf_remote_call (&remote, tls_get), ==, 0x1234);

  gum_test_elf_remote_close (&remote);
}

static gboolean
gum_test_elf_target_open (GumTestElfTarget * target)
{
  GBytes * blob;
  GError * error = NULL;

  blob = gum_test_elf_target_read ();
  if (blob == NULL)
    return FALSE;

  target->resolver = gum_native_module_resolver_new ();

  target->mapper = gum_mapper_new_take_blob ("module.so", blob,
      GUM_MODULE_RESOLVER (target->resolver), &error);
  g_assert_no_error (error);
  g_assert_nonnull (target->mapper);

  target->size = gum_mapper_size (target->mapper);
  target->base = gum_memory_allocate (NULL, target->size,
      gum_query_page_size (), GUM_PAGE_RW);

  gum_mapper_map (target->mapper, GUM_ADDRESS (target->base), &error);
  g_assert_no_error (error);

  target->constructor =
      GSIZE_TO_POINTER (gum_mapper_constructor (target->mapper));
  target->destructor =
      GSIZE_TO_POINTER (gum_mapper_destructor (target->mapper));

  target->constructor ();

  return TRUE;
}

static GBytes *
gum_test_elf_target_read (void)
{
  gchar * data_dir, * path;
  gchar * contents;
  gsize length;
  gboolean found;

  data_dir = test_util_get_data_dir ();
  path = g_build_filename (data_dir, "elfmapper-target.so", NULL);
  found = g_file_get_contents (path, &contents, &length, NULL);
  g_free (path);
  g_free (data_dir);

  if (!found)
  {
    g_test_skip ("ELF mapper target library is not available");
    return NULL;
  }

  return g_bytes_new_take (contents, length);
}

static void
gum_test_elf_target_close (GumTestElfTarget * target)
{
  target->destructor ();

  gum_memory_free (target->base, target->size);
  g_object_unref (target->mapper);
  g_object_unref (target->resolver);
}

static gpointer
gum_test_elf_tls_thread (gpointer data)
{
  GumElfTlsThreadContext * ctx = data;

  ctx->observed_initial = ctx->get ();
  ctx->set (0xbbbb);

  return NULL;
}

static gpointer
gum_test_elf_multi_tls_thread (gpointer data)
{
  GumElfMultiTlsContext * ctx = data;

  ctx->observed_a = ctx->get_a ();
  ctx->observed_b = ctx->get_b ();

  return NULL;
}

static gboolean
gum_test_elf_remote_open (GumTestElfRemote * remote)
{
  GBytes * blob;
  GError * error = NULL;
  guint8 probe = 0;

  blob = gum_test_elf_target_read ();
  if (blob == NULL)
    return FALSE;

  remote->resolver = gum_native_module_resolver_new ();

  remote->mapper = gum_mapper_new_take_blob ("module.so", blob,
      GUM_MODULE_RESOLVER (remote->resolver), &error);
  g_assert_no_error (error);
  g_assert_nonnull (remote->mapper);

  remote->size = gum_mapper_size (remote->mapper);
  remote->base = gum_memory_allocate (NULL, remote->size,
      gum_query_page_size (), GUM_PAGE_RWX);

  gum_test_elf_remote_spawn_victim (remote);

  remote->target = GUM_PROCESS_MEMORY (
      gum_native_process_memory_new_remote (remote->pid, NULL));
  if (!gum_process_memory_write (remote->target, GUM_ADDRESS (remote->base),
      &probe, sizeof (probe)))
  {
    gum_test_elf_remote_close (remote);
    g_test_skip ("Unable to write to child process memory");
    return FALSE;
  }
  gum_mapper_set_target (remote->mapper, remote->target);

  gum_mapper_map (remote->mapper, GUM_ADDRESS (remote->base), &error);
  g_assert_no_error (error);

  gum_test_elf_remote_call (remote, gum_mapper_constructor (remote->mapper));

  return TRUE;
}

static void
gum_test_elf_remote_spawn_victim (GumTestElfRemote * remote)
{
  int to_victim[2], from_victim[2];

  g_assert_cmpint (pipe (to_victim), ==, 0);
  g_assert_cmpint (pipe (from_victim), ==, 0);

  remote->pid = fork ();
  g_assert_cmpint (remote->pid, >=, 0);

  if (remote->pid == 0)
  {
    GumAddress function;

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
}

static void
gum_test_elf_remote_close (GumTestElfRemote * remote)
{
  close (remote->to_victim);
  close (remote->from_victim);
  kill (remote->pid, SIGKILL);
  waitpid (remote->pid, NULL, 0);

  gum_memory_free (remote->base, remote->size);
  g_object_unref (remote->target);
  g_object_unref (remote->mapper);
  g_object_unref (remote->resolver);
}

static int
gum_test_elf_remote_call (GumTestElfRemote * remote,
                          GumAddress function)
{
  int result;

  g_assert_cmpint (write (remote->to_victim, &function, sizeof (function)),
      ==, sizeof (function));
  g_assert_cmpint (read (remote->from_victim, &result, sizeof (result)),
      ==, sizeof (result));

  return result;
}
