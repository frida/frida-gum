/*
 * Copyright (C) 2026 Håvard Sørbø <havard@hsorbo.no>
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gummapper.h"

#include "testutil.h"
#include "gum/gumdarwin.h"
#include "gum/guminterceptor.h"

#include <limits.h>
#include <mach/mach.h>
#include <malloc/malloc.h>

#define TESTCASE(NAME) \
    void test_macho_mapper_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/MachoMapper", test_macho_mapper, NAME)

TESTLIST_BEGIN (macho_mapper)
  TESTENTRY (tlv_storage_is_per_thread)
  TESTENTRY (tlv_storage_is_freed_on_thread_exit)
  TESTENTRY (tlv_storage_is_freed_by_destructor)
  TESTENTRY (tlv_key_is_released_by_destructor)
TESTLIST_END ()

typedef struct _GumTestTlvTarget GumTestTlvTarget;
typedef struct _GumTestTlvThreadResult GumTestTlvThreadResult;
typedef struct _GumTestFreeProbe GumTestFreeProbe;

struct _GumTestTlvTarget
{
  GumDarwinModuleResolver * resolver;
  GumMapper * mapper;

  void (* constructor) (void);
  void (* destructor) (void);
  guint (* bump) (void);
  gpointer (* counter_address) (void);
};

struct _GumTestTlvThreadResult
{
  GumTestTlvTarget * target;
  guint value;
  gpointer address;
};

struct _GumTestFreeProbe
{
  GumInterceptor * interceptor;
  GumInvocationListener * listener;
  gpointer * address;
  gint hit;
};

static void gum_test_tlv_target_open (GumTestTlvTarget * target);
static void gum_test_tlv_target_remap (GumTestTlvTarget * target);
static void gum_test_tlv_target_close (GumTestTlvTarget * target);
static void gum_test_tlv_target_map (GumTestTlvTarget * target);
static gpointer gum_test_tlv_target_resolve (GumTestTlvTarget * target,
    const gchar * symbol);
static void gum_test_tlv_target_unmap (GumTestTlvTarget * target);
static gpointer gum_test_tlv_thread_func (gpointer data);

static void gum_test_free_probe_start (GumTestFreeProbe * probe,
    gpointer * address);
static void gum_test_free_probe_stop (GumTestFreeProbe * probe);
static void gum_test_free_probe_on_hit (GumInvocationContext * context,
    gpointer user_data);

TESTCASE (tlv_storage_is_per_thread)
{
  GumTestTlvTarget target;
  GumTestTlvThreadResult result;
  GThread * thread;

  gum_test_tlv_target_open (&target);
  target.constructor ();

  g_assert_cmpuint (target.bump (), ==, 43);
  g_assert_cmpuint (target.bump (), ==, 44);

  result.target = &target;
  thread = g_thread_new ("tlv-thread", gum_test_tlv_thread_func, &result);
  g_thread_join (thread);

  g_assert_cmpuint (result.value, ==, 43);
  g_assert_true (result.address != target.counter_address ());

  g_assert_cmpuint (target.bump (), ==, 45);

  target.destructor ();
  gum_test_tlv_target_close (&target);
}

TESTCASE (tlv_storage_is_freed_on_thread_exit)
{
  GumTestTlvTarget target;
  GumTestTlvThreadResult result;
  GumTestFreeProbe probe;
  GThread * thread;

  gum_test_tlv_target_open (&target);
  target.constructor ();

  result.target = &target;
  result.address = NULL;
  gum_test_free_probe_start (&probe, &result.address);

  thread = g_thread_new ("tlv-thread", gum_test_tlv_thread_func, &result);
  g_thread_join (thread);

  gum_test_free_probe_stop (&probe);

  g_assert_cmpuint (result.value, ==, 43);
  g_assert_true (probe.hit);

  target.destructor ();
  gum_test_tlv_target_close (&target);
}

TESTCASE (tlv_storage_is_freed_by_destructor)
{
  GumTestTlvTarget target;
  gpointer address;
  GumTestFreeProbe probe;

  gum_test_tlv_target_open (&target);
  target.constructor ();

  g_assert_cmpuint (target.bump (), ==, 43);
  address = target.counter_address ();

  gum_test_free_probe_start (&probe, &address);
  target.destructor ();
  gum_test_free_probe_stop (&probe);

  g_assert_true (probe.hit);

  gum_test_tlv_target_close (&target);
}

TESTCASE (tlv_key_is_released_by_destructor)
{
  GumTestTlvTarget target;
  guint i;

  gum_test_tlv_target_open (&target);

  for (i = 0; i != PTHREAD_KEYS_MAX + 1; i++)
  {
    target.constructor ();
    g_assert_cmpuint (target.bump (), ==, 43);
    target.destructor ();
    gum_test_tlv_target_remap (&target);
  }

  gum_test_tlv_target_close (&target);
}

static void
gum_test_tlv_target_open (GumTestTlvTarget * target)
{
  GError * error = NULL;

  target->resolver = gum_darwin_module_resolver_new (mach_task_self (),
      &error);
  g_assert_no_error (error);

  gum_test_tlv_target_map (target);
}

static void
gum_test_tlv_target_remap (GumTestTlvTarget * target)
{
  gum_test_tlv_target_unmap (target);
  gum_test_tlv_target_map (target);
}

static void
gum_test_tlv_target_close (GumTestTlvTarget * target)
{
  gum_test_tlv_target_unmap (target);
  g_object_unref (target->resolver);
}

static void
gum_test_tlv_target_map (GumTestTlvTarget * target)
{
  GError * error = NULL;

  target->mapper = gum_mapper_new_from_file (GUM_TESTS_MAPPER_TLV_TARGET,
      GUM_MODULE_RESOLVER (target->resolver), &error);
  g_assert_no_error (error);

  gum_mapper_map (target->mapper, 0, NULL, &error);
  g_assert_no_error (error);

  target->constructor =
      GSIZE_TO_POINTER (gum_mapper_constructor (target->mapper));
  target->destructor =
      GSIZE_TO_POINTER (gum_mapper_destructor (target->mapper));
  target->bump = gum_test_tlv_target_resolve (target, "gum_test_tlv_bump");
  target->counter_address =
      gum_test_tlv_target_resolve (target, "gum_test_tlv_counter_address");
}

static gpointer
gum_test_tlv_target_resolve (GumTestTlvTarget * target,
                             const gchar * symbol)
{
  gpointer address;

  address = GSIZE_TO_POINTER (gum_mapper_resolve (target->mapper, symbol));
  g_assert_nonnull (address);

  return address;
}

static void
gum_test_tlv_target_unmap (GumTestTlvTarget * target)
{
  gum_mapper_unmap (target->mapper);
  g_object_unref (target->mapper);
}

static gpointer
gum_test_tlv_thread_func (gpointer data)
{
  GumTestTlvThreadResult * result = data;
  GumTestTlvTarget * target = result->target;

  result->value = target->bump ();
  g_atomic_pointer_set (&result->address, target->counter_address ());

  return NULL;
}

static void
gum_test_free_probe_start (GumTestFreeProbe * probe,
                           gpointer * address)
{
  gpointer free_impl;

  probe->interceptor = gum_interceptor_obtain ();
  probe->listener = gum_make_probe_listener (gum_test_free_probe_on_hit,
      probe, NULL);
  probe->address = address;
  probe->hit = FALSE;

  free_impl = GSIZE_TO_POINTER (gum_module_find_global_export_by_name ("free"));
  g_assert_nonnull (free_impl);

  g_assert_cmpint (gum_interceptor_attach (probe->interceptor, free_impl,
      probe->listener, NULL), ==, GUM_ATTACH_OK);
}

static void
gum_test_free_probe_stop (GumTestFreeProbe * probe)
{
  gum_interceptor_detach (probe->interceptor, probe->listener);
  g_object_unref (probe->listener);
  g_object_unref (probe->interceptor);
}

static void
gum_test_free_probe_on_hit (GumInvocationContext * context,
                            gpointer user_data)
{
  GumTestFreeProbe * probe = user_data;
  guint8 * block, * address;

  block = gum_invocation_context_get_nth_argument (context, 0);
  address = g_atomic_pointer_get (probe->address);

  if (address >= block && address < block + malloc_size (block))
    g_atomic_int_set (&probe->hit, TRUE);
}
