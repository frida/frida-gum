/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumthreadregistry-priv.h"

#include "guminterceptor.h"
#include "gumsystemtap.h"
#include "gum/gumlinux.h"

static void gum_add_existing_threads (GumThreadRegistry * registry);
static gboolean gum_find_thread_start (const GumSystemTapProbeDetails * probe,
    gpointer user_data);
static void gum_thread_registry_on_pthread_start (GumInvocationContext * ic,
    gpointer user_data);
static void gum_thread_registry_on_pthread_setname (GumInvocationContext * ic,
    gpointer user_data);
static void gum_thread_registry_on_pthread_terminate (GumInvocationContext * ic,
    gpointer user_data);

static GumThreadRegistry * gum_registry;

static GumInterceptor * gum_thread_interceptor;
static GumInvocationListener * gum_start_handler = NULL;
static GumInvocationListener * gum_rename_handler = NULL;
static GumInvocationListener * gum_terminate_handler = NULL;

static int (* gum_pthread_getname_np) (pthread_t thread, char * name,
    size_t size);

void
_gum_thread_registry_activate (GumThreadRegistry * self)
{
  GumModule * libc;
  gpointer setname_impl, start_impl, terminate_impl;

  gum_registry = self;

  gum_thread_interceptor = gum_interceptor_obtain ();

  libc = gum_process_get_libc_module ();

  gum_pthread_getname_np = GSIZE_TO_POINTER (gum_module_find_export_by_name (
        libc, "pthread_getname_np"));
  setname_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (
        libc, "pthread_setname_np"));

  start_impl = NULL;
  gum_system_tap_enumerate_probes (libc, gum_find_thread_start, &start_impl);
  if (start_impl != NULL)
  {
    gum_start_handler = gum_make_probe_listener (
        gum_thread_registry_on_pthread_start, gum_registry, NULL);
    gum_interceptor_attach (gum_thread_interceptor, start_impl,
        gum_start_handler, NULL);
  }
  else
  {
    /* TODO */
    g_abort ();
  }

#if defined (HAVE_GLIBC)
  terminate_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (libc,
        "__call_tls_dtors"));
#elif defined (HAVE_ANDROID)
  terminate_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (libc,
        "pthread_exit"));
#else
# error TODO
#endif
  gum_terminate_handler = gum_make_probe_listener (
      gum_thread_registry_on_pthread_terminate, gum_registry, NULL);
  gum_interceptor_attach (gum_thread_interceptor, terminate_impl,
      gum_terminate_handler, NULL);

  if (setname_impl != NULL)
  {
    gum_rename_handler = gum_make_probe_listener (
        gum_thread_registry_on_pthread_setname, gum_registry, NULL);
    gum_interceptor_attach (gum_thread_interceptor, setname_impl,
        gum_rename_handler, NULL);
  }

  gum_add_existing_threads (gum_registry);
}

void
_gum_thread_registry_deactivate (GumThreadRegistry * self)
{
  GumInvocationListener ** handlers[] = {
    &gum_start_handler,
    &gum_rename_handler,
    &gum_terminate_handler,
  };
  guint i;

  for (i = 0; i != G_N_ELEMENTS (handlers); i++)
  {
    GumInvocationListener ** handler = handlers[i];

    if (*handler != NULL)
    {
      gum_interceptor_detach (gum_thread_interceptor, *handler);

      g_object_unref (*handler);
      *handler = NULL;
    }
  }

  g_clear_object (&gum_thread_interceptor);
}

static void
gum_add_existing_threads (GumThreadRegistry * registry)
{
  GDir * dir;
  const gchar * name;
  gboolean carry_on = TRUE;

  dir = g_dir_open ("/proc/self/task", 0, NULL);
  g_assert (dir != NULL);

  while (carry_on && (name = g_dir_read_name (dir)) != NULL)
  {
    GumThreadDetails t;

    t.id = atoi (name);
    t.name = gum_linux_query_thread_name (t.id);
    t.state = GUM_THREAD_RUNNING;
    bzero (&t.cpu_context, sizeof (GumCpuContext));

    _gum_thread_registry_register (registry, &t);

    g_free ((gpointer) t.name);
  }

  g_dir_close (dir);
}

static gboolean
gum_find_thread_start (const GumSystemTapProbeDetails * probe,
                       gpointer user_data)
{
  gpointer * start_impl = user_data;

  if (strcmp (probe->name, "pthread_start") == 0)
  {
    *start_impl = GSIZE_TO_POINTER (probe->address);
    return FALSE;
  }

  return TRUE;
}

static void
gum_thread_registry_on_pthread_start (GumInvocationContext * ic,
                                      gpointer user_data)
{
  GumThreadRegistry * registry = user_data;
  GumThreadDetails t;
  gchar name[64];
  gchar * name_malloc_data = NULL;

  t.id = gum_process_get_current_thread_id ();

  t.name = NULL;
  if (gum_pthread_getname_np != NULL)
  {
    gum_pthread_getname_np (pthread_self (), name, sizeof (name));
    if (name[0] != '\0')
      t.name = name;
  }
  else
  {
    name_malloc_data = gum_linux_query_thread_name (t.id);
    t.name = name_malloc_data;
  }

  t.state = GUM_THREAD_RUNNING;

  bzero (&t.cpu_context, sizeof (GumCpuContext));

  _gum_thread_registry_register (registry, &t);

  g_free (name_malloc_data);
}

static void
gum_thread_registry_on_pthread_setname (GumInvocationContext * ic,
                                        gpointer user_data)
{
  GumThreadRegistry * registry = user_data;
  pthread_t thread;
  const char * name;
  GumThreadId id;

  thread = GPOINTER_TO_SIZE (gum_invocation_context_get_nth_argument (ic, 0));
  name = gum_invocation_context_get_nth_argument (ic, 1);

  /* TODO: Support setting name from a different thread. */
  if (thread != pthread_self ())
    return;

  id = gum_process_get_current_thread_id ();

  _gum_thread_registry_rename (registry, id, name);
}

static void
gum_thread_registry_on_pthread_terminate (GumInvocationContext * ic,
                                          gpointer user_data)
{
  GumThreadRegistry * registry = user_data;

  _gum_thread_registry_unregister (registry,
      gum_process_get_current_thread_id ());
}
