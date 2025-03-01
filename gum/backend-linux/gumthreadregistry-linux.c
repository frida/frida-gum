/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumthreadregistry-priv.h"

#include "guminterceptor.h"
#include "gumlinux-priv.h"
#include "gum/gumlinux.h"

static gboolean gum_add_existing_thread (const GumThreadDetails * thread,
    gpointer user_data);
static void gum_thread_registry_on_pthread_start (GumInvocationContext * ic,
    gpointer user_data);
static void gum_thread_registry_on_pthread_terminate (GumInvocationContext * ic,
    gpointer user_data);
static void gum_thread_registry_on_pthread_setname (GumInvocationContext * ic,
    gpointer user_data);

static GumThreadRegistry * gum_registry;
static const GumLinuxPThreadSpec * gum_pthread;

static GumInterceptor * gum_thread_interceptor;
static GumInvocationListener * gum_start_handler;
static GumInvocationListener * gum_terminate_handler;
static GumInvocationListener * gum_rename_handler = NULL;

void
_gum_thread_registry_activate (GumThreadRegistry * self)
{
  gum_registry = self;
  gum_pthread = gum_linux_query_pthread_spec ();

  gum_start_handler = gum_make_probe_listener (
      gum_thread_registry_on_pthread_start, gum_registry, NULL);
  gum_terminate_handler = gum_make_probe_listener (
      gum_thread_registry_on_pthread_terminate, gum_registry, NULL);
  if (gum_pthread->set_name != NULL)
  {
    gum_rename_handler = gum_make_probe_listener (
        gum_thread_registry_on_pthread_setname, gum_registry, NULL);
  }

  gum_thread_interceptor = gum_interceptor_obtain ();
  gum_interceptor_begin_transaction (gum_thread_interceptor);

  gum_linux_lock_pthread_list (gum_pthread);

  gum_interceptor_attach (gum_thread_interceptor, gum_pthread->start_impl,
      gum_start_handler, NULL);
  gum_interceptor_attach (gum_thread_interceptor, gum_pthread->terminate_impl,
      gum_terminate_handler, NULL);
  if (gum_pthread->set_name != NULL)
  {
    gum_interceptor_attach (gum_thread_interceptor, gum_pthread->set_name,
        gum_rename_handler, NULL);
  }

  gum_interceptor_end_transaction (gum_thread_interceptor);

  gum_linux_enumerate_threads_unlocked (gum_add_existing_thread, gum_registry,
      GUM_THREAD_FLAGS_NAME |
      GUM_THREAD_FLAGS_ENTRYPOINT_ROUTINE |
      GUM_THREAD_FLAGS_ENTRYPOINT_PARAMETER,
      gum_pthread);

  gum_linux_unlock_pthread_list (gum_pthread);
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

static gboolean
gum_add_existing_thread (const GumThreadDetails * thread,
                         gpointer user_data)
{
  GumThreadRegistry * registry = user_data;

  _gum_thread_registry_register (registry, thread);

  return TRUE;
}

static void
gum_thread_registry_on_pthread_start (GumInvocationContext * ic,
                                      gpointer user_data)
{
  GumThreadRegistry * registry = user_data;
  GumThreadDetails thread;
  gpointer storage;

  gum_linux_query_pthread_details (pthread_self (),
      GUM_THREAD_FLAGS_NAME |
      GUM_THREAD_FLAGS_ENTRYPOINT_ROUTINE |
      GUM_THREAD_FLAGS_ENTRYPOINT_PARAMETER,
      gum_pthread, &thread, &storage);

  _gum_thread_registry_register (registry, &thread);

  g_free (storage);
}

static void
gum_thread_registry_on_pthread_terminate (GumInvocationContext * ic,
                                          gpointer user_data)
{
  GumThreadRegistry * registry = user_data;

  _gum_thread_registry_unregister (registry,
      gum_process_get_current_thread_id ());
}

static void
gum_thread_registry_on_pthread_setname (GumInvocationContext * ic,
                                        gpointer user_data)
{
  GumThreadRegistry * registry = user_data;
  pthread_t pthread;
  const char * name;

  pthread = GPOINTER_TO_SIZE (gum_invocation_context_get_nth_argument (ic, 0));
  name = gum_invocation_context_get_nth_argument (ic, 1);

  _gum_thread_registry_rename (registry,
      gum_linux_query_pthread_tid (pthread, gum_pthread), name);
}
