/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumthreadregistry-priv.h"

#include "guminterceptor.h"

static void gum_thread_registry_on_thread_start (GumInvocationContext * ic,
    gpointer user_data);
static void gum_thread_registry_on_thread_terminate (GumInvocationContext * ic,
    gpointer user_data);

static GumInterceptor * gum_thread_interceptor;
static GumInvocationListener * gum_start_handler;
static GumInvocationListener * gum_terminate_handler;

void
_gum_thread_registry_activate (GumThreadRegistry * self)
{
  GumModule * ntdll, * kernel32;
  gpointer thread_start_impl;

  gum_thread_interceptor = gum_interceptor_obtain ();

  ntdll = gum_process_find_module_by_name ("ntdll.dll");
  kernel32 = gum_process_find_module_by_name ("kernel32.dll");

  gum_start_handler = gum_make_probe_listener (
      gum_thread_registry_on_thread_start, self, NULL);
  gum_terminate_handler = gum_make_probe_listener (
      gum_thread_registry_on_thread_terminate, self, NULL);

  gum_interceptor_attach (gum_thread_interceptor,
      GSIZE_TO_POINTER (gum_module_find_export_by_name (kernel32,
          "BaseThreadInitThunk")),
      gum_start_handler, NULL);
  gum_interceptor_attach (gum_thread_interceptor,
      GSIZE_TO_POINTER (gum_module_find_export_by_name (ntdll,
          "RtlExitUserThread")),
      gum_terminate_handler, NULL);

  g_object_unref (kernel32);
  g_object_unref (ntdll);
}

void
_gum_thread_registry_deactivate (GumThreadRegistry * self)
{
  GumInvocationListener ** handlers[] = {
    &gum_start_handler,
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
gum_thread_registry_on_thread_start (GumInvocationContext * ic,
                                     gpointer user_data)
{
  GumThreadRegistry * registry = user_data;
  GumThreadDetails thread = { 0, };

  thread.id = gum_process_get_current_thread_id ();

  thread.entrypoint.routine =
      GUM_ADDRESS (gum_invocation_context_get_nth_argument (ic, 1));
  thread.entrypoint.parameter =
      GUM_ADDRESS (gum_invocation_context_get_nth_argument (ic, 2));
  thread.flags |= GUM_THREAD_FLAGS_HAS_ENTRYPOINT;

  _gum_thread_registry_register (registry, &thread);
}

static void
gum_thread_registry_on_thread_terminate (GumInvocationContext * ic,
                                         gpointer user_data)
{
  GumThreadRegistry * registry = user_data;

  _gum_thread_registry_unregister (registry,
      gum_process_get_current_thread_id ());
}
