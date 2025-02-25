/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumthreadregistry-priv.h"

#include "guminterceptor.h"
#include "gum/gumwindows.h"

#include <tlhelp32.h>
#include <winternl.h>

typedef enum {
  GUM_THREAD_QUERY_SET_WIN32_START_ADDRESS = 9,
} GumThreadInfoClass;

typedef NTSTATUS (WINAPI * GumQueryInformationThreadFunc) (HANDLE thread,
    GumThreadInfoClass klass, PVOID thread_information,
    ULONG thread_information_length, PULONG return_length);

static gboolean gum_add_existing_thread (const GumThreadDetails * thread,
    gpointer user_data);
static void gum_thread_registry_on_thread_start (GumInvocationContext * ic,
    gpointer user_data);
static void gum_thread_registry_on_thread_terminate (GumInvocationContext * ic,
    gpointer user_data);

static void gum_enumerate_threads (GumFoundThreadFunc func, gpointer user_data);

static GumInterceptor * gum_thread_interceptor;
static GumInvocationListener * gum_start_handler;
static GumInvocationListener * gum_terminate_handler;

static GumQueryInformationThreadFunc gum_query_information_thread;

void
_gum_thread_registry_activate (GumThreadRegistry * self)
{
  GumModule * ntdll, * kernel32;
  gpointer thread_start_impl;

  gum_thread_interceptor = gum_interceptor_obtain ();

  ntdll = gum_process_find_module_by_name ("ntdll.dll");
  kernel32 = gum_process_find_module_by_name ("kernel32.dll");

  gum_query_information_thread = GSIZE_TO_POINTER (
      gum_module_find_export_by_name (ntdll, "NtQueryInformationThread"));

  gum_start_handler = gum_make_probe_listener (
      gum_thread_registry_on_thread_start, self, NULL);
  gum_terminate_handler = gum_make_probe_listener (
      gum_thread_registry_on_thread_terminate, self, NULL);

  gum_interceptor_begin_transaction (gum_thread_interceptor);
  gum_interceptor_attach (gum_thread_interceptor,
      GSIZE_TO_POINTER (gum_module_find_export_by_name (kernel32,
          "BaseThreadInitThunk")),
      gum_start_handler, NULL);
  gum_interceptor_attach (gum_thread_interceptor,
      GSIZE_TO_POINTER (gum_module_find_export_by_name (ntdll,
          "RtlExitUserThread")),
      gum_terminate_handler, NULL);
  gum_interceptor_end_transaction (gum_thread_interceptor);

  gum_enumerate_threads (gum_add_existing_thread, self);

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

static gboolean
gum_add_existing_thread (const GumThreadDetails * thread,
                         gpointer user_data)
{
  GumThreadRegistry * registry = user_data;

  _gum_thread_registry_register (registry, thread);

  return TRUE;
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

static void
gum_enumerate_threads (GumFoundThreadFunc func,
                       gpointer user_data)
{
  DWORD this_process_id;
  HANDLE snapshot;
  THREADENTRY32 entry;
  gboolean carry_on;

  this_process_id = GetCurrentProcessId ();

  snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, 0);
  if (snapshot == INVALID_HANDLE_VALUE)
    goto beach;

  entry.dwSize = sizeof (entry);
  if (!Thread32First (snapshot, &entry))
    goto beach;

  carry_on = TRUE;
  do
  {
    if (RTL_CONTAINS_FIELD (&entry, entry.dwSize, th32OwnerProcessID) &&
        entry.th32OwnerProcessID == this_process_id)
    {
      HANDLE handle;

      handle = OpenThread (THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
      if (handle != NULL)
      {
        GumThreadDetails thread = { 0, };
        gsize start_address;

        thread.id = entry.th32ThreadID;

        thread.name = gum_windows_query_thread_name (handle);
        if (thread.name != NULL)
          thread.flags |= GUM_THREAD_FLAGS_HAS_NAME;

        start_address = 0;
        if (gum_query_information_thread (handle,
            GUM_THREAD_QUERY_SET_WIN32_START_ADDRESS, &start_address,
            sizeof (start_address), NULL) == 0)
        {
          thread.entrypoint.routine = start_address;
          thread.flags |= GUM_THREAD_FLAGS_HAS_ENTRYPOINT;
        }

        carry_on = func (&thread, user_data);

        g_free ((gpointer) thread.name);
        CloseHandle (handle);
      }
    }

    entry.dwSize = sizeof (entry);
  }
  while (carry_on && Thread32Next (snapshot, &entry));

beach:
  if (snapshot != INVALID_HANDLE_VALUE)
    CloseHandle (snapshot);
}
