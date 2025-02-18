/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumthreadregistry-priv.h"

#include "guminterceptor.h"

#include <strings.h>
#include <pthread/introspection.h>

static gboolean gum_add_existing_thread (const GumThreadDetails * thread,
    gpointer user_data);
static void gum_thread_registry_on_thread_event (unsigned int event,
    pthread_t thread, void * addr, size_t size);
static void gum_thread_registry_on_setname (GumInvocationContext * ic,
    gpointer user_data);

static GumThreadRegistry * gum_registry;

static gboolean gum_hook_installed = FALSE;
static pthread_introspection_hook_t gum_previous_hook;

static GumInterceptor * gum_thread_interceptor;
static GumInvocationListener * gum_rename_handler;

void
_gum_thread_registry_activate (GumThreadRegistry * self)
{
  gum_registry = self;

  gum_previous_hook =
      pthread_introspection_hook_install (gum_thread_registry_on_thread_event);
  gum_hook_installed = TRUE;

  gum_thread_interceptor = gum_interceptor_obtain ();
  gum_rename_handler = gum_make_probe_listener (gum_thread_registry_on_setname,
      gum_registry, NULL);
  gum_interceptor_attach (gum_thread_interceptor,
      GSIZE_TO_POINTER (gum_module_find_export_by_name (
          gum_process_get_libc_module (), "pthread_setname_np")),
      gum_rename_handler, NULL);

  gum_process_enumerate_threads (gum_add_existing_thread, gum_registry);
}

void
_gum_thread_registry_deactivate (GumThreadRegistry * self)
{
  if (gum_rename_handler != NULL)
  {
    gum_interceptor_detach (gum_thread_interceptor, gum_rename_handler);

    g_object_unref (gum_rename_handler);
    gum_rename_handler = NULL;

    g_object_unref (gum_thread_interceptor);
    gum_thread_interceptor = NULL;
  }

  if (gum_hook_installed)
  {
    (void) pthread_introspection_hook_install (gum_previous_hook);
    gum_previous_hook = NULL;

    gum_hook_installed = FALSE;
  }
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
gum_thread_registry_on_thread_event (unsigned int event,
                                     pthread_t thread,
                                     void * addr,
                                     size_t size)
{
  switch (event)
  {
    case PTHREAD_INTROSPECTION_THREAD_START:
    {
      GumThreadDetails t;
      gchar name[64];

      t.id = pthread_mach_thread_np (thread);

      t.name = NULL;
      pthread_getname_np (thread, name, sizeof (name));
      if (name[0] != '\0')
        t.name = name;

      t.state = GUM_THREAD_RUNNING;

      bzero (&t.cpu_context, sizeof (GumCpuContext));

      _gum_thread_registry_register (gum_registry, &t);

      break;
    }
    case PTHREAD_INTROSPECTION_THREAD_TERMINATE:
    {
      _gum_thread_registry_unregister (gum_registry,
          pthread_mach_thread_np (thread));
      break;
    }
    default:
      break;
  }

  if (gum_previous_hook != NULL)
    gum_previous_hook (event, thread, addr, size);
}

static void
gum_thread_registry_on_setname (GumInvocationContext * ic,
                                gpointer user_data)
{
  GumThreadRegistry * registry = user_data;
  pthread_t thread;
  GumThreadId id;
  const gchar * name;

  thread = pthread_self ();
  id = pthread_mach_thread_np (thread);
  name = gum_invocation_context_get_nth_argument (ic, 0);

  _gum_thread_registry_rename (registry, id, name);
}
