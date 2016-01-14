/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptbackend.h"

#include "gumdukscriptbackend.h"
#include "gumv8scriptbackend.h"

#include <gum/gum-init.h>
#include <gum/gumexceptor.h>

static GumExceptor * cached_exceptor;

static void
gum_script_backend_release_cached_exceptor (void)
{
  g_object_unref (cached_exceptor);
  cached_exceptor = NULL;
}

static void
gum_script_backend_deinit_v8 (void)
{
  g_object_unref (gum_script_backend_obtain_v8 ());
}

static void
gum_script_backend_deinit_duk (void)
{
  g_object_unref (gum_script_backend_obtain_duk ());
}

GType
gum_script_backend_get_type (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GType gtype;

    gtype = g_type_register_static_simple (G_TYPE_INTERFACE, "GumScriptBackend",
        sizeof (GumScriptBackendIface), NULL, 0, NULL, 0);
    g_type_interface_add_prerequisite (gtype, G_TYPE_OBJECT);

    /*
     * Hold onto Exceptor to avoid creating and destroying it over and over,
     * which isn't ideal with hooks being added and removed.
     */
    cached_exceptor = gum_exceptor_obtain ();
    _gum_register_destructor (gum_script_backend_release_cached_exceptor);

    g_once_init_leave (&gonce_value, gtype);
  }

  return (GType) gonce_value;
}

GumScriptBackend *
gum_script_backend_obtain (void)
{
  GumScriptBackend * backend = NULL;

#ifndef HAVE_DIET
  backend = gum_script_backend_obtain_v8 ();
#endif
  if (backend == NULL)
    backend = gum_script_backend_obtain_duk ();

  return backend;
}

GumScriptBackend *
gum_script_backend_obtain_v8 (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GumScriptBackend * backend = NULL;

    if (gum_query_is_rwx_supported ())
    {
#ifndef HAVE_DIET
      backend = GUM_SCRIPT_BACKEND (
          g_object_new (GUM_V8_TYPE_SCRIPT_BACKEND, NULL));
#endif

      if (backend != NULL)
        _gum_register_destructor (gum_script_backend_deinit_v8);
    }

    g_once_init_leave (&gonce_value, GPOINTER_TO_SIZE (backend) + 1);
  }

  return GUM_SCRIPT_BACKEND (GSIZE_TO_POINTER (gonce_value - 1));
}

GumScriptBackend *
gum_script_backend_obtain_duk (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GumScriptBackend * backend;

    backend = GUM_SCRIPT_BACKEND (
        g_object_new (GUM_DUK_TYPE_SCRIPT_BACKEND, NULL));

    _gum_register_destructor (gum_script_backend_deinit_duk);

    g_once_init_leave (&gonce_value, GPOINTER_TO_SIZE (backend) + 1);
  }

  return GUM_SCRIPT_BACKEND (GSIZE_TO_POINTER (gonce_value - 1));
}

void
gum_script_backend_create (GumScriptBackend * self,
                           const gchar * name,
                           const gchar * source,
                           GCancellable * cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create (self, name, source,
      cancellable, callback, user_data);
}

GumScript *
gum_script_backend_create_finish (GumScriptBackend * self,
                                  GAsyncResult * result,
                                  GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create_finish (self, result,
      error);
}

GumScript *
gum_script_backend_create_sync (GumScriptBackend * self,
                                const gchar * name,
                                const gchar * source,
                                GCancellable * cancellable,
                                GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create_sync (self, name,
      source, cancellable, error);
}

void
gum_script_backend_set_debug_message_handler (
    GumScriptBackend * self,
    GumScriptDebugMessageHandler handler,
    gpointer data,
    GDestroyNotify data_destroy)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->set_debug_message_handler (self,
      handler, data, data_destroy);
}

void
gum_script_backend_post_debug_message (GumScriptBackend * self,
                                       const gchar * message)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->post_debug_message (self, message);
}

void
gum_script_backend_ignore (GumScriptBackend * self,
                           GumThreadId thread_id)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->ignore (self, thread_id);
}

void
gum_script_backend_unignore (GumScriptBackend * self,
                             GumThreadId thread_id)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->unignore (self, thread_id);
}

void
gum_script_backend_unignore_later (GumScriptBackend * self,
                                   GumThreadId thread_id)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->unignore_later (self, thread_id);
}

gboolean
gum_script_backend_is_ignoring (GumScriptBackend * self,
                                GumThreadId thread_id)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->is_ignoring (self, thread_id);
}
