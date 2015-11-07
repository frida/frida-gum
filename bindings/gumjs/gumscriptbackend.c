/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptbackend.h"

#ifdef HAVE_IOS
# include "gumjscscriptbackend.h"
#endif
#include "gumv8scriptbackend.h"

#include <gum/gum-init.h>

static void
gum_script_backend_deinit (void)
{
  g_object_unref (gum_script_backend_obtain ());
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

    g_once_init_leave (&gonce_value, gtype);
  }

  return (GType) gonce_value;
}

GumScriptBackend *
gum_script_backend_obtain (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GumScriptBackend * backend;

    if (gum_query_is_rwx_supported ())
    {
      backend = GUM_SCRIPT_BACKEND (
          g_object_new (GUM_V8_TYPE_SCRIPT_BACKEND, NULL));
    }
    else
    {
#ifdef HAVE_IOS
      backend = GUM_SCRIPT_BACKEND (
          g_object_new (GUM_JSC_TYPE_SCRIPT_BACKEND, NULL));
#else
      backend = NULL;
#endif
    }

    if (backend != NULL)
      _gum_register_destructor (gum_script_backend_deinit);

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

gboolean
gum_script_backend_supports_unload (GumScriptBackend * self)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->supports_unload (self);
}
