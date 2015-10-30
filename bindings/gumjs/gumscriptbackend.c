/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptbackend.h"

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

    g_once_init_leave (&gonce_value, (GType) gtype);
  }

  return (GType) gonce_value;
}

void
gum_script_backend_create (GumScriptBackend * self,
                           const gchar * name,
                           const gchar * source,
                           GumScriptFlavor flavor,
                           GCancellable * cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create (self, name, source, flavor,
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
                                GumScriptFlavor flavor,
                                GCancellable * cancellable,
                                GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create_sync (self, name,
      source, flavor, cancellable, error);
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
