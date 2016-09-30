/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscript.h"

GType
gum_script_get_type (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GType gtype;

    gtype = g_type_register_static_simple (G_TYPE_INTERFACE, "GumScript",
        sizeof (GumScriptIface), NULL, 0, NULL, 0);
    g_type_interface_add_prerequisite (gtype, G_TYPE_OBJECT);

    g_once_init_leave (&gonce_value, gtype);
  }

  return (GType) gonce_value;
}

void
gum_script_load (GumScript * self,
                 GCancellable * cancellable,
                 GAsyncReadyCallback callback,
                 gpointer user_data)
{
  GUM_SCRIPT_GET_INTERFACE (self)->load (self, cancellable, callback,
      user_data);
}

void
gum_script_load_finish (GumScript * self,
                        GAsyncResult * result)
{
  GUM_SCRIPT_GET_INTERFACE (self)->load_finish (self, result);
}

void
gum_script_load_sync (GumScript * self,
                      GCancellable * cancellable)
{
  GUM_SCRIPT_GET_INTERFACE (self)->load_sync (self, cancellable);
}

void
gum_script_unload (GumScript * self,
                   GCancellable * cancellable,
                   GAsyncReadyCallback callback,
                   gpointer user_data)
{
  GUM_SCRIPT_GET_INTERFACE (self)->unload (self, cancellable, callback,
      user_data);
}

void
gum_script_unload_finish (GumScript * self,
                          GAsyncResult * result)
{
  GUM_SCRIPT_GET_INTERFACE (self)->unload_finish (self, result);
}

void
gum_script_unload_sync (GumScript * self,
                        GCancellable * cancellable)
{
  GUM_SCRIPT_GET_INTERFACE (self)->unload_sync (self, cancellable);
}

void
gum_script_set_message_handler (GumScript * self,
                                GumScriptMessageHandler handler,
                                gpointer data,
                                GDestroyNotify data_destroy)
{
  GUM_SCRIPT_GET_INTERFACE (self)->set_message_handler (self, handler, data,
      data_destroy);
}

void
gum_script_post (GumScript * self,
                 const gchar * message,
                 GBytes * data)
{
  GUM_SCRIPT_GET_INTERFACE (self)->post (self, message, data);
}

GumStalker *
gum_script_get_stalker (GumScript * self)
{
  return GUM_SCRIPT_GET_INTERFACE (self)->get_stalker (self);
}
