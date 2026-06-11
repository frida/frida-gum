/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscript.h"

G_DEFINE_INTERFACE (GumScript, gum_script, G_TYPE_OBJECT)

static void
gum_script_default_init (GumScriptInterface * iface)
{
}

void
gum_script_load (GumScript * self,
                 GCancellable * cancellable,
                 GAsyncReadyCallback callback,
                 gpointer user_data)
{
  GUM_SCRIPT_GET_IFACE (self)->load (self, cancellable, callback, user_data);
}

void
gum_script_load_finish (GumScript * self,
                        GAsyncResult * result)
{
  GUM_SCRIPT_GET_IFACE (self)->load_finish (self, result);
}

void
gum_script_load_sync (GumScript * self,
                      GCancellable * cancellable)
{
  GUM_SCRIPT_GET_IFACE (self)->load_sync (self, cancellable);
}

void
gum_script_unload (GumScript * self,
                   GCancellable * cancellable,
                   GAsyncReadyCallback callback,
                   gpointer user_data)
{
  GUM_SCRIPT_GET_IFACE (self)->unload (self, cancellable, callback, user_data);
}

void
gum_script_unload_finish (GumScript * self,
                          GAsyncResult * result)
{
  GUM_SCRIPT_GET_IFACE (self)->unload_finish (self, result);
}

void
gum_script_unload_sync (GumScript * self,
                        GCancellable * cancellable)
{
  GUM_SCRIPT_GET_IFACE (self)->unload_sync (self, cancellable);
}

void
gum_script_cancel (GumScript * self)
{
  GUM_SCRIPT_GET_IFACE (self)->cancel (self);
}

void
gum_script_set_message_handler (GumScript * self,
                                GumScriptMessageHandler handler,
                                gpointer data,
                                GDestroyNotify data_destroy)
{
  GUM_SCRIPT_GET_IFACE (self)->set_message_handler (self, handler, data,
      data_destroy);
}

void
gum_script_post (GumScript * self,
                 const gchar * message,
                 GBytes * data)
{
  GUM_SCRIPT_GET_IFACE (self)->post (self, message, data);
}

void
gum_script_set_debug_message_handler (GumScript * self,
                                      GumScriptDebugMessageHandler handler,
                                      gpointer data,
                                      GDestroyNotify data_destroy)
{
  GUM_SCRIPT_GET_IFACE (self)->set_debug_message_handler (self, handler, data,
      data_destroy);
}

void
gum_script_post_debug_message (GumScript * self,
                               const gchar * message)
{
  GUM_SCRIPT_GET_IFACE (self)->post_debug_message (self, message);
}

GumStalker *
gum_script_get_stalker (GumScript * self)
{
  return GUM_SCRIPT_GET_IFACE (self)->get_stalker (self);
}
