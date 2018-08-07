/*
 * Copyright (C) 2010-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_H__
#define __GUM_SCRIPT_H__

#include <gio/gio.h>
#include <gum/gum.h>
#include <json-glib/json-glib.h>

G_BEGIN_DECLS

#define GUM_TYPE_SCRIPT (gum_script_get_type ())
G_DECLARE_INTERFACE (GumScript, gum_script, GUM, SCRIPT, GObject)

typedef void (* GumScriptMessageHandler) (GumScript * script,
    const gchar * message, GBytes * data, gpointer user_data);

struct _GumScriptInterface
{
  GTypeInterface parent;

  void (* load) (GumScript * self, GCancellable * cancellable,
      GAsyncReadyCallback callback, gpointer user_data);
  void (* load_finish) (GumScript * self, GAsyncResult * result);
  void (* load_sync) (GumScript * self, GCancellable * cancellable);
  void (* unload) (GumScript * self, GCancellable * cancellable,
      GAsyncReadyCallback callback, gpointer user_data);
  void (* unload_finish) (GumScript * self, GAsyncResult * result);
  void (* unload_sync) (GumScript * self, GCancellable * cancellable);

  void (* set_message_handler) (GumScript * self,
      GumScriptMessageHandler handler, gpointer data,
      GDestroyNotify data_destroy);
  void (* post) (GumScript * self, const gchar * message, GBytes * data);

  GumStalker * (* get_stalker) (GumScript * self);
};

GUM_API void gum_script_load (GumScript * self, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
GUM_API void gum_script_load_finish (GumScript * self, GAsyncResult * result);
GUM_API void gum_script_load_sync (GumScript * self,
    GCancellable * cancellable);
GUM_API void gum_script_unload (GumScript * self, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
GUM_API void gum_script_unload_finish (GumScript * self, GAsyncResult * result);
GUM_API void gum_script_unload_sync (GumScript * self,
    GCancellable * cancellable);

GUM_API void gum_script_set_message_handler (GumScript * self,
    GumScriptMessageHandler handler, gpointer data,
    GDestroyNotify data_destroy);
GUM_API void gum_script_post (GumScript * self, const gchar * message,
    GBytes * data);

GUM_API GumStalker * gum_script_get_stalker (GumScript * self);

G_END_DECLS

#endif
