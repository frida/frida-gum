/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_H__
#define __GUM_SCRIPT_H__

#include <gio/gio.h>
#include <gum/gum.h>
#include <json-glib/json-glib.h>

#define GUM_TYPE_SCRIPT (gum_script_get_type ())
#define GUM_SCRIPT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), GUM_TYPE_SCRIPT,\
    GumScript))
#define GUM_SCRIPT_CAST(obj) ((GumScript *) (obj))
#define GUM_IS_SCRIPT(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), GUM_TYPE_SCRIPT))
#define GUM_SCRIPT_GET_INTERFACE(inst) (G_TYPE_INSTANCE_GET_INTERFACE ((inst),\
    GUM_TYPE_SCRIPT, GumScriptIface))

typedef struct _GumScript GumScript;
typedef struct _GumScriptIface GumScriptIface;

typedef void (* GumScriptMessageHandler) (GumScript * script,
    const gchar * message, GBytes * data, gpointer user_data);

struct _GumScriptIface
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

G_BEGIN_DECLS

GUM_API GType gum_script_get_type (void);

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
