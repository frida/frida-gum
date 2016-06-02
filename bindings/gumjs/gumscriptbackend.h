/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_BACKEND_H__
#define __GUM_SCRIPT_BACKEND_H__

#include <gumjs/gumscript.h>

#define GUM_TYPE_SCRIPT_BACKEND (gum_script_backend_get_type ())
#define GUM_SCRIPT_BACKEND(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_SCRIPT_BACKEND, GumScriptBackend))
#define GUM_SCRIPT_BACKEND_CAST(obj) ((GumScriptBackend *) (obj))
#define GUM_IS_SCRIPT_BACKEND(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_SCRIPT_BACKEND))
#define GUM_SCRIPT_BACKEND_GET_INTERFACE(inst) (G_TYPE_INSTANCE_GET_INTERFACE (\
    (inst), GUM_TYPE_SCRIPT_BACKEND, GumScriptBackendIface))

typedef struct _GumScriptBackend GumScriptBackend;
typedef struct _GumScriptBackendIface GumScriptBackendIface;

struct _GumScriptBackendIface
{
  GTypeInterface parent;

  void (* create) (GumScriptBackend * self, const gchar * name,
      const gchar * source, GCancellable * cancellable,
      GAsyncReadyCallback callback, gpointer user_data);
  GumScript * (* create_finish) (GumScriptBackend * self, GAsyncResult * result,
      GError ** error);
  GumScript * (* create_sync) (GumScriptBackend * self, const gchar * name,
      const gchar * source, GCancellable * cancellable,
      GError ** error);
  void (* create_from_bytes) (GumScriptBackend * self, const gchar * name,
      GBytes * bytes, GCancellable * cancellable, GAsyncReadyCallback callback,
      gpointer user_data);
  GumScript * (* create_from_bytes_finish) (GumScriptBackend * self,
      GAsyncResult * result, GError ** error);
  GumScript * (* create_from_bytes_sync) (GumScriptBackend * self,
      const gchar * name, GBytes * bytes, GCancellable * cancellable,
      GError ** error);

  void (* compile) (GumScriptBackend * self, const gchar * source,
      GCancellable * cancellable, GAsyncReadyCallback callback,
      gpointer user_data);
  GBytes * (* compile_finish) (GumScriptBackend * self, GAsyncResult * result,
      GError ** error);
  GBytes * (* compile_sync) (GumScriptBackend * self, const gchar * source,
      GCancellable * cancellable, GError ** error);

  void (* set_debug_message_handler) (GumScriptBackend * self,
      GumScriptDebugMessageHandler handler, gpointer data,
      GDestroyNotify data_destroy);
  void (* post_debug_message) (GumScriptBackend * self, const gchar * message);

  void (* ignore) (GumScriptBackend * self, GumThreadId thread_id);
  void (* unignore) (GumScriptBackend * self, GumThreadId thread_id);
  void (* unignore_later) (GumScriptBackend * self, GumThreadId thread_id);
  gboolean (* is_ignoring) (GumScriptBackend * self, GumThreadId thread_id);
};

G_BEGIN_DECLS

GUM_API GType gum_script_backend_get_type (void);

GUM_API GumScriptBackend * gum_script_backend_obtain (void);
GUM_API GumScriptBackend * gum_script_backend_obtain_v8 (void);
GUM_API GumScriptBackend * gum_script_backend_obtain_duk (void);

GUM_API void gum_script_backend_create (GumScriptBackend * self,
    const gchar * name, const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
GUM_API GumScript * gum_script_backend_create_finish (GumScriptBackend * self,
    GAsyncResult * result, GError ** error);
GUM_API GumScript * gum_script_backend_create_sync (GumScriptBackend * self,
    const gchar * name, const gchar * source, GCancellable * cancellable,
    GError ** error);
GUM_API void gum_script_backend_create_from_bytes (GumScriptBackend * self,
    const gchar * name, GBytes * bytes, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
GUM_API GumScript * gum_script_backend_create_from_bytes_finish (
    GumScriptBackend * self, GAsyncResult * result, GError ** error);
GUM_API GumScript * gum_script_backend_create_from_bytes_sync (
    GumScriptBackend * self, const gchar * name, GBytes * bytes,
    GCancellable * cancellable, GError ** error);

GUM_API void gum_script_backend_compile (GumScriptBackend * self,
    const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
GUM_API GBytes * gum_script_backend_compile_finish (GumScriptBackend * self,
    GAsyncResult * result, GError ** error);
GUM_API GBytes * gum_script_backend_compile_sync (GumScriptBackend * self,
    const gchar * source, GCancellable * cancellable, GError ** error);

GUM_API void gum_script_backend_set_debug_message_handler (
    GumScriptBackend * self, GumScriptDebugMessageHandler handler,
    gpointer data, GDestroyNotify data_destroy);
GUM_API void gum_script_backend_post_debug_message (GumScriptBackend * self,
    const gchar * message);

GUM_API void gum_script_backend_ignore (GumThreadId thread_id);
GUM_API void gum_script_backend_unignore (GumThreadId thread_id);
GUM_API void gum_script_backend_unignore_later (GumThreadId thread_id);
GUM_API gboolean gum_script_backend_is_ignoring (GumThreadId thread_id);

G_END_DECLS

#endif
