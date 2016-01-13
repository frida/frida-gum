/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukscriptbackend.h"

#include "gumdukscript.h"
#include "gumscripttask.h"

#include <gum/guminterceptor.h>

typedef struct _GumCreateScriptData GumCreateScriptData;

struct _GumDukScriptBackendPrivate
{
  GumScriptScheduler * scheduler;

  GHashTable * ignored_threads;
  GSList * pending_unignores;
  GSource * pending_timeout;
  GumInterceptor * interceptor;
  GRWLock ignored_lock;
};

struct _GumCreateScriptData
{
  gchar * name;
  gchar * source;
};

static void gum_duk_script_backend_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_duk_script_backend_dispose (GObject * object);

static void gum_duk_script_backend_create (GumScriptBackend * backend,
    const gchar * name, const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GumScript * gum_duk_script_backend_create_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GumScript * gum_duk_script_backend_create_sync (
    GumScriptBackend * backend, const gchar * name, const gchar * source,
    GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_create_script_task_new (
    GumDukScriptBackend * backend, const gchar * name, const gchar * source,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_create_script_task_run (GumScriptTask * task,
    gpointer source_object, gpointer task_data, GCancellable * cancellable);
static void gum_create_script_data_free (GumCreateScriptData * d);

static void gum_duk_script_backend_set_debug_message_handler (
    GumScriptBackend * backend, GumScriptDebugMessageHandler handler,
    gpointer data, GDestroyNotify data_destroy);
static void gum_duk_script_backend_post_debug_message (
    GumScriptBackend * backend, const gchar * message);

static void gum_duk_script_backend_ignore (GumScriptBackend * backend,
    GumThreadId thread_id);
static void gum_duk_script_backend_unignore (GumScriptBackend * backend,
    GumThreadId thread_id);
static void gum_duk_script_backend_adjust_ignore_level (
    GumDukScriptBackend * self, GumThreadId thread_id, gint adjustment);
static void gum_duk_script_backend_adjust_ignore_level_unlocked (
    GumDukScriptBackend * self, GumThreadId thread_id, gint adjustment);
static void gum_duk_script_backend_unignore_later (GumScriptBackend * backend,
    GumThreadId thread_id);
static gboolean gum_flush_pending_unignores (gpointer user_data);
static gboolean gum_duk_script_backend_is_ignoring (GumScriptBackend * backend,
    GumThreadId thread_id);
static gboolean gum_duk_script_backend_supports_unload (
    GumScriptBackend * backend);

G_DEFINE_TYPE_EXTENDED (GumDukScriptBackend,
                        gum_duk_script_backend,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT_BACKEND,
                            gum_duk_script_backend_iface_init));

static void
gum_duk_script_backend_class_init (GumDukScriptBackendClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumDukScriptBackendPrivate));

  object_class->dispose = gum_duk_script_backend_dispose;
}

static void
gum_duk_script_backend_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumScriptBackendIface * iface = (GumScriptBackendIface *) g_iface;

  (void) iface_data;

  iface->create = gum_duk_script_backend_create;
  iface->create_finish = gum_duk_script_backend_create_finish;
  iface->create_sync = gum_duk_script_backend_create_sync;

  iface->set_debug_message_handler =
      gum_duk_script_backend_set_debug_message_handler;
  iface->post_debug_message = gum_duk_script_backend_post_debug_message;

  iface->ignore = gum_duk_script_backend_ignore;
  iface->unignore = gum_duk_script_backend_unignore;
  iface->unignore_later = gum_duk_script_backend_unignore_later;
  iface->is_ignoring = gum_duk_script_backend_is_ignoring;

  iface->supports_unload = gum_duk_script_backend_supports_unload;
}

static void
gum_duk_script_backend_init (GumDukScriptBackend * self)
{
  GumDukScriptBackendPrivate * priv;

  priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_DUK_TYPE_SCRIPT_BACKEND, GumDukScriptBackendPrivate);

  priv->scheduler = NULL;

  priv->ignored_threads = g_hash_table_new_full (NULL, NULL, NULL, NULL);

  priv->interceptor = gum_interceptor_obtain ();
}

static void
gum_duk_script_backend_dispose (GObject * object)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (object);
  GumDukScriptBackendPrivate * priv = self->priv;

  if (priv->pending_timeout != NULL)
  {
    g_source_destroy (priv->pending_timeout);
    g_clear_pointer (&priv->pending_timeout, g_source_unref);
  }
  g_clear_pointer (&priv->pending_unignores, g_slist_free);

  g_clear_pointer (&priv->interceptor, g_object_unref);

  g_clear_pointer (&priv->ignored_threads, g_hash_table_unref);

  g_clear_pointer (&priv->scheduler, g_object_unref);

  G_OBJECT_CLASS (gum_duk_script_backend_parent_class)->dispose (object);
}

GumScriptScheduler *
gum_duk_script_backend_get_scheduler (GumDukScriptBackend * self)
{
  GumDukScriptBackendPrivate * priv = self->priv;

  if (priv->scheduler == NULL)
    priv->scheduler = gum_script_scheduler_new ();

  return priv->scheduler;
}

static void
gum_duk_script_backend_create (GumScriptBackend * backend,
                               const gchar * name,
                               const gchar * source,
                               GCancellable * cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumScriptTask * task;

  task = gum_create_script_task_new (self, name, source, cancellable, callback,
      user_data);
  gum_script_task_run_in_js_thread (task,
      gum_duk_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GumScript *
gum_duk_script_backend_create_finish (GumScriptBackend * backend,
                                      GAsyncResult * result,
                                      GError ** error)
{
  (void) backend;

  return GUM_SCRIPT (gum_script_task_propagate_pointer (
      GUM_SCRIPT_TASK (result), error));
}

static GumScript *
gum_duk_script_backend_create_sync (GumScriptBackend * backend,
                                    const gchar * name,
                                    const gchar * source,
                                    GCancellable * cancellable,
                                    GError ** error)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumScript * script;
  GumScriptTask * task;

  task = gum_create_script_task_new (self, name, source, cancellable, NULL,
      NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_duk_script_backend_get_scheduler (self));
  script = GUM_SCRIPT (gum_script_task_propagate_pointer (task, error));
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_create_script_task_new (GumDukScriptBackend * backend,
                            const gchar * name,
                            const gchar * source,
                            GCancellable * cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
  GumCreateScriptData * d = g_slice_new (GumCreateScriptData);
  d->name = g_strdup (name);
  d->source = g_strdup (source);

  GumScriptTask * task = gum_script_task_new (gum_create_script_task_run,
      backend, cancellable, callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_create_script_data_free);
  return task;
}

static void
gum_create_script_task_run (GumScriptTask * task,
                            gpointer source_object,
                            gpointer task_data,
                            GCancellable * cancellable)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (source_object);
  GumCreateScriptData * d = (GumCreateScriptData *) task_data;
  GumDukScript * script;
  GError * error = NULL;

  (void) cancellable;

  script = GUM_DUK_SCRIPT (g_object_new (GUM_DUK_TYPE_SCRIPT,
      "name", d->name,
      "source", d->source,
      "main-context", gum_script_task_get_context (task),
      "backend", self,
      NULL));

  gum_duk_script_create_context (script, &error);

  if (error == NULL)
  {
    gum_script_task_return_pointer (task, script, g_object_unref);
  }
  else
  {
    gum_script_task_return_error (task, error);
    g_object_unref (script);
  }
}

static void
gum_create_script_data_free (GumCreateScriptData * d)
{
  g_free (d->name);
  g_free (d->source);

  g_slice_free (GumCreateScriptData, d);
}

static void
gum_duk_script_backend_set_debug_message_handler (
    GumScriptBackend * backend,
    GumScriptDebugMessageHandler handler,
    gpointer data,
    GDestroyNotify data_destroy)
{
  /* TODO */

  (void) backend;
  (void) handler;
  (void) data;
  (void) data_destroy;
}

static void
gum_duk_script_backend_post_debug_message (GumScriptBackend * backend,
                                           const gchar * message)
{
  /* TODO */

  (void) backend;
  (void) message;
}

static void
gum_duk_script_backend_ignore (GumScriptBackend * backend,
                               GumThreadId thread_id)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);

  gum_duk_script_backend_adjust_ignore_level (self, thread_id, 1);
}

static void
gum_duk_script_backend_unignore (GumScriptBackend * backend,
                                 GumThreadId thread_id)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);

  gum_duk_script_backend_adjust_ignore_level (self, thread_id, -1);
}

static void
gum_duk_script_backend_adjust_ignore_level (GumDukScriptBackend * self,
                                            GumThreadId thread_id,
                                            gint adjustment)
{
  GumDukScriptBackendPrivate * priv = self->priv;

  gum_interceptor_ignore_current_thread (priv->interceptor);

  g_rw_lock_writer_lock (&priv->ignored_lock);
  gum_duk_script_backend_adjust_ignore_level_unlocked (self, thread_id,
      adjustment);
  g_rw_lock_writer_unlock (&priv->ignored_lock);

  gum_interceptor_unignore_current_thread (priv->interceptor);
}

static void
gum_duk_script_backend_adjust_ignore_level_unlocked (
    GumDukScriptBackend * self,
    GumThreadId thread_id,
    gint adjustment)
{
  GumDukScriptBackendPrivate * priv = self->priv;
  gpointer thread_id_ptr = GSIZE_TO_POINTER (thread_id);
  gint level;

  level = GPOINTER_TO_INT (g_hash_table_lookup (priv->ignored_threads,
      thread_id_ptr));
  level += adjustment;

  if (level > 0)
  {
    g_hash_table_insert (priv->ignored_threads, thread_id_ptr,
        GINT_TO_POINTER (level));
  }
  else
  {
    g_hash_table_remove (priv->ignored_threads, thread_id_ptr);
  }
}

static void
gum_duk_script_backend_unignore_later (GumScriptBackend * backend,
                                       GumThreadId thread_id)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumDukScriptBackendPrivate * priv = self->priv;
  GMainContext * main_context;
  GSource * source;

  main_context = gum_script_scheduler_get_js_context (
      gum_duk_script_backend_get_scheduler (self));

  gum_interceptor_ignore_current_thread (priv->interceptor);

  g_rw_lock_writer_lock (&priv->ignored_lock);

  priv->pending_unignores = g_slist_prepend (priv->pending_unignores,
      GSIZE_TO_POINTER (thread_id));
  source = priv->pending_timeout;
  priv->pending_timeout = NULL;

  g_rw_lock_writer_unlock (&priv->ignored_lock);

  if (source != NULL)
  {
    g_source_destroy (source);
    g_source_unref (source);
  }
  source = g_timeout_source_new_seconds (5);
  g_source_set_callback (source, gum_flush_pending_unignores, self, NULL);
  g_source_attach (source, main_context);

  g_rw_lock_writer_lock (&priv->ignored_lock);

  if (priv->pending_timeout == NULL)
  {
    priv->pending_timeout = source;
    source = NULL;
  }

  g_rw_lock_writer_unlock (&priv->ignored_lock);

  if (source != NULL)
  {
    g_source_destroy (source);
    g_source_unref (source);
  }

  gum_interceptor_unignore_current_thread (priv->interceptor);
}

static gboolean
gum_flush_pending_unignores (gpointer user_data)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (user_data);
  GumDukScriptBackendPrivate * priv = self->priv;

  gum_interceptor_ignore_current_thread (priv->interceptor);

  g_rw_lock_writer_lock (&priv->ignored_lock);

  if (priv->pending_timeout == g_main_current_source ())
  {
    g_source_unref (priv->pending_timeout);
    priv->pending_timeout = NULL;
  }

  while (priv->pending_unignores != NULL)
  {
    GumThreadId thread_id;

    thread_id = GPOINTER_TO_SIZE (priv->pending_unignores->data);
    priv->pending_unignores = g_slist_delete_link (priv->pending_unignores,
        priv->pending_unignores);
    gum_duk_script_backend_adjust_ignore_level_unlocked (self, thread_id, -1);
  }

  g_rw_lock_writer_unlock (&priv->ignored_lock);

  gum_interceptor_unignore_current_thread (priv->interceptor);

  return FALSE;
}

static gboolean
gum_duk_script_backend_is_ignoring (GumScriptBackend * backend,
                                    GumThreadId thread_id)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumDukScriptBackendPrivate * priv = self->priv;
  gboolean is_ignored;

  g_rw_lock_reader_lock (&priv->ignored_lock);

  is_ignored = priv->ignored_threads != NULL && g_hash_table_contains (
      priv->ignored_threads, GSIZE_TO_POINTER (thread_id));

  g_rw_lock_reader_unlock (&priv->ignored_lock);

  return is_ignored;
}

static gboolean
gum_duk_script_backend_supports_unload (GumScriptBackend * backend)
{
  (void) backend;

  return TRUE;
}
