/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukscriptbackend.h"

#include "duktape.h"
#include "gumdukscript.h"
#include "gumscripttask.h"

#include <gum/guminterceptor.h>

typedef struct _GumCreateScriptData GumCreateScriptData;
typedef struct _GumCreateScriptFromBytesData GumCreateScriptFromBytesData;
typedef struct _GumCompileScriptData GumCompileScriptData;

struct _GumDukScriptBackendPrivate
{
  GumScriptScheduler * scheduler;
};

struct _GumCreateScriptData
{
  gchar * name;
  gchar * source;
};

struct _GumCreateScriptFromBytesData
{
  gchar * name;
  GBytes * bytes;
};

struct _GumCompileScriptData
{
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
static void gum_duk_script_backend_create_from_bytes (
    GumScriptBackend * backend, const gchar * name, GBytes * bytes,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static GumScript * gum_duk_script_backend_create_from_bytes_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GumScript * gum_duk_script_backend_create_from_bytes_sync (
    GumScriptBackend * backend, const gchar * name, GBytes * bytes,
    GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_create_script_from_bytes_task_new (
    GumDukScriptBackend * backend, const gchar * name, GBytes * bytes,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_create_script_from_bytes_task_run (GumScriptTask * task,
    gpointer source_object, gpointer task_data, GCancellable * cancellable);
static void gum_create_script_from_bytes_data_free (
    GumCreateScriptFromBytesData * d);

static void gum_duk_script_backend_compile (GumScriptBackend * backend,
    const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GBytes * gum_duk_script_backend_compile_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GBytes * gum_duk_script_backend_compile_sync (GumScriptBackend * backend,
    const gchar * source, GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_compile_script_task_new (
    GumDukScriptBackend * backend, const gchar * source,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_compile_script_task_run (GumScriptTask * task,
    gpointer source_object, gpointer task_data, GCancellable * cancellable);
static void gum_compile_script_data_free (GumCompileScriptData * d);

static void gum_duk_script_backend_set_debug_message_handler (
    GumScriptBackend * backend, GumScriptDebugMessageHandler handler,
    gpointer data, GDestroyNotify data_destroy);
static void gum_duk_script_backend_post_debug_message (
    GumScriptBackend * backend, const gchar * message);

static void gum_duk_script_backend_on_fatal_error (duk_context * ctx,
    duk_errcode_t code, const char * msg);

static void * gum_duk_alloc (void * udata, duk_size_t size);
static void * gum_duk_realloc (void * udata, void * ptr, duk_size_t size);
static void gum_duk_free (void * udata, void * ptr);

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
  iface->create_from_bytes = gum_duk_script_backend_create_from_bytes;
  iface->create_from_bytes_finish =
      gum_duk_script_backend_create_from_bytes_finish;
  iface->create_from_bytes_sync = gum_duk_script_backend_create_from_bytes_sync;

  iface->compile = gum_duk_script_backend_compile;
  iface->compile_finish = gum_duk_script_backend_compile_finish;
  iface->compile_sync = gum_duk_script_backend_compile_sync;

  iface->set_debug_message_handler =
      gum_duk_script_backend_set_debug_message_handler;
  iface->post_debug_message = gum_duk_script_backend_post_debug_message;
}

static void
gum_duk_script_backend_init (GumDukScriptBackend * self)
{
  GumDukScriptBackendPrivate * priv;

  priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_DUK_TYPE_SCRIPT_BACKEND, GumDukScriptBackendPrivate);

  priv->scheduler = NULL;
}

static void
gum_duk_script_backend_dispose (GObject * object)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (object);
  GumDukScriptBackendPrivate * priv = self->priv;

  g_clear_pointer (&priv->scheduler, g_object_unref);

  G_OBJECT_CLASS (gum_duk_script_backend_parent_class)->dispose (object);
}

gpointer
gum_duk_script_backend_create_heap (GumDukScriptBackend * self)
{
  return duk_create_heap (gum_duk_alloc, gum_duk_realloc, gum_duk_free, NULL,
      gum_duk_script_backend_on_fatal_error);
}

gboolean
gum_duk_script_backend_push_program (GumDukScriptBackend * self,
                                     gpointer ctx,
                                     const gchar * name,
                                     const gchar * source,
                                     GError ** error)
{
  gchar * url;
  gboolean valid;

  url = g_strconcat ("file:///", name, ".js", NULL);

  duk_push_string (ctx, source);
  duk_push_string (ctx, url);
  valid = duk_pcompile (ctx, 0) == 0;

  g_free (url);

  if (!valid)
  {
    gchar message[1024];
    gint line;

    /*
     * As duktape doesn't currently provide line number information, we
     * grab it from the error message itself using an sscanf.
     */
    sscanf (duk_safe_to_string (ctx, -1), "%[^\n(] (line %d)", message, &line);

    duk_pop (ctx);

    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "Script(line %u): %s",
        line,
        message);
  }

  return valid;
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

  return gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), error);
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
  script = gum_script_task_propagate_pointer (task, error);
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
  GumCreateScriptData * d;
  GumScriptTask * task;

  d = g_slice_new (GumCreateScriptData);
  d->name = g_strdup (name);
  d->source = g_strdup (source);

  task = gum_script_task_new (gum_create_script_task_run,
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
  GumDukScriptBackend * self = source_object;
  GumCreateScriptData * d = task_data;
  GumDukScript * script;
  GError * error = NULL;

  (void) cancellable;

  script = g_object_new (GUM_DUK_TYPE_SCRIPT,
      "name", d->name,
      "source", d->source,
      "main-context", gum_script_task_get_context (task),
      "backend", self,
      NULL);

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
gum_duk_script_backend_create_from_bytes (GumScriptBackend * backend,
                                          const gchar * name,
                                          GBytes * bytes,
                                          GCancellable * cancellable,
                                          GAsyncReadyCallback callback,
                                          gpointer user_data)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumScriptTask * task;

  task = gum_create_script_from_bytes_task_new (self, name, bytes, cancellable,
      callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_duk_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GumScript *
gum_duk_script_backend_create_from_bytes_finish (GumScriptBackend * backend,
                                                 GAsyncResult * result,
                                                 GError ** error)
{
  (void) backend;

  return gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), error);
}

static GumScript *
gum_duk_script_backend_create_from_bytes_sync (GumScriptBackend * backend,
                                               const gchar * name,
                                               GBytes * bytes,
                                               GCancellable * cancellable,
                                               GError ** error)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumScript * script;
  GumScriptTask * task;

  task = gum_create_script_from_bytes_task_new (self, name, bytes, cancellable,
      NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_duk_script_backend_get_scheduler (self));
  script = GUM_SCRIPT (gum_script_task_propagate_pointer (task, error));
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_create_script_from_bytes_task_new (GumDukScriptBackend * backend,
                                       const gchar * name,
                                       GBytes * bytes,
                                       GCancellable * cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
  GumCreateScriptFromBytesData * d;
  GumScriptTask * task;

  d = g_slice_new (GumCreateScriptFromBytesData);
  d->name = g_strdup (name);
  d->bytes = g_bytes_ref (bytes);

  task = gum_script_task_new (gum_create_script_from_bytes_task_run, backend,
      cancellable, callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_create_script_from_bytes_data_free);
  return task;
}

static void
gum_create_script_from_bytes_task_run (GumScriptTask * task,
                                       gpointer source_object,
                                       gpointer task_data,
                                       GCancellable * cancellable)
{
  GumDukScriptBackend * self = source_object;
  GumCreateScriptFromBytesData * d = task_data;
  GumDukScript * script;
  GError * error = NULL;

  (void) cancellable;

  script = g_object_new (GUM_DUK_TYPE_SCRIPT,
      "name", d->name,
      "bytecode", d->bytes,
      "main-context", gum_script_task_get_context (task),
      "backend", self,
      NULL);

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
gum_create_script_from_bytes_data_free (GumCreateScriptFromBytesData * d)
{
  g_free (d->name);
  g_bytes_unref (d->bytes);

  g_slice_free (GumCreateScriptFromBytesData, d);
}

static void
gum_duk_script_backend_compile (GumScriptBackend * backend,
                                const gchar * source,
                                GCancellable * cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GumScriptTask * task;

  task = gum_compile_script_task_new (self, source, cancellable, callback,
      user_data);
  gum_script_task_run_in_js_thread (task,
      gum_duk_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GBytes *
gum_duk_script_backend_compile_finish (GumScriptBackend * backend,
                                       GAsyncResult * result,
                                       GError ** error)
{
  (void) backend;

  return gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), error);
}

static GBytes *
gum_duk_script_backend_compile_sync (GumScriptBackend * backend,
                                     const gchar * source,
                                     GCancellable * cancellable,
                                     GError ** error)
{
  GumDukScriptBackend * self = GUM_DUK_SCRIPT_BACKEND (backend);
  GBytes * bytes;
  GumScriptTask * task;

  task = gum_compile_script_task_new (self, source, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_duk_script_backend_get_scheduler (self));
  bytes = gum_script_task_propagate_pointer (task, error);
  g_object_unref (task);

  return bytes;
}

static GumScriptTask *
gum_compile_script_task_new (GumDukScriptBackend * backend,
                             const gchar * source,
                             GCancellable * cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
  GumCompileScriptData * d = g_slice_new (GumCompileScriptData);
  d->source = g_strdup (source);

  GumScriptTask * task = gum_script_task_new (gum_compile_script_task_run,
      backend, cancellable, callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_compile_script_data_free);
  return task;
}

static void
gum_compile_script_task_run (GumScriptTask * task,
                             gpointer source_object,
                             gpointer task_data,
                             GCancellable * cancellable)
{
  GumDukScriptBackend * self = source_object;
  GumCompileScriptData * d = task_data;
  duk_context * ctx;
  GError * error = NULL;

  (void) cancellable;

  ctx = gum_duk_script_backend_create_heap (self);

  gum_duk_script_backend_push_program (self, ctx, "agent", d->source, &error);

  if (error == NULL)
  {
    gconstpointer code;
    duk_size_t size;
    GBytes * bytes;

    duk_dump_function (ctx);

    code = duk_require_buffer_data (ctx, -1, &size);

    bytes = g_bytes_new_with_free_func (code, size,
        (GDestroyNotify) duk_destroy_heap, ctx);

    gum_script_task_return_pointer (task, bytes,
        (GDestroyNotify) g_bytes_unref);
  }
  else
  {
    gum_script_task_return_error (task, error);

    duk_destroy_heap (ctx);
  }
}

static void
gum_compile_script_data_free (GumCompileScriptData * d)
{
  g_free (d->source);

  g_slice_free (GumCompileScriptData, d);
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
gum_duk_script_backend_on_fatal_error (duk_context * ctx,
                                       duk_errcode_t code,
                                       const char * msg)
{
  (void) ctx;

  g_printerr ("FATAL ERROR OCCURRED: %d, %s\n", code, msg);
  abort();
}

static void *
gum_duk_alloc (void * udata,
               duk_size_t size)
{
  (void) udata;

  return g_malloc (size);
}

static void *
gum_duk_realloc (void * udata,
                 void * ptr,
                 duk_size_t size)
{
  (void) udata;

  return g_realloc (ptr, size);
}

static void
gum_duk_free (void * udata,
              void * ptr)
{
  (void) udata;

  g_free (ptr);
}
