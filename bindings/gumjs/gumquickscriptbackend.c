/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickscriptbackend.h"

#include "gumquickscript.h"
#include "gumquickscriptbackend-priv.h"
#include "gumscripttask.h"

#include <stdlib.h>
#include <string.h>

typedef struct _GumCreateScriptData GumCreateScriptData;
typedef struct _GumCreateScriptFromBytesData GumCreateScriptFromBytesData;
typedef struct _GumCompileScriptData GumCompileScriptData;

struct _GumQuickScriptBackend
{
  GObject parent;

  GMutex mutex;
  GRecMutex scope_mutex;

  GumScriptScheduler * scheduler;
};

struct _GumCreateScriptData
{
  gchar * name;
  gchar * source;
};

struct _GumCreateScriptFromBytesData
{
  GBytes * bytes;
};

struct _GumCompileScriptData
{
  gchar * name;
  gchar * source;
};

static void gum_quick_script_backend_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_script_backend_dispose (GObject * object);
static void gum_quick_script_backend_finalize (GObject * object);

static void gum_quick_script_backend_create (GumScriptBackend * backend,
    const gchar * name, const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GumScript * gum_quick_script_backend_create_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GumScript * gum_quick_script_backend_create_sync (
    GumScriptBackend * backend, const gchar * name, const gchar * source,
    GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_create_script_task_new (
    GumQuickScriptBackend * backend, const gchar * name, const gchar * source,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_create_script_task_run (GumScriptTask * task,
    GumQuickScriptBackend * self, GumCreateScriptData * d,
    GCancellable * cancellable);
static void gum_create_script_data_free (GumCreateScriptData * d);
static void gum_quick_script_backend_create_from_bytes (
    GumScriptBackend * backend, GBytes * bytes, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GumScript * gum_quick_script_backend_create_from_bytes_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GumScript * gum_quick_script_backend_create_from_bytes_sync (
    GumScriptBackend * backend, GBytes * bytes, GCancellable * cancellable,
    GError ** error);
static GumScriptTask * gum_create_script_from_bytes_task_new (
    GumQuickScriptBackend * backend, GBytes * bytes, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static void gum_create_script_from_bytes_task_run (GumScriptTask * task,
    GumQuickScriptBackend * self, GumCreateScriptFromBytesData * d,
    GCancellable * cancellable);
static void gum_create_script_from_bytes_data_free (
    GumCreateScriptFromBytesData * d);

static void gum_quick_script_backend_compile (GumScriptBackend * backend,
    const gchar * name, const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GBytes * gum_quick_script_backend_compile_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GBytes * gum_quick_script_backend_compile_sync (
    GumScriptBackend * backend, const gchar * name, const gchar * source,
    GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_compile_script_task_new (
    GumQuickScriptBackend * backend, const gchar * name, const gchar * source,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_compile_script_task_run (GumScriptTask * task,
    GumQuickScriptBackend * self, GumCompileScriptData * d,
    GCancellable * cancellable);
static void gum_compile_script_data_free (GumCompileScriptData * d);

static void gum_quick_script_backend_set_debug_message_handler (
    GumScriptBackend * backend, GumScriptBackendDebugMessageHandler handler,
    gpointer data, GDestroyNotify data_destroy);
static void gum_quick_script_backend_post_debug_message (
    GumScriptBackend * backend, const gchar * message);

static void gum_quick_script_backend_with_lock_held (GumScriptBackend * backend,
    GumScriptBackendLockedFunc func, gpointer user_data);
static gboolean gum_quick_script_backend_is_locked (GumScriptBackend * backend);

#ifndef HAVE_ASAN
static void * gum_quick_malloc (JSMallocState * state, size_t size);
static void gum_quick_free (JSMallocState * state, void * ptr);
static void * gum_quick_realloc (JSMallocState * state, void * ptr,
    size_t size);
static size_t gum_quick_malloc_usable_size (const void * ptr);
#endif

G_DEFINE_TYPE_EXTENDED (GumQuickScriptBackend,
                        gum_quick_script_backend,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT_BACKEND,
                            gum_quick_script_backend_iface_init))

static void
gum_quick_script_backend_class_init (GumQuickScriptBackendClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_script_backend_dispose;
  object_class->finalize = gum_quick_script_backend_finalize;
}

static void
gum_quick_script_backend_iface_init (gpointer g_iface,
                                     gpointer iface_data)
{
  GumScriptBackendInterface * iface = g_iface;

  iface->create = gum_quick_script_backend_create;
  iface->create_finish = gum_quick_script_backend_create_finish;
  iface->create_sync = gum_quick_script_backend_create_sync;
  iface->create_from_bytes = gum_quick_script_backend_create_from_bytes;
  iface->create_from_bytes_finish =
      gum_quick_script_backend_create_from_bytes_finish;
  iface->create_from_bytes_sync =
      gum_quick_script_backend_create_from_bytes_sync;

  iface->compile = gum_quick_script_backend_compile;
  iface->compile_finish = gum_quick_script_backend_compile_finish;
  iface->compile_sync = gum_quick_script_backend_compile_sync;

  iface->set_debug_message_handler =
      gum_quick_script_backend_set_debug_message_handler;
  iface->post_debug_message = gum_quick_script_backend_post_debug_message;

  iface->with_lock_held = gum_quick_script_backend_with_lock_held;
  iface->is_locked = gum_quick_script_backend_is_locked;
}

static void
gum_quick_script_backend_init (GumQuickScriptBackend * self)
{
  g_mutex_init (&self->mutex);
  g_rec_mutex_init (&self->scope_mutex);

  self->scheduler = g_object_ref (gum_script_backend_get_scheduler ());
}

static void
gum_quick_script_backend_dispose (GObject * object)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (object);

  g_clear_object (&self->scheduler);

  G_OBJECT_CLASS (gum_quick_script_backend_parent_class)->dispose (object);
}

static void
gum_quick_script_backend_finalize (GObject * object)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (object);

  g_mutex_clear (&self->mutex);
  g_rec_mutex_clear (&self->scope_mutex);

  G_OBJECT_CLASS (gum_quick_script_backend_parent_class)->finalize (object);
}

JSRuntime *
gum_quick_script_backend_make_runtime (GumQuickScriptBackend * self)
{
#ifndef HAVE_ASAN
  const JSMallocFunctions mf = {
    gum_quick_malloc,
    gum_quick_free,
    gum_quick_realloc,
    gum_quick_malloc_usable_size
  };

  return JS_NewRuntime2 (&mf, self);
#else
  return JS_NewRuntime ();
#endif
}

JSValue
gum_quick_script_backend_compile_program (GumQuickScriptBackend * self,
                                          JSContext * ctx,
                                          const gchar * name,
                                          const gchar * source,
                                          GError ** error)
{
  JSValue val;
  gchar * filename;

  filename = g_strconcat ("/", name, ".js", NULL);

  val = JS_Eval (ctx, source, strlen (source), filename,
      JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_STRICT | JS_EVAL_FLAG_COMPILE_ONLY);

  g_free (filename);

  if (JS_IsException (val))
  {
    JSValue exception_val, line_val;
    const char * message;
    uint32_t line;

    exception_val = JS_GetException (ctx);

    message = JS_ToCString (ctx, exception_val);

    line_val = JS_GetPropertyStr (ctx, exception_val, "lineNumber");
    JS_ToUint32 (ctx, &line, line_val);

    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "Script(line %u): %s",
        line,
        message);

    JS_FreeValue (ctx, line_val);
    JS_FreeCString (ctx, message);
    JS_FreeValue (ctx, exception_val);
  }

  return val;
}

JSValue
gum_quick_script_backend_read_program (GumQuickScriptBackend * self,
                                       JSContext * ctx,
                                       GBytes * bytecode,
                                       GError ** error)
{
  JSValue val;
  gconstpointer code;
  gsize size;

  code = g_bytes_get_data (bytecode, &size);

  val = JS_ReadObject (ctx, code, size, JS_READ_OBJ_BYTECODE);

  if (JS_IsException (val))
  {
    JSValue exception_val;
    const char * message_str;

    exception_val = JS_GetException (ctx);
    message_str = JS_ToCString (ctx, exception_val);

    g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, message_str);

    JS_FreeCString (ctx, message_str);
    JS_FreeValue (ctx, exception_val);
  }

  return val;
}

GRecMutex *
gum_quick_script_backend_get_scope_mutex (GumQuickScriptBackend * self)
{
  return &self->scope_mutex;
}

GumScriptScheduler *
gum_quick_script_backend_get_scheduler (GumQuickScriptBackend * self)
{
  return self->scheduler;
}

static void
gum_quick_script_backend_create (GumScriptBackend * backend,
                                 const gchar * name,
                                 const gchar * source,
                                 GCancellable * cancellable,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (backend);
  GumScriptTask * task;

  task = gum_create_script_task_new (self, name, source, cancellable, callback,
      user_data);
  gum_script_task_run_in_js_thread (task, self->scheduler);
  g_object_unref (task);
}

static GumScript *
gum_quick_script_backend_create_finish (GumScriptBackend * backend,
                                        GAsyncResult * result,
                                        GError ** error)
{
  return gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), error);
}

static GumScript *
gum_quick_script_backend_create_sync (GumScriptBackend * backend,
                                      const gchar * name,
                                      const gchar * source,
                                      GCancellable * cancellable,
                                      GError ** error)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (backend);
  GumScript * script;
  GumScriptTask * task;

  task = gum_create_script_task_new (self, name, source, cancellable, NULL,
      NULL);
  gum_script_task_run_in_js_thread_sync (task, self->scheduler);
  script = gum_script_task_propagate_pointer (task, error);
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_create_script_task_new (GumQuickScriptBackend * backend,
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

  task = gum_script_task_new ((GumScriptTaskFunc) gum_create_script_task_run,
      backend, cancellable, callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_create_script_data_free);
  return task;
}

static void
gum_create_script_task_run (GumScriptTask * task,
                            GumQuickScriptBackend * self,
                            GumCreateScriptData * d,
                            GCancellable * cancellable)
{
  GumQuickScript * script;
  GError * error = NULL;

  script = g_object_new (GUM_QUICK_TYPE_SCRIPT,
      "name", d->name,
      "source", d->source,
      "main-context", gum_script_task_get_context (task),
      "backend", self,
      NULL);

  gum_quick_script_create_context (script, &error);

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
gum_quick_script_backend_create_from_bytes (GumScriptBackend * backend,
                                            GBytes * bytes,
                                            GCancellable * cancellable,
                                            GAsyncReadyCallback callback,
                                            gpointer user_data)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (backend);
  GumScriptTask * task;

  task = gum_create_script_from_bytes_task_new (self, bytes, cancellable,
      callback, user_data);
  gum_script_task_run_in_js_thread (task, self->scheduler);
  g_object_unref (task);
}

static GumScript *
gum_quick_script_backend_create_from_bytes_finish (GumScriptBackend * backend,
                                                   GAsyncResult * result,
                                                   GError ** error)
{
  return gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), error);
}

static GumScript *
gum_quick_script_backend_create_from_bytes_sync (GumScriptBackend * backend,
                                                 GBytes * bytes,
                                                 GCancellable * cancellable,
                                                 GError ** error)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (backend);
  GumScript * script;
  GumScriptTask * task;

  task = gum_create_script_from_bytes_task_new (self, bytes, cancellable, NULL,
      NULL);
  gum_script_task_run_in_js_thread_sync (task, self->scheduler);
  script = GUM_SCRIPT (gum_script_task_propagate_pointer (task, error));
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_create_script_from_bytes_task_new (GumQuickScriptBackend * backend,
                                       GBytes * bytes,
                                       GCancellable * cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
  GumCreateScriptFromBytesData * d;
  GumScriptTask * task;

  d = g_slice_new (GumCreateScriptFromBytesData);
  d->bytes = g_bytes_ref (bytes);

  task = gum_script_task_new (
      (GumScriptTaskFunc) gum_create_script_from_bytes_task_run, backend,
      cancellable, callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_create_script_from_bytes_data_free);
  return task;
}

static void
gum_create_script_from_bytes_task_run (GumScriptTask * task,
                                       GumQuickScriptBackend * self,
                                       GumCreateScriptFromBytesData * d,
                                       GCancellable * cancellable)
{
  GumQuickScript * script;
  GError * error = NULL;

  script = g_object_new (GUM_QUICK_TYPE_SCRIPT,
      "bytecode", d->bytes,
      "main-context", gum_script_task_get_context (task),
      "backend", self,
      NULL);

  gum_quick_script_create_context (script, &error);

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
  g_bytes_unref (d->bytes);

  g_slice_free (GumCreateScriptFromBytesData, d);
}

static void
gum_quick_script_backend_compile (GumScriptBackend * backend,
                                  const gchar * name,
                                  const gchar * source,
                                  GCancellable * cancellable,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (backend);
  GumScriptTask * task;

  task = gum_compile_script_task_new (self, name, source, cancellable, callback,
      user_data);
  gum_script_task_run_in_js_thread (task, self->scheduler);
  g_object_unref (task);
}

static GBytes *
gum_quick_script_backend_compile_finish (GumScriptBackend * backend,
                                         GAsyncResult * result,
                                         GError ** error)
{
  return gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), error);
}

static GBytes *
gum_quick_script_backend_compile_sync (GumScriptBackend * backend,
                                       const gchar * name,
                                       const gchar * source,
                                       GCancellable * cancellable,
                                       GError ** error)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (backend);
  GBytes * bytes;
  GumScriptTask * task;

  task = gum_compile_script_task_new (self, name, source, cancellable, NULL,
      NULL);
  gum_script_task_run_in_js_thread_sync (task, self->scheduler);
  bytes = gum_script_task_propagate_pointer (task, error);
  g_object_unref (task);

  return bytes;
}

static GumScriptTask *
gum_compile_script_task_new (GumQuickScriptBackend * backend,
                             const gchar * name,
                             const gchar * source,
                             GCancellable * cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
  GumCompileScriptData * d = g_slice_new (GumCompileScriptData);
  d->name = g_strdup (name);
  d->source = g_strdup (source);

  GumScriptTask * task = gum_script_task_new (
      (GumScriptTaskFunc) gum_compile_script_task_run, backend, cancellable,
      callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_compile_script_data_free);
  return task;
}

static void
gum_compile_script_task_run (GumScriptTask * task,
                             GumQuickScriptBackend * self,
                             GumCompileScriptData * d,
                             GCancellable * cancellable)
{
  JSRuntime * rt;
  JSContext * ctx;
  JSValue val;
  GError * error = NULL;

  rt = gum_quick_script_backend_make_runtime (self);
  ctx = JS_NewContext (rt);

  val = gum_quick_script_backend_compile_program (self, ctx, d->name, d->source,
      &error);

  if (error == NULL)
  {
    uint8_t * code;
    size_t size;
    GBytes * bytes;
    GDestroyNotify free_impl;

#ifndef HAVE_ASAN
    free_impl = gum_free;
#else
    free_impl = free;
#endif

    code = JS_WriteObject (ctx, &size, val, JS_WRITE_OBJ_BYTECODE);

    bytes = g_bytes_new_with_free_func (code, size, free_impl, code);

    gum_script_task_return_pointer (task, bytes,
        (GDestroyNotify) g_bytes_unref);
  }
  else
  {
    gum_script_task_return_error (task, error);

    JS_FreeContext (ctx);
    JS_FreeRuntime (rt);
  }
}

static void
gum_compile_script_data_free (GumCompileScriptData * d)
{
  g_free (d->name);
  g_free (d->source);

  g_slice_free (GumCompileScriptData, d);
}

static void
gum_quick_script_backend_set_debug_message_handler (
    GumScriptBackend * backend,
    GumScriptBackendDebugMessageHandler handler,
    gpointer data,
    GDestroyNotify data_destroy)
{
  if (data_destroy != NULL)
    data_destroy (data);
}

static void
gum_quick_script_backend_post_debug_message (GumScriptBackend * backend,
                                             const gchar * message)
{
}

static void
gum_quick_script_backend_with_lock_held (GumScriptBackend * backend,
                                         GumScriptBackendLockedFunc func,
                                         gpointer user_data)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (backend);

  g_rec_mutex_lock (&self->scope_mutex);
  func (user_data);
  g_rec_mutex_unlock (&self->scope_mutex);
}

static gboolean
gum_quick_script_backend_is_locked (GumScriptBackend * backend)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (backend);

  if (!g_rec_mutex_trylock (&self->scope_mutex))
    return TRUE;

  g_rec_mutex_unlock (&self->scope_mutex);
  return FALSE;
}

#ifndef HAVE_ASAN

static void *
gum_quick_malloc (JSMallocState * state,
                  size_t size)
{
  return gum_malloc (size);
}

static void
gum_quick_free (JSMallocState * state,
                void * ptr)
{
  gum_free (ptr);
}

static void *
gum_quick_realloc (JSMallocState * state,
                   void * ptr,
                   size_t size)
{
  return gum_realloc (ptr, size);
}

static size_t
gum_quick_malloc_usable_size (const void * ptr)
{
  return gum_malloc_usable_size (ptr);
}

#endif
