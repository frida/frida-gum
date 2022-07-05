/*
 * Copyright (C) 2020-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickscriptbackend.h"

#include "gumquickscript.h"
#include "gumquickscriptbackend-priv.h"
#include "gumscripttask.h"

#include <stdlib.h>
#include <string.h>

typedef struct _GumCompileProgramOperation GumCompileProgramOperation;
typedef struct _GumCreateScriptData GumCreateScriptData;
typedef struct _GumCreateScriptFromBytesData GumCreateScriptFromBytesData;
typedef struct _GumCompileScriptData GumCompileScriptData;

struct _GumQuickScriptBackend
{
  GObject parent;

  GMutex mutex;
  GRecMutex scope_mutex;
  gboolean scope_mutex_trapped;

  GumScriptScheduler * scheduler;
};

struct _GumCompileProgramOperation
{
  GumESProgram * program;
  GError * error;
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

static char * gum_normalize_module_name (JSContext * ctx,
    const char * base_name, const char * name, void * opaque);
static JSModuleDef * gum_load_module (JSContext * ctx, const char * module_name,
    void * opaque);
static JSValue gum_compile_module (JSContext * ctx, GumESAsset * asset,
    GumCompileProgramOperation * op);

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

static GumESProgram * gum_es_program_new (void);

static GumESAsset * gum_es_asset_new_take (gchar * name, gchar * alias,
    gpointer data, gsize data_size);
static GumESAsset * gum_es_asset_ref (GumESAsset * asset);
static void gum_es_asset_unref (GumESAsset * asset);

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
  self->scope_mutex_trapped = FALSE;

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

GumESProgram *
gum_quick_script_backend_compile_program (GumQuickScriptBackend * self,
                                          JSContext * ctx,
                                          const gchar * name,
                                          const gchar * source,
                                          GError ** error)
{
  GumESProgram * program;
  GumCompileProgramOperation op;
  JSRuntime * rt;
  const gchar * package_marker = "📦\n";
  const gchar * delimiter_marker = "\n✄\n";
  const gchar * alias_marker = "\n↻ ";
  GumESAsset * entrypoint = NULL;

  program = gum_es_program_new ();

  op.program = program;
  op.error = NULL;

  rt = JS_GetRuntime (ctx);

  if (g_str_has_prefix (source, package_marker))
  {
    const gchar * source_end, * header_cursor;

    program->es_assets = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
        (GDestroyNotify) gum_es_asset_unref);

    JS_SetModuleLoaderFunc (rt, gum_normalize_module_name, gum_load_module,
        &op);

    source_end = source + strlen (source);
    header_cursor = source + strlen (package_marker);

    do
    {
      const gchar * asset_cursor, * header_end;
      guint i;
      JSValue val;

      entrypoint = NULL;

      asset_cursor = strstr (header_cursor, delimiter_marker);
      if (asset_cursor == NULL)
        goto malformed_package;

      header_end = asset_cursor;

      for (i = 0; header_cursor != header_end; i++)
      {
        guint64 asset_size;
        const gchar * size_end, * rest_start, * rest_end;
        gchar * asset_name, * asset_alias, * asset_data;
        GumESAsset * asset;

        if (i != 0 && !g_str_has_prefix (asset_cursor, delimiter_marker))
          goto malformed_package;
        asset_cursor += strlen (delimiter_marker);

        asset_size = g_ascii_strtoull (header_cursor, (gchar **) &size_end, 10);
        if (asset_size == 0 || asset_size > GUM_MAX_ASSET_SIZE)
          goto malformed_package;
        if (asset_cursor + asset_size > source_end)
          goto malformed_package;

        rest_start = size_end + 1;
        rest_end = strchr (rest_start, '\n');

        asset_name = g_strndup (rest_start, rest_end - rest_start);

        asset_alias = NULL;
        if (g_str_has_prefix (rest_end, alias_marker))
        {
          const gchar * alias_start, * alias_end;

          alias_start = rest_end + strlen (alias_marker);
          alias_end = strchr (alias_start, '\n');

          asset_alias = g_strndup (alias_start, alias_end - alias_start);

          rest_end = alias_end;
        }

        if (g_hash_table_contains (program->es_assets, asset_name) ||
            (asset_alias != NULL &&
              g_hash_table_contains (program->es_assets, asset_alias)))
        {
          g_free (asset_alias);
          g_free (asset_name);
          goto malformed_package;
        }

        asset_data = g_strndup (asset_cursor, asset_size);

        asset = gum_es_asset_new_take (asset_name, asset_alias, asset_data,
            asset_size);
        g_hash_table_insert (program->es_assets, asset_name, asset);
        if (asset_alias != NULL)
        {
          g_hash_table_insert (program->es_assets, asset_alias,
              gum_es_asset_ref (asset));
        }

        if (entrypoint == NULL && g_str_has_suffix (asset_name, ".js"))
          entrypoint = asset;

        header_cursor = rest_end;
        asset_cursor += asset_size;
      }

      if (entrypoint == NULL)
        goto malformed_package;

      val = gum_compile_module (ctx, entrypoint, &op);
      if (JS_IsException (val))
        goto propagate_error;

      g_array_append_val (program->entrypoints, val);

      if (g_str_has_prefix (asset_cursor, delimiter_marker))
        header_cursor = asset_cursor + strlen (delimiter_marker);
      else
        header_cursor = NULL;
    }
    while (header_cursor != NULL);
  }
  else
  {
    JSValue val;
    GRegex * pattern;
    GMatchInfo * match_info;

    program->global_filename = g_strconcat ("/", name, ".js", NULL);

    val = JS_Eval (ctx, source, strlen (source), program->global_filename,
        JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_STRICT | JS_EVAL_FLAG_COMPILE_ONLY);

    if (JS_IsException (val))
      goto malformed_code;

    g_array_append_val (program->entrypoints, val);

    pattern = g_regex_new ("//[#@][ \\t]sourceMappingURL=[ \\t]*"
        "data:application/json;.*?base64,([^\\s'\"]*)[ \\t]*$",
        G_REGEX_MULTILINE, 0, NULL);

    g_regex_match (pattern, source, 0, &match_info);
    if (g_match_info_matches (match_info))
    {
      gchar * data_encoded, * data;
      gsize size;

      data_encoded = g_match_info_fetch (match_info, 1);

      data = (gchar *) g_base64_decode (data_encoded, &size);
      if (data != NULL && g_utf8_validate (data, size, NULL))
      {
        program->global_source_map = g_strndup (data, size);
      }
      g_free (data);

      g_free (data_encoded);
    }

    g_match_info_free (match_info);
    g_regex_unref (pattern);
  }

  goto beach;

malformed_package:
  {
    op.error = g_error_new (
        GUM_ERROR,
        GUM_ERROR_INVALID_DATA,
        "Malformed package");

    goto propagate_error;
  }
malformed_code:
  {
    JSValue exception_val, line_val;
    const char * message;
    uint32_t line;

    exception_val = JS_GetException (ctx);

    message = JS_ToCString (ctx, exception_val);

    line_val = JS_GetPropertyStr (ctx, exception_val, "lineNumber");
    JS_ToUint32 (ctx, &line, line_val);

    op.error = g_error_new (
        GUM_ERROR,
        GUM_ERROR_FAILED,
        "Script(line %u): %s",
        line,
        message);

    JS_FreeValue (ctx, line_val);
    JS_FreeCString (ctx, message);
    JS_FreeValue (ctx, exception_val);

    goto propagate_error;
  }
propagate_error:
  {
    g_propagate_error (error, op.error);

    gum_es_program_free (program, ctx);
    program = NULL;

    goto beach;
  }
beach:
  {
    JS_SetModuleLoaderFunc (rt, NULL, NULL, NULL);

    return program;
  }
}

static char *
gum_normalize_module_name (JSContext * ctx,
                           const char * base_name,
                           const char * name,
                           void * opaque)
{
  GumCompileProgramOperation * op = opaque;
  char * result;
  const char * base_dir_end;
  guint base_dir_length;
  const char * cursor;

  if (name[0] != '.')
  {
    GumESAsset * asset;

    asset = g_hash_table_lookup (op->program->es_assets, name);
    if (asset != NULL)
      return js_strdup (ctx, asset->name);

    return js_strdup (ctx, name);
  }

  /* The following is exactly like QuickJS' default implementation: */

  base_dir_end = strrchr (base_name, '/');
  if (base_dir_end != NULL)
    base_dir_length = base_dir_end - base_name;
  else
    base_dir_length = 0;

  result = js_malloc (ctx, base_dir_length + 1 + strlen (name) + 1);
  memcpy (result, base_name, base_dir_length);
  result[base_dir_length] = '\0';

  cursor = name;
  while (TRUE)
  {
    if (g_str_has_prefix (cursor, "./"))
    {
      cursor += 2;
    }
    else if (g_str_has_prefix (cursor, "../"))
    {
      char * new_end;

      if (result[0] == '\0')
        break;

      new_end = strrchr (result, '/');
      if (new_end != NULL)
        new_end++;
      else
        new_end = result;

      if (strcmp (new_end, ".") == 0 || strcmp (new_end, "..") == 0)
        break;

      if (new_end > result)
        new_end--;

      *new_end = '\0';

      cursor += 3;
    }
    else
    {
      break;
    }
  }

  strcat (result, "/");
  strcat (result, cursor);

  return result;
}

static JSModuleDef *
gum_load_module (JSContext * ctx,
                 const char * module_name,
                 void * opaque)
{
  GumCompileProgramOperation * op = opaque;
  GumESAsset * asset;
  JSValue val;

  asset = g_hash_table_lookup (op->program->es_assets, module_name);
  if (asset == NULL)
    goto not_found;

  val = gum_compile_module (ctx, asset, op);
  if (JS_IsException (val))
    return NULL;

  JS_FreeValue (ctx, val);

  return JS_VALUE_GET_PTR (val);

not_found:
  {
    if (op->error == NULL)
    {
      op->error = g_error_new (
          GUM_ERROR,
          GUM_ERROR_FAILED,
          "Could not load module '%s'",
          module_name);
    }

    return NULL;
  }
}

static JSValue
gum_compile_module (JSContext * ctx,
                    GumESAsset * asset,
                    GumCompileProgramOperation * op)
{
  JSValue val;

  val = JS_Eval (ctx, asset->data, asset->data_size, asset->name,
      JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_STRICT | JS_EVAL_FLAG_COMPILE_ONLY);
  if (JS_IsException (val))
    goto malformed_module;

  g_free (asset->data);
  asset->data = NULL;

  return val;

malformed_module:
  {
    JSValue exception_val, message_val, line_val;
    const char * message;
    uint32_t line;

    if (op->error != NULL)
      return JS_EXCEPTION;

    exception_val = JS_GetException (ctx);
    message_val = JS_GetPropertyStr (ctx, exception_val, "message");
    line_val = JS_GetPropertyStr (ctx, exception_val, "lineNumber");

    message = JS_ToCString (ctx, message_val);
    JS_ToUint32 (ctx, &line, line_val);

    op->error = g_error_new (
        GUM_ERROR,
        GUM_ERROR_FAILED,
        "Could not parse '%s' line %u: %s",
        asset->name,
        line,
        message);

    JS_FreeCString (ctx, message);
    JS_FreeValue (ctx, line_val);
    JS_FreeValue (ctx, message_val);
    JS_FreeValue (ctx, exception_val);

    return JS_EXCEPTION;
  }
}

GumESProgram *
gum_quick_script_backend_read_program (GumQuickScriptBackend * self,
                                       JSContext * ctx,
                                       GBytes * bytecode,
                                       GError ** error)
{
  GumESProgram * program;
  JSValue val;
  gconstpointer code;
  gsize size;

  program = gum_es_program_new ();

  code = g_bytes_get_data (bytecode, &size);

  val = JS_ReadObject (ctx, code, size, JS_READ_OBJ_BYTECODE);

  if (JS_IsException (val))
    goto malformed_code;

  g_array_append_val (program->entrypoints, val);

  return program;

malformed_code:
  {
    JSValue exception_val;
    const char * message_str;

    gum_es_program_free (program, ctx);

    exception_val = JS_GetException (ctx);
    message_str = JS_ToCString (ctx, exception_val);

    g_set_error_literal (error, GUM_ERROR, GUM_ERROR_FAILED, message_str);

    JS_FreeCString (ctx, message_str);
    JS_FreeValue (ctx, exception_val);

    return NULL;
  }
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
  GumESProgram * program;
  GError * error = NULL;

  rt = gum_quick_script_backend_make_runtime (self);
  ctx = JS_NewContext (rt);

  program = gum_quick_script_backend_compile_program (self, ctx, d->name,
      d->source, &error);

  if (error == NULL)
  {
    JSValue val;
    uint8_t * code;
    size_t size;
    GBytes * bytes;
    GDestroyNotify free_impl;

    /* TODO: Add support for compiling ESM-flavored scripts to bytecode. */
    val = g_array_index (program->entrypoints, JSValue, 0);

#ifndef HAVE_ASAN
    free_impl = gum_free;
#else
    free_impl = free;
#endif

    code = JS_WriteObject (ctx, &size, val, JS_WRITE_OBJ_BYTECODE);

    bytes = g_bytes_new_with_free_func (code, size, free_impl, code);

    gum_script_task_return_pointer (task, bytes,
        (GDestroyNotify) g_bytes_unref);

    gum_es_program_free (program, ctx);
  }
  else
  {
    gum_script_task_return_error (task, error);
  }

  JS_FreeContext (ctx);
  JS_FreeRuntime (rt);
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

  if (self->scope_mutex_trapped)
  {
    func (user_data);
    return;
  }

  g_rec_mutex_lock (&self->scope_mutex);
  func (user_data);
  g_rec_mutex_unlock (&self->scope_mutex);
}

static gboolean
gum_quick_script_backend_is_locked (GumScriptBackend * backend)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (backend);

  if (self->scope_mutex_trapped)
    return FALSE;

  if (!g_rec_mutex_trylock (&self->scope_mutex))
    return TRUE;

  g_rec_mutex_unlock (&self->scope_mutex);

  return FALSE;
}

gboolean
gum_quick_script_backend_is_scope_mutex_trapped (GumQuickScriptBackend * self)
{
  return self->scope_mutex_trapped;
}

void
gum_quick_script_backend_mark_scope_mutex_trapped (GumQuickScriptBackend * self)
{
  self->scope_mutex_trapped = TRUE;
}

static GumESProgram *
gum_es_program_new (void)
{
  GumESProgram * program;

  program = g_slice_new0 (GumESProgram);
  program->entrypoints = g_array_new (FALSE, FALSE, sizeof (JSValue));

  return program;
}

void
gum_es_program_free (GumESProgram * program,
                     JSContext * ctx)
{
  GArray * entrypoints;
  guint i;

  if (program == NULL)
    return;

  g_free (program->global_source_map);
  g_free (program->global_filename);

  g_clear_pointer (&program->es_assets, g_hash_table_unref);

  entrypoints = program->entrypoints;
  for (i = 0; i != entrypoints->len; i++)
    JS_FreeValue (ctx, g_array_index (entrypoints, JSValue, i));
  g_array_free (entrypoints, TRUE);

  g_slice_free (GumESProgram, program);
}

static GumESAsset *
gum_es_asset_new_take (gchar * name,
                       gchar * alias,
                       gpointer data,
                       gsize data_size)
{
  GumESAsset * asset;

  asset = g_slice_new (GumESAsset);

  asset->ref_count = 1;

  asset->name = name;
  asset->alias = alias;

  asset->data = data;
  asset->data_size = data_size;

  return asset;
}

static GumESAsset *
gum_es_asset_ref (GumESAsset * asset)
{
  g_atomic_int_inc (&asset->ref_count);

  return asset;
}

static void
gum_es_asset_unref (GumESAsset * asset)
{
  if (asset == NULL)
    return;

  if (!g_atomic_int_dec_and_test (&asset->ref_count))
    return;

  g_free (asset->data);
  g_free (asset->alias);
  g_free (asset->name);

  g_slice_free (GumESAsset, asset);
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
