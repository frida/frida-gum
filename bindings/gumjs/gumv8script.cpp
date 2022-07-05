/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8script.h"

#include "gumscripttask.h"
#include "gumv8script-priv.h"
#include "gumv8value.h"

#include <cstring>

using namespace v8;

typedef void (* GumUnloadNotifyFunc) (GumV8Script * self, gpointer user_data);

enum
{
  CONTEXT_CREATED,
  CONTEXT_DESTROYED,
  LAST_SIGNAL
};

enum
{
  PROP_0,
  PROP_NAME,
  PROP_SOURCE,
  PROP_MAIN_CONTEXT,
  PROP_BACKEND
};

enum _GumScriptState
{
  GUM_SCRIPT_STATE_CREATED,
  GUM_SCRIPT_STATE_LOADING,
  GUM_SCRIPT_STATE_LOADED,
  GUM_SCRIPT_STATE_UNLOADING,
  GUM_SCRIPT_STATE_UNLOADED
};

struct GumUnloadNotifyCallback
{
  GumUnloadNotifyFunc func;
  gpointer data;
  GDestroyNotify data_destroy;
};

struct GumEmitData
{
  GumV8Script * script;
  gchar * message;
  GBytes * data;
};

struct GumPostData
{
  GumV8Script * script;
  gchar * message;
  GBytes * data;
};

static void gum_v8_script_iface_init (gpointer g_iface, gpointer iface_data);

static void gum_v8_script_constructed (GObject * object);
static void gum_v8_script_dispose (GObject * object);
static void gum_v8_script_finalize (GObject * object);
static void gum_v8_script_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_v8_script_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);
static GumESProgram * gum_v8_script_compile (GumV8Script * self,
    Isolate * isolate, Local<Context> context, GError ** error);
static MaybeLocal<Module> gum_resolve_module (Local<Context> context,
    Local<String> specifier, Local<Module> referrer);
static gchar * gum_normalize_module_name (const gchar * base_name,
    const gchar * name, GumESProgram * program);
static MaybeLocal<Module> gum_ensure_module_loaded (Isolate * isolate,
    Local<Context> context, GumESAsset * asset, GumESProgram * program);
static void gum_v8_script_destroy_context (GumV8Script * self);

static void gum_v8_script_load (GumScript * script, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static void gum_v8_script_load_finish (GumScript * script,
    GAsyncResult * result);
static void gum_v8_script_load_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_v8_script_do_load (GumScriptTask * task, GumV8Script * self,
    gpointer task_data, GCancellable * cancellable);
static void gum_v8_script_execute_entrypoints (GumV8Script * self,
    GumScriptTask * task);
static void gum_v8_script_on_entrypoints_executed (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_script_unload (GumScript * script,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_v8_script_unload_finish (GumScript * script,
    GAsyncResult * result);
static void gum_v8_script_unload_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_v8_script_do_unload (GumScriptTask * task, GumV8Script * self,
    gpointer task_data, GCancellable * cancellable);
static void gum_v8_script_complete_unload_task (GumV8Script * self,
    GumScriptTask * task);
static void gum_v8_script_try_unload (GumV8Script * self);
static void gum_v8_script_once_unloaded (GumV8Script * self,
    GumUnloadNotifyFunc func, gpointer data, GDestroyNotify data_destroy);

static void gum_v8_script_set_message_handler (GumScript * script,
    GumScriptMessageHandler handler, gpointer data,
    GDestroyNotify data_destroy);
static void gum_v8_script_post (GumScript * script, const gchar * message,
    GBytes * data);
static void gum_v8_script_do_post (GumPostData * d);
static void gum_v8_post_data_free (GumPostData * d);

static GumStalker * gum_v8_script_get_stalker (GumScript * script);

static void gum_v8_script_emit (GumV8Script * self, const gchar * message,
    GBytes * data);
static gboolean gum_v8_script_do_emit (GumEmitData * d);
static void gum_v8_emit_data_free (GumEmitData * d);

static GumESProgram * gum_es_program_new (void);
static void gum_es_program_free (GumESProgram * program);

static GumESAsset * gum_es_asset_new_take (gchar * name, gchar * alias,
    gpointer data, gsize data_size);
static GumESAsset * gum_es_asset_ref (GumESAsset * asset);
static void gum_es_asset_unref (GumESAsset * asset);

G_DEFINE_TYPE_EXTENDED (GumV8Script,
                        gum_v8_script,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT,
                            gum_v8_script_iface_init))

static guint gum_v8_script_signals[LAST_SIGNAL] = { 0, };

static void
gum_v8_script_class_init (GumV8ScriptClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_v8_script_constructed;
  object_class->dispose = gum_v8_script_dispose;
  object_class->finalize = gum_v8_script_finalize;
  object_class->get_property = gum_v8_script_get_property;
  object_class->set_property = gum_v8_script_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_SOURCE,
      g_param_spec_string ("source", "Source", "Source code", NULL,
      (GParamFlags) (G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_MAIN_CONTEXT,
      g_param_spec_boxed ("main-context", "MainContext",
      "MainContext being used", G_TYPE_MAIN_CONTEXT,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_BACKEND,
      g_param_spec_object ("backend", "Backend", "Backend being used",
      GUM_V8_TYPE_SCRIPT_BACKEND,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));

  gum_v8_script_signals[CONTEXT_CREATED] = g_signal_new ("context-created",
      G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST, 0, NULL, NULL,
      g_cclosure_marshal_VOID__POINTER, G_TYPE_NONE, 1, G_TYPE_POINTER);
  gum_v8_script_signals[CONTEXT_DESTROYED] = g_signal_new ("context-destroyed",
      G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST, 0, NULL, NULL,
      g_cclosure_marshal_VOID__POINTER, G_TYPE_NONE, 1, G_TYPE_POINTER);
}

static void
gum_v8_script_iface_init (gpointer g_iface,
                          gpointer iface_data)
{
  auto iface = (GumScriptInterface *) g_iface;

  iface->load = gum_v8_script_load;
  iface->load_finish = gum_v8_script_load_finish;
  iface->load_sync = gum_v8_script_load_sync;
  iface->unload = gum_v8_script_unload;
  iface->unload_finish = gum_v8_script_unload_finish;
  iface->unload_sync = gum_v8_script_unload_sync;

  iface->set_message_handler = gum_v8_script_set_message_handler;
  iface->post = gum_v8_script_post;

  iface->get_stalker = gum_v8_script_get_stalker;
}

static void
gum_v8_script_init (GumV8Script * self)
{
  self->state = GUM_SCRIPT_STATE_CREATED;
  self->on_unload = NULL;
}

static void
gum_v8_script_constructed (GObject * object)
{
  auto self = GUM_V8_SCRIPT (object);

  G_OBJECT_CLASS (gum_v8_script_parent_class)->constructed (object);

  self->isolate = (Isolate *) gum_v8_script_backend_get_isolate (self->backend);
}

static void
gum_v8_script_dispose (GObject * object)
{
  auto self = GUM_V8_SCRIPT (object);
  auto script = GUM_SCRIPT (self);

  gum_v8_script_set_message_handler (script, NULL, NULL, NULL);

  if (self->state == GUM_SCRIPT_STATE_LOADED)
  {
    /* dispose() will be triggered again at the end of unload() */
    gum_v8_script_unload (script, NULL, NULL, NULL);
  }
  else
  {
    if (self->state == GUM_SCRIPT_STATE_CREATED && self->context != nullptr)
      gum_v8_script_destroy_context (self);

    self->isolate = nullptr;

    g_clear_pointer (&self->main_context, g_main_context_unref);
    g_clear_pointer (&self->backend, g_object_unref);
  }

  G_OBJECT_CLASS (gum_v8_script_parent_class)->dispose (object);
}

static void
gum_v8_script_finalize (GObject * object)
{
  auto self = GUM_V8_SCRIPT (object);

  g_free (self->name);
  g_free (self->source);

  G_OBJECT_CLASS (gum_v8_script_parent_class)->finalize (object);
}

static void
gum_v8_script_get_property (GObject * object,
                            guint property_id,
                            GValue * value,
                            GParamSpec * pspec)
{
  auto self = GUM_V8_SCRIPT (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_MAIN_CONTEXT:
      g_value_set_boxed (value, self->main_context);
      break;
    case PROP_BACKEND:
      g_value_set_object (value, self->backend);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_v8_script_set_property (GObject * object,
                            guint property_id,
                            const GValue * value,
                            GParamSpec * pspec)
{
  auto self = GUM_V8_SCRIPT (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_free (self->name);
      self->name = g_value_dup_string (value);
      break;
    case PROP_SOURCE:
      g_free (self->source);
      self->source = g_value_dup_string (value);
      break;
    case PROP_MAIN_CONTEXT:
      if (self->main_context != NULL)
        g_main_context_unref (self->main_context);
      self->main_context = (GMainContext *) g_value_dup_boxed (value);
      break;
    case PROP_BACKEND:
      if (self->backend != NULL)
        g_object_unref (self->backend);
      self->backend = GUM_V8_SCRIPT_BACKEND (g_value_dup_object (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

gboolean
gum_v8_script_create_context (GumV8Script * self,
                              GError ** error)
{
  g_assert (self->context == NULL);

  {
    Isolate * isolate = self->isolate;
    Locker locker (isolate);
    Isolate::Scope isolate_scope (isolate);
    HandleScope handle_scope (isolate);

    auto global_templ = ObjectTemplate::New (isolate);
    auto platform =
        (GumV8Platform *) gum_v8_script_backend_get_platform (self->backend);
    _gum_v8_core_init (&self->core, self, platform->GetRuntimeSourceMap (),
        gum_v8_script_emit, gum_v8_script_backend_get_scheduler (self->backend),
        isolate, global_templ);
    _gum_v8_kernel_init (&self->kernel, &self->core, global_templ);
    _gum_v8_memory_init (&self->memory, &self->core, global_templ);
    _gum_v8_module_init (&self->module, &self->core, global_templ);
    _gum_v8_process_init (&self->process, &self->module, &self->core,
        global_templ);
    _gum_v8_thread_init (&self->thread, &self->core, global_templ);
    _gum_v8_file_init (&self->file, &self->core, global_templ);
    _gum_v8_checksum_init (&self->checksum, &self->core, global_templ);
    _gum_v8_stream_init (&self->stream, &self->core, global_templ);
    _gum_v8_socket_init (&self->socket, &self->core, global_templ);
#ifdef HAVE_SQLITE
    _gum_v8_database_init (&self->database, &self->core, global_templ);
#endif
    _gum_v8_interceptor_init (&self->interceptor, &self->core,
        global_templ);
    _gum_v8_api_resolver_init (&self->api_resolver, &self->core, global_templ);
    _gum_v8_symbol_init (&self->symbol, &self->core, global_templ);
    _gum_v8_cmodule_init (&self->cmodule, &self->core, global_templ);
    _gum_v8_instruction_init (&self->instruction, &self->core, global_templ);
    _gum_v8_code_writer_init (&self->code_writer, &self->core, global_templ);
    _gum_v8_code_relocator_init (&self->code_relocator, &self->code_writer,
        &self->instruction, &self->core, global_templ);
    _gum_v8_stalker_init (&self->stalker, &self->code_writer,
        &self->instruction, &self->core, global_templ);

    Local<Context> context (Context::New (isolate, NULL, global_templ));
    g_signal_emit (self, gum_v8_script_signals[CONTEXT_CREATED], 0, &context);
    self->context = new GumPersistent<Context>::type (isolate, context);
    Context::Scope context_scope (context);
    _gum_v8_core_realize (&self->core);
    _gum_v8_kernel_realize (&self->kernel);
    _gum_v8_memory_realize (&self->memory);
    _gum_v8_module_realize (&self->module);
    _gum_v8_process_realize (&self->process);
    _gum_v8_thread_realize (&self->thread);
    _gum_v8_file_realize (&self->file);
    _gum_v8_checksum_realize (&self->checksum);
    _gum_v8_stream_realize (&self->stream);
    _gum_v8_socket_realize (&self->socket);
#ifdef HAVE_SQLITE
    _gum_v8_database_realize (&self->database);
#endif
    _gum_v8_interceptor_realize (&self->interceptor);
    _gum_v8_api_resolver_realize (&self->api_resolver);
    _gum_v8_symbol_realize (&self->symbol);
    _gum_v8_cmodule_realize (&self->cmodule);
    _gum_v8_instruction_realize (&self->instruction);
    _gum_v8_code_writer_realize (&self->code_writer);
    _gum_v8_code_relocator_realize (&self->code_relocator);
    _gum_v8_stalker_realize (&self->stalker);

    self->program = gum_v8_script_compile (self, isolate, context, error);
  }

  if (self->program == NULL)
  {
    gum_v8_script_destroy_context (self);
    return FALSE;
  }

  g_free (self->source);
  self->source = NULL;

  return TRUE;
}

static GumESProgram *
gum_v8_script_compile (GumV8Script * self,
                       Isolate * isolate,
                       Local<Context> context,
                       GError ** error)
{
  GumESProgram * program = gum_es_program_new ();
  context->SetAlignedPointerInEmbedderData (0, program);

  const gchar * source = self->source;
  const gchar * package_marker = "📦\n";
  const gchar * delimiter_marker = "\n✄\n";
  const gchar * alias_marker = "\n↻ ";

  if (g_str_has_prefix (source, package_marker))
  {
    program->entrypoints = g_ptr_array_new ();
    program->es_assets = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
        (GDestroyNotify) gum_es_asset_unref);
    program->es_modules = g_hash_table_new (NULL, NULL);

    const gchar * source_end = source + std::strlen (source);
    const gchar * header_cursor = source + std::strlen (package_marker);

    do
    {
      GumESAsset * entrypoint = NULL;

      const gchar * asset_cursor = strstr (header_cursor, delimiter_marker);
      if (asset_cursor == NULL)
        goto malformed_package;

      const gchar * header_end = asset_cursor;

      for (guint i = 0; header_cursor != header_end; i++)
      {
        if (i != 0 && !g_str_has_prefix (asset_cursor, delimiter_marker))
          goto malformed_package;
        asset_cursor += std::strlen (delimiter_marker);

        const gchar * size_end;
        guint64 asset_size =
            g_ascii_strtoull (header_cursor, (gchar **) &size_end, 10);
        if (asset_size == 0 || asset_size > GUM_MAX_ASSET_SIZE)
          goto malformed_package;
        if (asset_cursor + asset_size > source_end)
          goto malformed_package;

        const gchar * rest_start = size_end + 1;
        const gchar * rest_end = std::strchr (rest_start, '\n');

        gchar * asset_name = g_strndup (rest_start, rest_end - rest_start);

        gchar * asset_alias = NULL;
        if (g_str_has_prefix (rest_end, alias_marker))
        {
          const gchar * alias_start = rest_end + std::strlen (alias_marker);
          const gchar * alias_end = std::strchr (alias_start, '\n');
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

        gchar * asset_data = g_strndup (asset_cursor, asset_size);

        auto asset = gum_es_asset_new_take (asset_name, asset_alias, asset_data,
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

      Local<Module> module;
      TryCatch trycatch (isolate);
      auto result =
          gum_ensure_module_loaded (isolate, context, entrypoint, program);
      if (!result.ToLocal (&module))
      {
        gchar * message =
            _gum_v8_error_get_message (isolate, trycatch.Exception ());
        g_set_error_literal (error, GUM_ERROR, GUM_ERROR_FAILED, message);
        g_free (message);
        goto propagate_error;
      }

      g_ptr_array_add (program->entrypoints, entrypoint);

      if (g_str_has_prefix (asset_cursor, delimiter_marker))
        header_cursor = asset_cursor + std::strlen (delimiter_marker);
      else
        header_cursor = NULL;
    }
    while (header_cursor != NULL);
  }
  else
  {
    program->global_filename = g_strconcat ("/", self->name, ".js", NULL);

    auto resource_name = String::NewFromUtf8 (isolate, program->global_filename)
        .ToLocalChecked ();
    ScriptOrigin origin (resource_name);

    auto source_str = String::NewFromUtf8 (isolate, source).ToLocalChecked ();

    Local<Script> code;
    TryCatch trycatch (isolate);
    auto maybe_code = Script::Compile (context, source_str, &origin);
    if (maybe_code.ToLocal (&code))
    {
      program->global_code = new GumPersistent<Script>::type (isolate, code);
    }
    else
    {
      Local<Message> message = trycatch.Message ();
      Local<Value> exception = trycatch.Exception ();
      String::Utf8Value exception_str (isolate, exception);
      g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED, "Script(line %d): %s",
          message->GetLineNumber (context).FromMaybe (-1), *exception_str);
      goto propagate_error;
    }
  }

  goto beach;

malformed_package:
  {
    g_set_error (error,
        GUM_ERROR,
        GUM_ERROR_INVALID_DATA,
        "Malformed package");

    goto propagate_error;
  }
propagate_error:
  {
    context->SetAlignedPointerInEmbedderData (0, nullptr);
    gum_es_program_free (program);
    program = NULL;

    goto beach;
  }
beach:
  {
    return program;
  }
}

static MaybeLocal<Module>
gum_resolve_module (Local<Context> context,
                    Local<String> specifier,
                    Local<Module> referrer)
{
  auto isolate = context->GetIsolate ();
  auto program =
      (GumESProgram *) context->GetAlignedPointerFromEmbedderData (0);

  auto referrer_module = (GumESAsset *) g_hash_table_lookup (
      program->es_modules, GINT_TO_POINTER (referrer->ScriptId ()));

  String::Utf8Value specifier_str (isolate, specifier);
  gchar * name = gum_normalize_module_name (referrer_module->name,
      *specifier_str, program);

  GumESAsset * target_module = (GumESAsset *) g_hash_table_lookup (
      program->es_assets, name);

  g_free (name);

  if (target_module == NULL)
    goto not_found;

  return gum_ensure_module_loaded (isolate, context, target_module, program);

not_found:
  {
    _gum_v8_throw (isolate, "could not load module '%s'", *specifier_str);
    return MaybeLocal<Module> ();
  }
}

static gchar *
gum_normalize_module_name (const gchar * base_name,
                           const gchar * name,
                           GumESProgram * program)
{
  if (name[0] != '.')
  {
    auto asset = (GumESAsset *) g_hash_table_lookup (program->es_assets, name);
    if (asset != NULL)
      return g_strdup (asset->name);

    return g_strdup (name);
  }

  /* The following is exactly like QuickJS' default implementation: */

  guint base_dir_length;
  auto base_dir_end = strrchr (base_name, '/');
  if (base_dir_end != NULL)
    base_dir_length = base_dir_end - base_name;
  else
    base_dir_length = 0;

  auto result = (gchar *) g_malloc (base_dir_length + 1 + strlen (name) + 1);
  memcpy (result, base_name, base_dir_length);
  result[base_dir_length] = '\0';

  auto cursor = name;
  while (TRUE)
  {
    if (g_str_has_prefix (cursor, "./"))
    {
      cursor += 2;
    }
    else if (g_str_has_prefix (cursor, "../"))
    {
      if (result[0] == '\0')
        break;

      gchar * new_end = strrchr (result, '/');
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

static MaybeLocal<Module>
gum_ensure_module_loaded (Isolate * isolate,
                          Local<Context> context,
                          GumESAsset * asset,
                          GumESProgram * program)
{
  if (asset->module != nullptr)
    return Local<Module>::New (isolate, *asset->module);

  auto source_str = String::NewFromUtf8 (isolate, (const char *) asset->data)
      .ToLocalChecked ();

  auto resource_name = String::NewFromUtf8 (isolate, asset->name)
      .ToLocalChecked ();
  auto resource_line_offset = Local<Integer> ();
  auto resource_column_offset = Local<Integer> ();
  auto resource_is_shared_cross_origin = Local<Boolean> ();
  auto script_id = Local<Integer> ();
  auto source_map_url = Local<Value> ();
  auto resource_is_opaque = Local<Boolean> ();
  auto is_wasm = Local<Boolean> ();
  auto is_module = True (isolate);
  ScriptOrigin origin (
      resource_name,
      resource_line_offset,
      resource_column_offset,
      resource_is_shared_cross_origin,
      script_id,
      source_map_url,
      resource_is_opaque,
      is_wasm,
      is_module);

  ScriptCompiler::Source source (source_str, origin);

  gchar * error_description = NULL;
  int line = -1;

  Local<Module> module;
  {
    TryCatch trycatch (isolate);
    auto compile_result = ScriptCompiler::CompileModule (isolate, &source);
    if (!compile_result.ToLocal (&module))
    {
      error_description =
          _gum_v8_error_get_message (isolate, trycatch.Exception ());
      line = trycatch.Message ()->GetLineNumber (context).FromMaybe (-1);
    }
  }
  if (error_description != NULL)
  {
    _gum_v8_throw (isolate,
        "could not parse '%s' line %d: %s",
        asset->name,
        line,
        error_description);
    g_free (error_description);
    return MaybeLocal<Module> ();
  }

  asset->module = new GumPersistent<Module>::type (isolate, module);

  g_hash_table_insert (program->es_modules,
      GINT_TO_POINTER (module->ScriptId ()), asset);

  bool success = false;
  {
    TryCatch trycatch (isolate);
    auto instantiate_result =
        module->InstantiateModule (context, gum_resolve_module);
    if (!instantiate_result.To (&success) || !success)
    {
      error_description =
          _gum_v8_error_get_message (isolate, trycatch.Exception ());
    }
  }
  if (error_description != NULL)
  {
    _gum_v8_throw_literal (isolate, error_description);
    g_free (error_description);
    return MaybeLocal<Module> ();
  }

  g_free (asset->data);
  asset->data = NULL;

  return module;
}

static void
gum_v8_script_destroy_context (GumV8Script * self)
{
  g_assert (self->context != NULL);

  {
    ScriptScope scope (self);

    _gum_v8_stalker_dispose (&self->stalker);
    _gum_v8_code_relocator_dispose (&self->code_relocator);
    _gum_v8_code_writer_dispose (&self->code_writer);
    _gum_v8_instruction_dispose (&self->instruction);
    _gum_v8_cmodule_dispose (&self->cmodule);
    _gum_v8_symbol_dispose (&self->symbol);
    _gum_v8_api_resolver_dispose (&self->api_resolver);
    _gum_v8_interceptor_dispose (&self->interceptor);
#ifdef HAVE_SQLITE
    _gum_v8_database_dispose (&self->database);
#endif
    _gum_v8_socket_dispose (&self->socket);
    _gum_v8_stream_dispose (&self->stream);
    _gum_v8_checksum_dispose (&self->checksum);
    _gum_v8_file_dispose (&self->file);
    _gum_v8_thread_dispose (&self->thread);
    _gum_v8_process_dispose (&self->process);
    _gum_v8_module_dispose (&self->module);
    _gum_v8_memory_dispose (&self->memory);
    _gum_v8_kernel_dispose (&self->kernel);
    _gum_v8_core_dispose (&self->core);

    auto context = Local<Context>::New (self->isolate, *self->context);
    g_signal_emit (self, gum_v8_script_signals[CONTEXT_DESTROYED], 0, &context);
  }

  gum_es_program_free (self->program);
  self->program = NULL;
  delete self->context;
  self->context = nullptr;

  _gum_v8_stalker_finalize (&self->stalker);
  _gum_v8_code_relocator_finalize (&self->code_relocator);
  _gum_v8_code_writer_finalize (&self->code_writer);
  _gum_v8_instruction_finalize (&self->instruction);
  _gum_v8_cmodule_finalize (&self->cmodule);
  _gum_v8_symbol_finalize (&self->symbol);
  _gum_v8_api_resolver_finalize (&self->api_resolver);
  _gum_v8_interceptor_finalize (&self->interceptor);
#ifdef HAVE_SQLITE
  _gum_v8_database_finalize (&self->database);
#endif
  _gum_v8_socket_finalize (&self->socket);
  _gum_v8_stream_finalize (&self->stream);
  _gum_v8_checksum_finalize (&self->checksum);
  _gum_v8_file_finalize (&self->file);
  _gum_v8_thread_finalize (&self->thread);
  _gum_v8_process_finalize (&self->process);
  _gum_v8_module_finalize (&self->module);
  _gum_v8_memory_finalize (&self->memory);
  _gum_v8_kernel_finalize (&self->kernel);
  _gum_v8_core_finalize (&self->core);
}

static void
gum_v8_script_load (GumScript * script,
                    GCancellable * cancellable,
                    GAsyncReadyCallback callback,
                    gpointer user_data)
{
  auto self = GUM_V8_SCRIPT (script);

  auto task = gum_script_task_new ((GumScriptTaskFunc) gum_v8_script_do_load,
      self, cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self->backend));
  g_object_unref (task);
}

static void
gum_v8_script_load_finish (GumScript * script,
                           GAsyncResult * result)
{
  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_v8_script_load_sync (GumScript * script,
                         GCancellable * cancellable)
{
  auto self = GUM_V8_SCRIPT (script);

  auto task = gum_script_task_new ((GumScriptTaskFunc) gum_v8_script_do_load,
      self, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_v8_script_do_load (GumScriptTask * task,
                       GumV8Script * self,
                       gpointer task_data,
                       GCancellable * cancellable)
{
  if (self->state != GUM_SCRIPT_STATE_CREATED)
    goto invalid_operation;

  self->state = GUM_SCRIPT_STATE_LOADING;

  gum_v8_script_execute_entrypoints (self, task);

  return;

invalid_operation:
  {
    gum_script_task_return_error (task,
        g_error_new_literal (
          GUM_ERROR,
          GUM_ERROR_NOT_SUPPORTED,
          "Invalid operation"));
  }
}

static void
gum_v8_script_execute_entrypoints (GumV8Script * self,
                                   GumScriptTask * task)
{
  bool done;
  {
    ScriptScope scope (self);
    auto isolate = self->isolate;
    auto context = isolate->GetCurrentContext ();

    auto platform =
        (GumV8Platform *) gum_v8_script_backend_get_platform (self->backend);
    gum_v8_bundle_run (platform->GetRuntimeBundle ());

    auto program = self->program;
    if (program->entrypoints != NULL)
    {
      auto entrypoints = program->entrypoints;

      auto pending = Array::New (isolate, entrypoints->len);
      for (guint i = 0; i != entrypoints->len; i++)
      {
        auto entrypoint = (GumESAsset *) g_ptr_array_index (entrypoints, i);
        auto module = Local<Module>::New (isolate, *entrypoint->module);
        auto promise = module->Evaluate (context);
        pending->Set (context, i, promise.ToLocalChecked ()).Check ();
      }

      auto promise_class = context->Global ()
          ->Get (context, _gum_v8_string_new_ascii (isolate, "Promise"))
          .ToLocalChecked ().As<Object> ();
      auto all_settled = promise_class
          ->Get (context, _gum_v8_string_new_ascii (isolate, "allSettled"))
          .ToLocalChecked ().As<Function> ();

      Local<Value> argv[] = { pending };
      auto load_request = all_settled
          ->Call (context, promise_class, G_N_ELEMENTS (argv), argv)
          .ToLocalChecked ().As<Promise> ();

      load_request->Then (context,
          Function::New (context, gum_v8_script_on_entrypoints_executed,
            External::New (isolate, g_object_ref (task)), 1,
            ConstructorBehavior::kThrow)
          .ToLocalChecked ())
          .ToLocalChecked ();

      done = false;
    }
    else
    {
      auto code = Local<Script>::New (isolate, *program->global_code);
      auto result = code->Run (context);
      _gum_v8_ignore_result (result);

      done = true;
    }
  }

  if (done)
  {
    self->state = GUM_SCRIPT_STATE_LOADED;

    gum_script_task_return_pointer (task, NULL, NULL);
  }
}

static void
gum_v8_script_on_entrypoints_executed (const FunctionCallbackInfo<Value> & info)
{
  auto task = (GumScriptTask *) info.Data ().As<External> ()->Value ();
  auto self = (GumV8Script *)
      g_async_result_get_source_object (G_ASYNC_RESULT (task));
  auto isolate = info.GetIsolate ();
  auto context = isolate->GetCurrentContext ();

  auto values = info[0].As<Array> ();
  uint32_t n = values->Length ();
  auto reason_str = _gum_v8_string_new_ascii (isolate, "reason");
  for (uint32_t i = 0; i != n; i++)
  {
    auto value = values->Get (context, i).ToLocalChecked ().As<Object> ();
    auto reason = value->Get (context, reason_str).ToLocalChecked ();
    if (!reason->IsUndefined ())
      _gum_v8_core_on_unhandled_exception (&self->core, reason);
  }

  self->state = GUM_SCRIPT_STATE_LOADED;

  gum_script_task_return_pointer (task, NULL, NULL);

  g_object_unref (self);
  g_object_unref (task);
}

static void
gum_v8_script_unload (GumScript * script,
                      GCancellable * cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
  auto self = GUM_V8_SCRIPT (script);

  auto task = gum_script_task_new ((GumScriptTaskFunc) gum_v8_script_do_unload,
      self, cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self->backend));
  g_object_unref (task);
}

static void
gum_v8_script_unload_finish (GumScript * script,
                             GAsyncResult * result)
{
  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_v8_script_unload_sync (GumScript * script,
                           GCancellable * cancellable)
{
  auto self = GUM_V8_SCRIPT (script);

  auto task = gum_script_task_new ((GumScriptTaskFunc) gum_v8_script_do_unload,
      self, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_v8_script_do_unload (GumScriptTask * task,
                         GumV8Script * self,
                         gpointer task_data,
                         GCancellable * cancellable)
{
  if (self->state != GUM_SCRIPT_STATE_LOADED)
    goto invalid_operation;

  self->state = GUM_SCRIPT_STATE_UNLOADING;
  gum_v8_script_once_unloaded (self,
      (GumUnloadNotifyFunc) gum_v8_script_complete_unload_task,
      g_object_ref (task), g_object_unref);

  gum_v8_script_try_unload (self);

  return;

invalid_operation:
  {
    gum_script_task_return_error (task,
        g_error_new_literal (
          GUM_ERROR,
          GUM_ERROR_NOT_SUPPORTED,
          "Invalid operation"));
  }
}

static void
gum_v8_script_complete_unload_task (GumV8Script * self,
                                    GumScriptTask * task)
{
  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_v8_script_try_unload (GumV8Script * self)
{
  g_assert (self->state == GUM_SCRIPT_STATE_UNLOADING);

  gboolean success;

  {
    ScriptScope scope (self);

    _gum_v8_stalker_flush (&self->stalker);
    _gum_v8_interceptor_flush (&self->interceptor);
    _gum_v8_socket_flush (&self->socket);
    _gum_v8_stream_flush (&self->stream);
    _gum_v8_process_flush (&self->process);
    success = _gum_v8_core_flush (&self->core, gum_v8_script_try_unload);
  }

  if (success)
  {
    gum_v8_script_destroy_context (self);

    self->state = GUM_SCRIPT_STATE_UNLOADED;

    while (self->on_unload != NULL)
    {
      auto link = self->on_unload;
      auto callback = (GumUnloadNotifyCallback *) link->data;

      callback->func (self, callback->data);
      if (callback->data_destroy != NULL)
        callback->data_destroy (callback->data);
      g_slice_free (GumUnloadNotifyCallback, callback);

      self->on_unload = g_slist_delete_link (self->on_unload, link);
    }
  }
}

static void
gum_v8_script_once_unloaded (GumV8Script * self,
                             GumUnloadNotifyFunc func,
                             gpointer data,
                             GDestroyNotify data_destroy)
{
  auto callback = g_slice_new (GumUnloadNotifyCallback);
  callback->func = func;
  callback->data = data;
  callback->data_destroy = data_destroy;

  self->on_unload = g_slist_append (self->on_unload, callback);
}

static void
gum_v8_script_set_message_handler (GumScript * script,
                                   GumScriptMessageHandler handler,
                                   gpointer data,
                                   GDestroyNotify data_destroy)
{
  auto self = GUM_V8_SCRIPT (script);

  if (self->message_handler_data_destroy != NULL)
    self->message_handler_data_destroy (self->message_handler_data);
  self->message_handler = handler;
  self->message_handler_data = data;
  self->message_handler_data_destroy = data_destroy;
}

static void
gum_v8_script_post (GumScript * script,
                    const gchar * message,
                    GBytes * data)
{
  auto self = GUM_V8_SCRIPT (script);

  auto d = g_slice_new (GumPostData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  gum_script_scheduler_push_job_on_js_thread (
      gum_v8_script_backend_get_scheduler (self->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_v8_script_do_post, d,
      (GDestroyNotify) gum_v8_post_data_free);
}

static void
gum_v8_script_do_post (GumPostData * d)
{
  GBytes * data = d->data;
  d->data = NULL;

  _gum_v8_core_post (&d->script->core, d->message, data);
}

static void
gum_v8_post_data_free (GumPostData * d)
{
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumPostData, d);
}

static GumStalker *
gum_v8_script_get_stalker (GumScript * script)
{
  auto self = GUM_V8_SCRIPT (script);

  return _gum_v8_stalker_get (&self->stalker);
}

static void
gum_v8_script_emit (GumV8Script * self,
                    const gchar * message,
                    GBytes * data)
{
  auto d = g_slice_new (GumEmitData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  auto source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) gum_v8_script_do_emit, d,
      (GDestroyNotify) gum_v8_emit_data_free);
  g_source_attach (source, self->main_context);
  g_source_unref (source);
}

static gboolean
gum_v8_script_do_emit (GumEmitData * d)
{
  auto self = d->script;

  if (self->message_handler != NULL)
  {
    self->message_handler (GUM_SCRIPT (self), d->message, d->data,
        self->message_handler_data);
  }

  return FALSE;
}

static void
gum_v8_emit_data_free (GumEmitData * d)
{
  g_bytes_unref (d->data);
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumEmitData, d);
}

static GumESProgram *
gum_es_program_new (void)
{
  return g_slice_new0 (GumESProgram);
}

static void
gum_es_program_free (GumESProgram * program)
{
  if (program == NULL)
    return;

  delete program->global_code;
  g_free (program->global_filename);

  g_clear_pointer (&program->es_modules, g_hash_table_unref);
  g_clear_pointer (&program->es_assets, g_hash_table_unref);
  g_clear_pointer (&program->entrypoints, g_ptr_array_unref);

  g_slice_free (GumESProgram, program);
}

static GumESAsset *
gum_es_asset_new_take (gchar * name,
                       gchar * alias,
                       gpointer data,
                       gsize data_size)
{
  auto asset = g_slice_new (GumESAsset);

  asset->ref_count = 1;

  asset->name = name;
  asset->alias = alias;

  asset->data = data;
  asset->data_size = data_size;

  asset->module = nullptr;

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

  delete asset->module;
  g_free (asset->data);
  g_free (asset->alias);
  g_free (asset->name);

  g_slice_free (GumESAsset, asset);
}
