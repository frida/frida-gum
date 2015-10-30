/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8script.h"

#include "gumv8script-priv.h"

#include <gum/gum-init.h>
#include <string.h>
#include <v8-debug.h>

#define GUM_V8_FLAGS \
    "--es-staging " \
    "--harmony-array-includes " \
    "--harmony-regexps " \
    "--harmony-proxies " \
    "--harmony-rest-parameters " \
    "--harmony-reflect " \
    "--harmony-destructuring " \
    "--expose-gc"

using namespace v8;

typedef struct _GumV8FromStringData GumV8FromStringData;
typedef struct _GumV8EmitMessageData GumV8EmitMessageData;
typedef struct _GumV8PostMessageData GumV8PostMessageData;

enum
{
  PROP_0,
  PROP_NAME,
  PROP_SOURCE,
  PROP_FLAVOR,
  PROP_MAIN_CONTEXT
};

struct _GumV8FromStringData
{
  gchar * name;
  gchar * source;
  GumV8ScriptFlavor flavor;
};

struct _GumV8EmitMessageData
{
  GumV8Script * script;
  gchar * message;
  GBytes * data;
};

struct _GumV8PostMessageData
{
  GumV8Script * script;
  gchar * message;
};

static GumV8Platform * gum_v8_script_do_init (void);
static void gum_v8_script_do_deinit (void);

static void gum_v8_script_listener_iface_init (gpointer g_iface,
    gpointer iface_data);

static void gum_v8_script_dispose (GObject * object);
static void gum_v8_script_finalize (GObject * object);
static void gum_v8_script_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_v8_script_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);
static void gum_v8_script_destroy_context (GumV8Script * self);

static GumScriptTask * gum_v8_script_from_string_task_new (const gchar * name,
    const gchar * source, GumV8ScriptFlavor flavor, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static void gum_v8_script_from_string_task_run (GumScriptTask * task,
    gpointer source_object, gpointer task_data, GCancellable * cancellable);
static void gum_v8_from_string_data_free (GumV8FromStringData * d);
static void gum_v8_script_emit_message (GumV8Script * self,
    const gchar * message, GBytes * data);
static gboolean gum_v8_script_do_emit_message (GumV8EmitMessageData * d);
static void gum_v8_emit_message_data_free (GumV8EmitMessageData * d);
static void gum_v8_script_do_load (GumScriptTask * task, gpointer source_object,
    gpointer task_data, GCancellable * cancellable);
static void gum_v8_script_do_unload (GumScriptTask * task, gpointer source_object,
    gpointer task_data, GCancellable * cancellable);
static void gum_v8_script_do_post_message (GumV8PostMessageData * d);
static void gum_v8_post_message_data_free (GumV8PostMessageData * d);

static void gum_v8_script_do_enable_debugger (void);
static void gum_v8_script_do_disable_debugger (void);
static void gum_v8_script_emit_debug_message (const Debug::Message & message);
static gboolean gum_v8_script_do_emit_debug_message (const gchar * message);
static void gum_v8_script_do_process_debug_messages (void);

static void gum_v8_script_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_v8_script_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);

G_DEFINE_TYPE_EXTENDED (GumV8Script,
                        gum_v8_script,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_v8_script_listener_iface_init));

G_LOCK_DEFINE_STATIC (gum_debug);
static GumV8ScriptDebugMessageHandler gum_debug_handler = NULL;
static gpointer gum_debug_handler_data = NULL;
static GDestroyNotify gum_debug_handler_data_destroy = NULL;
static GMainContext * gum_debug_handler_context = NULL;
static GumPersistent<Context>::type * gum_debug_context = nullptr;

GumV8Platform *
gum_v8_script_get_platform (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, (GThreadFunc) gum_v8_script_do_init, NULL);

  return static_cast<GumV8Platform *> (init_once.retval);
}

static Isolate *
gum_v8_script_get_isolate (void)
{
  return gum_v8_script_get_platform ()->GetIsolate ();
}

static GumScriptScheduler *
gum_v8_script_get_scheduler (void)
{
  return gum_v8_script_get_platform ()->GetScheduler ();
}

static GumV8Platform *
gum_v8_script_do_init (void)
{
  V8::SetFlagsFromString (GUM_V8_FLAGS,
      static_cast<int> (strlen (GUM_V8_FLAGS)));

  GumV8Platform * platform = new GumV8Platform ();

  _gum_register_destructor (gum_v8_script_do_deinit);

  return platform;
}

static void
gum_v8_script_do_deinit (void)
{
  GumV8Platform * platform = gum_v8_script_get_platform ();

  if (gum_debug_handler_data_destroy != NULL)
    gum_debug_handler_data_destroy (gum_debug_handler_data);
  gum_debug_handler = NULL;
  gum_debug_handler_data = NULL;
  gum_debug_handler_data_destroy = NULL;

  if (gum_debug_handler_context != NULL)
  {
    g_main_context_unref (gum_debug_handler_context);
    gum_debug_handler_context = NULL;
  }

  gum_v8_script_do_disable_debugger ();

  delete platform;
}

static void
gum_v8_script_class_init (GumV8ScriptClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumV8ScriptPrivate));

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
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_FLAVOR,
      g_param_spec_uint ("flavor", "Flavor", "Flavor", GUM_SCRIPT_FLAVOR_KERNEL,
      GUM_SCRIPT_FLAVOR_USER, GUM_SCRIPT_FLAVOR_USER,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_MAIN_CONTEXT,
      g_param_spec_boxed ("main-context", "MainContext",
      "MainContext being used", G_TYPE_MAIN_CONTEXT,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
}

static void
gum_v8_script_listener_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = gum_v8_script_on_enter;
  iface->on_leave = gum_v8_script_on_leave;
}

static void
gum_v8_script_init (GumV8Script * self)
{
  GumV8ScriptPrivate * priv;

  priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_SCRIPT, GumV8ScriptPrivate);

  priv->isolate = gum_v8_script_get_isolate ();
  priv->loaded = FALSE;
}

static void
gum_v8_script_dispose (GObject * object)
{
  GumV8Script * self = GUM_V8_SCRIPT (object);
  GumV8ScriptPrivate * priv = self->priv;

  gum_v8_script_set_message_handler (self, NULL, NULL, NULL);

  if (priv->loaded)
  {
    /* dispose() will be triggered again at the end of unload() */
    gum_v8_script_unload (self, NULL, NULL, NULL);
  }
  else
  {
    priv->isolate = NULL;

    if (priv->main_context != NULL)
    {
      g_main_context_unref (priv->main_context);
      priv->main_context = NULL;
    }
  }

  G_OBJECT_CLASS (gum_v8_script_parent_class)->dispose (object);
}

static void
gum_v8_script_finalize (GObject * object)
{
  GumV8Script * self = GUM_V8_SCRIPT (object);
  GumV8ScriptPrivate * priv = self->priv;

  g_free (priv->name);
  g_free (priv->source);

  G_OBJECT_CLASS (gum_v8_script_parent_class)->finalize (object);
}

static void
gum_v8_script_get_property (GObject * object,
                            guint property_id,
                            GValue * value,
                            GParamSpec * pspec)
{
  GumV8Script * self = GUM_V8_SCRIPT (object);
  GumV8ScriptPrivate * priv = self->priv;

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, priv->name);
      break;
    case PROP_SOURCE:
      g_value_set_string (value, priv->source);
      break;
    case PROP_FLAVOR:
      g_value_set_uint (value, priv->flavor);
      break;
    case PROP_MAIN_CONTEXT:
      g_value_set_boxed (value, priv->main_context);
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
  GumV8Script * self = GUM_V8_SCRIPT (object);
  GumV8ScriptPrivate * priv = self->priv;

  switch (property_id)
  {
    case PROP_NAME:
      g_free (priv->name);
      priv->name = g_value_dup_string (value);
      break;
    case PROP_SOURCE:
      g_free (priv->source);
      priv->source = g_value_dup_string (value);
      break;
    case PROP_FLAVOR:
      priv->flavor = g_value_get_uint (value);
      break;
    case PROP_MAIN_CONTEXT:
      if (priv->main_context != NULL)
        g_main_context_unref (priv->main_context);
      priv->main_context = (GMainContext *) g_value_dup_boxed (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static gboolean
gum_v8_script_create_context (GumV8Script * self,
                              GError ** error)
{
  GumV8ScriptPrivate * priv = self->priv;

  g_assert (priv->context == NULL);

  {
    Handle<ObjectTemplate> global_templ = ObjectTemplate::New ();
    _gum_v8_core_init (&priv->core, self, gum_v8_script_emit_message,
        gum_v8_script_get_scheduler (), priv->isolate, global_templ);
    if (priv->flavor == GUM_SCRIPT_FLAVOR_USER)
    {
      _gum_v8_memory_init (&priv->memory, &priv->core, global_templ);
      _gum_v8_process_init (&priv->process, &priv->core, global_templ);
      _gum_v8_thread_init (&priv->thread, &priv->core, global_templ);
      _gum_v8_module_init (&priv->module, &priv->core, global_templ);
      _gum_v8_file_init (&priv->file, &priv->core, global_templ);
      _gum_v8_socket_init (&priv->socket, &priv->core, global_templ);
      _gum_v8_interceptor_init (&priv->interceptor, &priv->core,
          global_templ);
      _gum_v8_stalker_init (&priv->stalker, &priv->core, global_templ);
      _gum_v8_symbol_init (&priv->symbol, &priv->core, global_templ);
      _gum_v8_instruction_init (&priv->instruction, &priv->core,
          global_templ);
    }
    else
    {
      _gum_v8_kernel_init (&priv->kernel, &priv->core, global_templ);
    }

    Local<Context> context (Context::New (priv->isolate, NULL, global_templ));
    priv->context = new GumPersistent<Context>::type (priv->isolate, context);
    Context::Scope context_scope (context);
    _gum_v8_core_realize (&priv->core);
    if (priv->flavor == GUM_SCRIPT_FLAVOR_USER)
    {
      _gum_v8_memory_realize (&priv->memory);
      _gum_v8_process_realize (&priv->process);
      _gum_v8_thread_realize (&priv->thread);
      _gum_v8_module_realize (&priv->module);
      _gum_v8_file_realize (&priv->file);
      _gum_v8_socket_realize (&priv->socket);
      _gum_v8_interceptor_realize (&priv->interceptor);
      _gum_v8_stalker_realize (&priv->stalker);
      _gum_v8_symbol_realize (&priv->symbol);
      _gum_v8_instruction_realize (&priv->instruction);
    }
    else
    {
      _gum_v8_kernel_realize (&priv->kernel);
    }

    gchar * resource_name_str = g_strconcat (priv->name, ".js",
        (gpointer) NULL);
    Local<String> resource_name (String::NewFromUtf8 (priv->isolate,
        resource_name_str));
    ScriptOrigin origin (resource_name);
    g_free (resource_name_str);

    Local<String> source (String::NewFromUtf8 (priv->isolate,
        priv->source));

    TryCatch trycatch;
    MaybeLocal<Script> maybe_code =
        Script::Compile (context, source, &origin);
    Local<Script> code;
    if (maybe_code.ToLocal (&code))
    {
      priv->code =
          new GumPersistent<Script>::type (priv->isolate, code);
    }
    else
    {
      Handle<Message> message = trycatch.Message ();
      Handle<Value> exception = trycatch.Exception ();
      String::Utf8Value exception_str (exception);
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Script(line %d): %s",
          message->GetLineNumber (), *exception_str);
    }
  }

  if (priv->code == NULL)
  {
    gum_v8_script_destroy_context (self);
    return FALSE;
  }

  return TRUE;
}

static void
gum_v8_script_destroy_context (GumV8Script * self)
{
  GumV8ScriptPrivate * priv = self->priv;

  g_assert (priv->context != NULL);

  {
    Local<Context> context (Local<Context>::New (priv->isolate,
        *priv->context));
    Context::Scope context_scope (context);

    if (priv->flavor == GUM_SCRIPT_FLAVOR_USER)
      _gum_v8_stalker_flush (&priv->stalker);
    _gum_v8_core_flush (&priv->core);

    if (priv->flavor == GUM_SCRIPT_FLAVOR_USER)
    {
      _gum_v8_instruction_dispose (&priv->instruction);
      _gum_v8_symbol_dispose (&priv->symbol);
      _gum_v8_stalker_dispose (&priv->stalker);
      _gum_v8_interceptor_dispose (&priv->interceptor);
      _gum_v8_socket_dispose (&priv->socket);
      _gum_v8_file_dispose (&priv->file);
      _gum_v8_module_dispose (&priv->module);
      _gum_v8_thread_dispose (&priv->thread);
      _gum_v8_process_dispose (&priv->process);
      _gum_v8_memory_dispose (&priv->memory);
    }
    else
    {
      _gum_v8_kernel_dispose (&priv->kernel);
    }
    _gum_v8_core_dispose (&priv->core);
  }

  delete priv->code;
  priv->code = NULL;
  delete priv->context;
  priv->context = NULL;

  if (priv->flavor == GUM_SCRIPT_FLAVOR_USER)
  {
    _gum_v8_instruction_finalize (&priv->instruction);
    _gum_v8_symbol_finalize (&priv->symbol);
    _gum_v8_stalker_finalize (&priv->stalker);
    _gum_v8_interceptor_finalize (&priv->interceptor);
    _gum_v8_socket_finalize (&priv->socket);
    _gum_v8_file_finalize (&priv->file);
    _gum_v8_module_finalize (&priv->module);
    _gum_v8_thread_finalize (&priv->thread);
    _gum_v8_process_finalize (&priv->process);
    _gum_v8_memory_finalize (&priv->memory);
  }
  else
  {
    _gum_v8_kernel_finalize (&priv->kernel);
  }
  _gum_v8_core_finalize (&priv->core);

  priv->loaded = FALSE;
}

void
gum_v8_script_from_string (const gchar * name,
                           const gchar * source,
                           GumV8ScriptFlavor flavor,
                           GCancellable * cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
  GumScriptTask * task;

  task = gum_v8_script_from_string_task_new (name, source, flavor, cancellable,
      callback, user_data);
  gum_script_task_run_in_js_thread (task, gum_v8_script_get_scheduler ());
  g_object_unref (task);
}

GumV8Script *
gum_v8_script_from_string_finish (GAsyncResult * result,
                                  GError ** error)
{
  return GUM_V8_SCRIPT (gum_script_task_propagate_pointer (
      GUM_SCRIPT_TASK (result), error));
}

GumV8Script *
gum_v8_script_from_string_sync (const gchar * name,
                                const gchar * source,
                                GumV8ScriptFlavor flavor,
                                GCancellable * cancellable,
                                GError ** error)
{
  GumV8Script * script;
  GumScriptTask * task;

  task = gum_v8_script_from_string_task_new (name, source, flavor, cancellable,
      NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task, gum_v8_script_get_scheduler ());
  script = GUM_V8_SCRIPT (gum_script_task_propagate_pointer (task, error));
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_v8_script_from_string_task_new (const gchar * name,
                                    const gchar * source,
                                    GumV8ScriptFlavor flavor,
                                    GCancellable * cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
  GumV8FromStringData * d = g_slice_new (GumV8FromStringData);
  d->name = g_strdup (name);
  d->source = g_strdup (source);
  d->flavor = flavor;

  GumScriptTask * task = gum_script_task_new (gum_v8_script_from_string_task_run,
      NULL, cancellable, callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_v8_from_string_data_free);
  return task;
}

static void
gum_v8_script_from_string_task_run (GumScriptTask * task,
                                    gpointer source_object,
                                    gpointer task_data,
                                    GCancellable * cancellable)
{
  GumV8FromStringData * d = (GumV8FromStringData *) task_data;
  GumV8Script * script;
  Isolate * isolate;
  GError * error = NULL;

  script = GUM_V8_SCRIPT (g_object_new (GUM_V8_TYPE_SCRIPT,
      "name", d->name,
      "source", d->source,
      "flavor", d->flavor,
      "main-context", gum_script_task_get_context (task),
      NULL));
  isolate = script->priv->isolate;

  {
    Locker locker (isolate);
    Isolate::Scope isolate_scope (isolate);
    HandleScope handle_scope (isolate);

    gum_v8_script_create_context (script, &error);
  }

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
gum_v8_from_string_data_free (GumV8FromStringData * d)
{
  g_free (d->name);
  g_free (d->source);

  g_slice_free (GumV8FromStringData, d);
}

GumStalker *
gum_v8_script_get_stalker (GumV8Script * self)
{
  return _gum_v8_stalker_get (&self->priv->stalker);
}

void
gum_v8_script_set_message_handler (GumV8Script * self,
                                   GumV8ScriptMessageHandler handler,
                                   gpointer data,
                                   GDestroyNotify data_destroy)
{
  GumV8ScriptPrivate * priv = self->priv;

  if (priv->message_handler_data_destroy != NULL)
    priv->message_handler_data_destroy (priv->message_handler_data);
  priv->message_handler = handler;
  priv->message_handler_data = data;
  priv->message_handler_data_destroy = data_destroy;
}

static void
gum_v8_script_emit_message (GumV8Script * self,
                            const gchar * message,
                            GBytes * data)
{
  GumV8EmitMessageData * d = g_slice_new (GumV8EmitMessageData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  GSource * source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_v8_script_do_emit_message,
      d,
      (GDestroyNotify) gum_v8_emit_message_data_free);
  g_source_attach (source, self->priv->main_context);
  g_source_unref (source);
}

static gboolean
gum_v8_script_do_emit_message (GumV8EmitMessageData * d)
{
  GumV8Script * self = d->script;
  GumV8ScriptPrivate * priv = self->priv;

  if (priv->message_handler != NULL)
  {
    priv->message_handler (self, d->message, d->data,
        priv->message_handler_data);
  }

  return FALSE;
}

static void
gum_v8_emit_message_data_free (GumV8EmitMessageData * d)
{
  g_bytes_unref (d->data);
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumV8EmitMessageData, d);
}

void
gum_v8_script_load (GumV8Script * self,
                    GCancellable * cancellable,
                    GAsyncReadyCallback callback,
                    gpointer user_data)
{
  GumScriptTask * task;

  task = gum_script_task_new (gum_v8_script_do_load, self, cancellable, callback,
      user_data);
  gum_script_task_run_in_js_thread (task, gum_v8_script_get_scheduler ());
  g_object_unref (task);
}

void
gum_v8_script_load_finish (GumV8Script * self,
                           GAsyncResult * result)
{
  (void) self;

  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

void
gum_v8_script_load_sync (GumV8Script * self,
                         GCancellable * cancellable)
{
  GumScriptTask * task;

  task = gum_script_task_new (gum_v8_script_do_load, self, cancellable, NULL,
      NULL);
  gum_script_task_run_in_js_thread_sync (task, gum_v8_script_get_scheduler ());
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_v8_script_do_load (GumScriptTask * task,
                       gpointer source_object,
                       gpointer task_data,
                       GCancellable * cancellable)
{
  GumV8Script * self = GUM_V8_SCRIPT (source_object);
  GumV8ScriptPrivate * priv = self->priv;

  {
    Locker locker (priv->isolate);
    Isolate::Scope isolate_scope (priv->isolate);
    HandleScope handle_scope (priv->isolate);

    if (priv->code == NULL)
    {
      gboolean created;

      created = gum_v8_script_create_context (self, NULL);
      g_assert (created);
    }

    if (!priv->loaded)
    {
      priv->loaded = TRUE;

      ScriptScope scope (self);

      gum_v8_bundle_run (gum_v8_script_get_platform ()->GetUserRuntime ());

      Local<Script> code (Local<Script>::New (priv->isolate, *priv->code));
      code->Run ();
    }
  }

  gum_script_task_return_pointer (task, NULL, NULL);
}

void
gum_v8_script_unload (GumV8Script * self,
                      GCancellable * cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
  GumScriptTask * task;

  task = gum_script_task_new (gum_v8_script_do_unload, self, cancellable, callback,
      user_data);
  gum_script_task_run_in_js_thread (task, gum_v8_script_get_scheduler ());
  g_object_unref (task);
}

void
gum_v8_script_unload_finish (GumV8Script * self,
                             GAsyncResult * result)
{
  (void) self;

  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

void
gum_v8_script_unload_sync (GumV8Script * self,
                           GCancellable * cancellable)
{
  GumScriptTask * task;

  task = gum_script_task_new (gum_v8_script_do_unload, self, cancellable, NULL,
      NULL);
  gum_script_task_run_in_js_thread_sync (task, gum_v8_script_get_scheduler ());
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_v8_script_do_unload (GumScriptTask * task,
                         gpointer source_object,
                         gpointer task_data,
                         GCancellable * cancellable)
{
  GumV8Script * self = GUM_V8_SCRIPT (source_object);
  GumV8ScriptPrivate * priv = self->priv;

  {
    Locker locker (priv->isolate);
    Isolate::Scope isolate_scope (priv->isolate);
    HandleScope handle_scope (priv->isolate);

    if (priv->loaded)
    {
      priv->loaded = FALSE;

      gum_v8_script_destroy_context (self);
    }
  }

  gum_script_task_return_pointer (task, NULL, NULL);
}

void
gum_v8_script_post_message (GumV8Script * self,
                            const gchar * message)
{
  GumV8PostMessageData * d = g_slice_new (GumV8PostMessageData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);

  gum_script_scheduler_push_job_on_js_thread (gum_v8_script_get_scheduler (),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_v8_script_do_post_message, d,
      (GDestroyNotify) gum_v8_post_message_data_free, NULL);
}

static void
gum_v8_script_do_post_message (GumV8PostMessageData * d)
{
  _gum_v8_core_post_message (&d->script->priv->core, d->message);
}

static void
gum_v8_post_message_data_free (GumV8PostMessageData * d)
{
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumV8PostMessageData, d);
}

void
gum_v8_script_set_debug_message_handler (GumV8ScriptDebugMessageHandler handler,
                                         gpointer data,
                                         GDestroyNotify data_destroy)
{
  GMainContext * old_context, * new_context;

  if (gum_debug_handler_data_destroy != NULL)
    gum_debug_handler_data_destroy (gum_debug_handler_data);

  gum_debug_handler = handler;
  gum_debug_handler_data = data;
  gum_debug_handler_data_destroy = data_destroy;

  new_context = (handler != NULL) ? g_main_context_ref_thread_default () : NULL;

  G_LOCK (gum_debug);
  old_context = gum_debug_handler_context;
  gum_debug_handler_context = new_context;
  G_UNLOCK (gum_debug);

  if (old_context != NULL)
    g_main_context_unref (old_context);

  gum_script_scheduler_push_job_on_js_thread (gum_v8_script_get_scheduler (),
      G_PRIORITY_DEFAULT,
      (handler != NULL)
          ? (GumScriptJobFunc) gum_v8_script_do_enable_debugger
          : (GumScriptJobFunc) gum_v8_script_do_disable_debugger,
      NULL, NULL, NULL);
}

static void
gum_v8_script_do_enable_debugger (void)
{
  Isolate * isolate = gum_v8_script_get_isolate ();

  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  Debug::SetMessageHandler (gum_v8_script_emit_debug_message);

  Local<Context> context = Debug::GetDebugContext ();
  gum_debug_context = new GumPersistent<Context>::type (isolate, context);
  Context::Scope context_scope (context);

  gum_v8_bundle_run (gum_v8_script_get_platform ()->GetDebugRuntime ());
}

static void
gum_v8_script_do_disable_debugger (void)
{
  Isolate * isolate = gum_v8_script_get_isolate ();

  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  delete gum_debug_context;
  gum_debug_context = nullptr;

  Debug::SetMessageHandler (nullptr);
}

static void
gum_v8_script_emit_debug_message (const Debug::Message & message)
{
  Isolate * isolate = message.GetIsolate ();
  HandleScope scope (isolate);

  Local<String> json = message.GetJSON ();
  String::Utf8Value json_str (json);

  G_LOCK (gum_debug);
  GMainContext * context = (gum_debug_handler_context != NULL)
      ? g_main_context_ref (gum_debug_handler_context)
      : NULL;
  G_UNLOCK (gum_debug);

  if (context == NULL)
    return;

  GSource * source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_v8_script_do_emit_debug_message,
      g_strdup (*json_str),
      g_free);
  g_source_attach (source, context);
  g_source_unref (source);

  g_main_context_unref (context);
}

static gboolean
gum_v8_script_do_emit_debug_message (const gchar * message)
{
  if (gum_debug_handler != NULL)
    gum_debug_handler (message, gum_debug_handler_data);

  return FALSE;
}

void
gum_v8_script_post_debug_message (const gchar * message)
{
  if (gum_debug_handler == NULL)
    return;

  Isolate * isolate = gum_v8_script_get_isolate ();

  glong command_length;
  uint16_t * command = g_utf8_to_utf16 (message, (glong) strlen (message), NULL,
      &command_length, NULL);
  g_assert (command != NULL);

  Debug::SendCommand (isolate, command, command_length);

  g_free (command);

  gum_script_scheduler_push_job_on_js_thread (gum_v8_script_get_scheduler (),
      G_PRIORITY_DEFAULT,
      (GumScriptJobFunc) gum_v8_script_do_process_debug_messages, NULL, NULL,
      NULL);
}

static void
gum_v8_script_do_process_debug_messages (void)
{
  Isolate * isolate = gum_v8_script_get_isolate ();
  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);
  Local<Context> context (Local<Context>::New (isolate, *gum_debug_context));
  Context::Scope context_scope (context);

  Debug::ProcessDebugMessages ();
}

static void
gum_v8_script_on_enter (GumInvocationListener * listener,
                        GumInvocationContext * context)
{
  GumV8Script * self = GUM_V8_SCRIPT_CAST (listener);

  _gum_v8_interceptor_on_enter (&self->priv->interceptor, context);
}

static void
gum_v8_script_on_leave (GumInvocationListener * listener,
                        GumInvocationContext * context)
{
  GumV8Script * self = GUM_V8_SCRIPT_CAST (listener);

  _gum_v8_interceptor_on_leave (&self->priv->interceptor, context);
}

