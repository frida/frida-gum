/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 * Copyright (C) 2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscript.h"

#include "gumscriptcore.h"
#include "gumscriptfile.h"
#include "gumscriptinstruction.h"
#include "gumscriptinterceptor.h"
#include "gumscriptmemory.h"
#include "gumscriptmodule.h"
#include "gumscriptplatform.h"
#include "gumscriptprocess.h"
#include "gumscriptscope.h"
#include "gumscriptsocket.h"
#include "gumscriptstalker.h"
#include "gumscriptsymbol.h"
#include "gumscripttask.h"
#include "gumscriptthread.h"

#include <gum/gum-init.h>
#include <string.h>
#include <v8-debug.h>

#define GUM_SCRIPT_V8_FLAGS "--harmony --expose-gc"

using namespace v8;

typedef struct _GumScriptFromStringData GumScriptFromStringData;
typedef struct _GumScriptEmitMessageData GumScriptEmitMessageData;
typedef struct _GumScriptPostMessageData GumScriptPostMessageData;

enum
{
  PROP_0,
  PROP_NAME,
  PROP_SOURCE,
  PROP_MAIN_CONTEXT
};

struct _GumScriptPrivate
{
  gchar * name;
  gchar * source;
  GMainContext * main_context;

  Isolate * isolate;
  GumScriptCore core;
  GumScriptMemory memory;
  GumScriptProcess process;
  GumScriptThread thread;
  GumScriptModule module;
  GumScriptFile file;
  GumScriptSocket socket;
  GumScriptInterceptor interceptor;
  GumScriptStalker stalker;
  GumScriptSymbol symbol;
  GumScriptInstruction instruction;
  GumPersistent<Context>::type * context;
  GumPersistent<Script>::type * code;
  gboolean loaded;

  GumScriptMessageHandler message_handler;
  gpointer message_handler_data;
  GDestroyNotify message_handler_data_destroy;
};

struct _GumScriptFromStringData
{
  gchar * name;
  gchar * source;
};

struct _GumScriptEmitMessageData
{
  GumScript * script;
  gchar * message;
  guint8 * data;
  gint data_length;
};

struct _GumScriptPostMessageData
{
  GumScript * script;
  gchar * message;
};

static GumScriptPlatform * gum_script_do_init (void);
static void gum_script_do_deinit (void);

static void gum_script_listener_iface_init (gpointer g_iface,
    gpointer iface_data);

static void gum_script_dispose (GObject * object);
static void gum_script_finalize (GObject * object);
static void gum_script_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_script_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);
static void gum_script_destroy_context (GumScript * self);

static GumScriptTask * gum_script_from_string_task_new (const gchar * name,
    const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static void gum_script_from_string_task_run (GumScriptTask * task,
    gpointer source_object, gpointer task_data, GCancellable * cancellable);
static void gum_script_from_string_data_free (GumScriptFromStringData * d);
static void gum_script_emit_message (GumScript * self,
    const gchar * message, const guint8 * data, gint data_length);
static gboolean gum_script_do_emit_message (GumScriptEmitMessageData * d);
static void gum_script_emit_message_data_free (GumScriptEmitMessageData * d);
static void gum_script_do_load (GumScriptTask * task, gpointer source_object,
    gpointer task_data, GCancellable * cancellable);
static void gum_script_do_unload (GumScriptTask * task, gpointer source_object,
    gpointer task_data, GCancellable * cancellable);
static void gum_script_do_post_message (GumScriptPostMessageData * d);
static void gum_script_post_message_data_free (GumScriptPostMessageData * d);

static void gum_script_do_enable_debugger (void);
static void gum_script_do_disable_debugger (void);
static void gum_script_emit_debug_message (const Debug::Message & message);
static gboolean gum_script_do_emit_debug_message (const gchar * message);
static void gum_script_do_process_debug_messages (void);

static void gum_script_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_script_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);

G_DEFINE_TYPE_EXTENDED (GumScript,
                        gum_script,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_script_listener_iface_init));

G_LOCK_DEFINE_STATIC (gum_debug);
static GumScriptDebugMessageHandler gum_debug_handler = NULL;
static gpointer gum_debug_handler_data = NULL;
static GDestroyNotify gum_debug_handler_data_destroy = NULL;
static GMainContext * gum_debug_handler_context = NULL;
static GumPersistent<Context>::type * gum_debug_context = nullptr;

static GumScriptPlatform *
gum_script_get_platform (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, (GThreadFunc) gum_script_do_init, NULL);

  return static_cast<GumScriptPlatform *> (init_once.retval);
}

static Isolate *
gum_script_get_isolate (void)
{
  return gum_script_get_platform ()->GetIsolate ();
}

static GumScriptScheduler *
gum_script_get_scheduler (void)
{
  return gum_script_get_platform ()->GetScheduler ();
}

static GumScriptPlatform *
gum_script_do_init (void)
{
  V8::SetFlagsFromString (GUM_SCRIPT_V8_FLAGS,
                          static_cast<int> (strlen (GUM_SCRIPT_V8_FLAGS)));

  GumScriptPlatform * platform = new GumScriptPlatform ();

  _gum_register_destructor (gum_script_do_deinit);

  return platform;
}

static void
gum_script_do_deinit (void)
{
  GumScriptPlatform * platform = gum_script_get_platform ();

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

  gum_script_do_disable_debugger ();

  delete platform;
}

static void
gum_script_class_init (GumScriptClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumScriptPrivate));

  object_class->dispose = gum_script_dispose;
  object_class->finalize = gum_script_finalize;
  object_class->get_property = gum_script_get_property;
  object_class->set_property = gum_script_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_SOURCE,
      g_param_spec_string ("source", "Source", "Source code", NULL,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_MAIN_CONTEXT,
      g_param_spec_boxed ("main-context", "MainContext",
      "MainContext being used", G_TYPE_MAIN_CONTEXT,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
}

static void
gum_script_listener_iface_init (gpointer g_iface,
                                gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = gum_script_on_enter;
  iface->on_leave = gum_script_on_leave;
}

static void
gum_script_init (GumScript * self)
{
  GumScriptPrivate * priv;

  priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_SCRIPT, GumScriptPrivate);

  priv->isolate = gum_script_get_isolate ();
  priv->loaded = FALSE;
}

static void
gum_script_dispose (GObject * object)
{
  GumScript * self = GUM_SCRIPT (object);
  GumScriptPrivate * priv = self->priv;

  gum_script_set_message_handler (self, NULL, NULL, NULL);

  if (priv->loaded)
  {
    /* dispose() will be triggered again at the end of unload() */
    gum_script_unload (self, NULL, NULL, NULL);
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

  G_OBJECT_CLASS (gum_script_parent_class)->dispose (object);
}

static void
gum_script_finalize (GObject * object)
{
  GumScript * self = GUM_SCRIPT (object);
  GumScriptPrivate * priv = self->priv;

  g_free (priv->name);
  g_free (priv->source);

  G_OBJECT_CLASS (gum_script_parent_class)->finalize (object);
}

static void
gum_script_get_property (GObject * object,
                         guint property_id,
                         GValue * value,
                         GParamSpec * pspec)
{
  GumScript * self = GUM_SCRIPT (object);
  GumScriptPrivate * priv = self->priv;

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, priv->name);
      break;
    case PROP_SOURCE:
      g_value_set_string (value, priv->source);
      break;
    case PROP_MAIN_CONTEXT:
      g_value_set_boxed (value, priv->main_context);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_script_set_property (GObject * object,
                         guint property_id,
                         const GValue * value,
                         GParamSpec * pspec)
{
  GumScript * self = GUM_SCRIPT (object);
  GumScriptPrivate * priv = self->priv;

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
gum_script_create_context (GumScript * self,
                           GError ** error)
{
  GumScriptPrivate * priv = self->priv;

  g_assert (priv->context == NULL);

  {
    Handle<ObjectTemplate> global_templ = ObjectTemplate::New ();
    _gum_script_core_init (&priv->core, self, gum_script_emit_message,
        gum_script_get_scheduler (), priv->isolate, global_templ);
    _gum_script_memory_init (&priv->memory, &priv->core, global_templ);
    _gum_script_process_init (&priv->process, &priv->core, global_templ);
    _gum_script_thread_init (&priv->thread, &priv->core, global_templ);
    _gum_script_module_init (&priv->module, &priv->core, global_templ);
    _gum_script_file_init (&priv->file, &priv->core, global_templ);
    _gum_script_socket_init (&priv->socket, &priv->core, global_templ);
    _gum_script_interceptor_init (&priv->interceptor, &priv->core,
        global_templ);
    _gum_script_stalker_init (&priv->stalker, &priv->core, global_templ);
    _gum_script_symbol_init (&priv->symbol, &priv->core, global_templ);
    _gum_script_instruction_init (&priv->instruction, &priv->core,
        global_templ);

    Local<Context> context (Context::New (priv->isolate, NULL, global_templ));
    priv->context = new GumPersistent<Context>::type (priv->isolate, context);
    Context::Scope context_scope (context);
    _gum_script_core_realize (&priv->core);
    _gum_script_memory_realize (&priv->memory);
    _gum_script_process_realize (&priv->process);
    _gum_script_thread_realize (&priv->thread);
    _gum_script_module_realize (&priv->module);
    _gum_script_file_realize (&priv->file);
    _gum_script_socket_realize (&priv->socket);
    _gum_script_interceptor_realize (&priv->interceptor);
    _gum_script_stalker_realize (&priv->stalker);
    _gum_script_symbol_realize (&priv->symbol);
    _gum_script_instruction_realize (&priv->instruction);

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
    gum_script_destroy_context (self);
    return FALSE;
  }

  return TRUE;
}

static void
gum_script_destroy_context (GumScript * self)
{
  GumScriptPrivate * priv = self->priv;

  g_assert (priv->context != NULL);

  {
    Local<Context> context (Local<Context>::New (priv->isolate,
        *priv->context));
    Context::Scope context_scope (context);

    _gum_script_stalker_flush (&priv->stalker);
    _gum_script_core_flush (&priv->core);

    _gum_script_instruction_dispose (&priv->instruction);
    _gum_script_symbol_dispose (&priv->symbol);
    _gum_script_stalker_dispose (&priv->stalker);
    _gum_script_interceptor_dispose (&priv->interceptor);
    _gum_script_socket_dispose (&priv->socket);
    _gum_script_file_dispose (&priv->file);
    _gum_script_module_dispose (&priv->module);
    _gum_script_thread_dispose (&priv->thread);
    _gum_script_process_dispose (&priv->process);
    _gum_script_memory_dispose (&priv->memory);
    _gum_script_core_dispose (&priv->core);
  }

  delete priv->code;
  priv->code = NULL;
  delete priv->context;
  priv->context = NULL;

  _gum_script_instruction_finalize (&priv->instruction);
  _gum_script_symbol_finalize (&priv->symbol);
  _gum_script_stalker_finalize (&priv->stalker);
  _gum_script_interceptor_finalize (&priv->interceptor);
  _gum_script_socket_finalize (&priv->socket);
  _gum_script_file_finalize (&priv->file);
  _gum_script_module_finalize (&priv->module);
  _gum_script_thread_finalize (&priv->thread);
  _gum_script_process_finalize (&priv->process);
  _gum_script_memory_finalize (&priv->memory);
  _gum_script_core_finalize (&priv->core);

  priv->loaded = FALSE;
}

void
gum_script_from_string (const gchar * name,
                        const gchar * source,
                        GCancellable * cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
  GumScriptTask * task;

  task = gum_script_from_string_task_new (name, source, cancellable, callback,
      user_data);
  gum_script_task_run_in_v8_thread (task, gum_script_get_scheduler ());
  g_object_unref (task);
}

GumScript *
gum_script_from_string_finish (GAsyncResult * result,
                               GError ** error)
{
  return GUM_SCRIPT (gum_script_task_propagate_pointer (
      GUM_SCRIPT_TASK (result), error));
}

GumScript *
gum_script_from_string_sync (const gchar * name,
                             const gchar * source,
                             GCancellable * cancellable,
                             GError ** error)
{
  GumScript * script;
  GumScriptTask * task;

  task = gum_script_from_string_task_new (name, source, cancellable, NULL,
      NULL);
  gum_script_task_run_in_v8_thread_sync (task, gum_script_get_scheduler ());
  script = GUM_SCRIPT (gum_script_task_propagate_pointer (task, error));
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_script_from_string_task_new (const gchar * name,
                                 const gchar * source,
                                 GCancellable * cancellable,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data)
{
  GumScriptFromStringData * d = g_slice_new (GumScriptFromStringData);
  d->name = g_strdup (name);
  d->source = g_strdup (source);

  GumScriptTask * task = gum_script_task_new (gum_script_from_string_task_run,
      NULL, cancellable, callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_script_from_string_data_free);
  return task;
}

static void
gum_script_from_string_task_run (GumScriptTask * task,
                                 gpointer source_object,
                                 gpointer task_data,
                                 GCancellable * cancellable)
{
  GumScriptFromStringData * d = (GumScriptFromStringData *) task_data;
  GumScript * script;
  Isolate * isolate;
  GError * error = NULL;

  script = GUM_SCRIPT (g_object_new (GUM_TYPE_SCRIPT,
      "name", d->name,
      "source", d->source,
      "main-context", gum_script_task_get_context (task),
      NULL));
  isolate = script->priv->isolate;

  {
    Locker locker (isolate);
    Isolate::Scope isolate_scope (isolate);
    HandleScope handle_scope (isolate);

    gum_script_create_context (script, &error);
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
gum_script_from_string_data_free (GumScriptFromStringData * d)
{
  g_free (d->name);
  g_free (d->source);

  g_slice_free (GumScriptFromStringData, d);
}

GumStalker *
gum_script_get_stalker (GumScript * self)
{
  return _gum_script_stalker_get (&self->priv->stalker);
}

void
gum_script_set_message_handler (GumScript * self,
                                GumScriptMessageHandler handler,
                                gpointer data,
                                GDestroyNotify data_destroy)
{
  GumScriptPrivate * priv = self->priv;

  if (priv->message_handler_data_destroy != NULL)
    priv->message_handler_data_destroy (priv->message_handler_data);
  priv->message_handler = handler;
  priv->message_handler_data = data;
  priv->message_handler_data_destroy = data_destroy;
}

static void
gum_script_emit_message (GumScript * self,
                         const gchar * message,
                         const guint8 * data,
                         gint data_length)
{
  GumScriptEmitMessageData * d = g_slice_new (GumScriptEmitMessageData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (guint8 *) g_memdup (data, data_length);
  d->data_length = data_length;

  GSource * source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_script_do_emit_message,
      d,
      (GDestroyNotify) gum_script_emit_message_data_free);
  g_source_attach (source, self->priv->main_context);
  g_source_unref (source);
}

static gboolean
gum_script_do_emit_message (GumScriptEmitMessageData * d)
{
  GumScript * self = d->script;
  GumScriptPrivate * priv = self->priv;

  if (priv->message_handler != NULL)
  {
    priv->message_handler (self, d->message, d->data, d->data_length,
        priv->message_handler_data);
  }

  return FALSE;
}

static void
gum_script_emit_message_data_free (GumScriptEmitMessageData * d)
{
  g_free (d->data);
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumScriptEmitMessageData, d);
}

void
gum_script_load (GumScript * self,
                 GCancellable * cancellable,
                 GAsyncReadyCallback callback,
                 gpointer user_data)
{
  GumScriptTask * task;

  task = gum_script_task_new (gum_script_do_load, self, cancellable, callback,
      user_data);
  gum_script_task_run_in_v8_thread (task, gum_script_get_scheduler ());
  g_object_unref (task);
}

void
gum_script_load_finish (GumScript * self,
                        GAsyncResult * result)
{
  (void) self;

  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

void
gum_script_load_sync (GumScript * self,
                      GCancellable * cancellable)
{
  GumScriptTask * task;

  task = gum_script_task_new (gum_script_do_load, self, cancellable, NULL,
      NULL);
  gum_script_task_run_in_v8_thread_sync (task, gum_script_get_scheduler ());
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_script_do_load (GumScriptTask * task,
                    gpointer source_object,
                    gpointer task_data,
                    GCancellable * cancellable)
{
  GumScript * self = GUM_SCRIPT (source_object);
  GumScriptPrivate * priv = self->priv;

  {
    Locker locker (priv->isolate);
    Isolate::Scope isolate_scope (priv->isolate);
    HandleScope handle_scope (priv->isolate);

    if (priv->code == NULL)
    {
      gboolean created;

      created = gum_script_create_context (self, NULL);
      g_assert (created);
    }

    if (!priv->loaded)
    {
      priv->loaded = TRUE;

      ScriptScope scope (self);

      gum_script_bundle_run (gum_script_get_platform ()->GetUserRuntime ());

      Local<Script> code (Local<Script>::New (priv->isolate, *priv->code));
      code->Run ();
    }
  }

  gum_script_task_return_pointer (task, NULL, NULL);
}

void
gum_script_unload (GumScript * self,
                   GCancellable * cancellable,
                   GAsyncReadyCallback callback,
                   gpointer user_data)
{
  GumScriptTask * task;

  task = gum_script_task_new (gum_script_do_unload, self, cancellable, callback,
      user_data);
  gum_script_task_run_in_v8_thread (task, gum_script_get_scheduler ());
  g_object_unref (task);
}

void
gum_script_unload_finish (GumScript * self,
                          GAsyncResult * result)
{
  (void) self;

  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

void
gum_script_unload_sync (GumScript * self,
                        GCancellable * cancellable)
{
  GumScriptTask * task;

  task = gum_script_task_new (gum_script_do_unload, self, cancellable, NULL,
      NULL);
  gum_script_task_run_in_v8_thread_sync (task, gum_script_get_scheduler ());
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_script_do_unload (GumScriptTask * task,
                      gpointer source_object,
                      gpointer task_data,
                      GCancellable * cancellable)
{
  GumScript * self = GUM_SCRIPT (source_object);
  GumScriptPrivate * priv = self->priv;

  {
    Locker locker (priv->isolate);
    Isolate::Scope isolate_scope (priv->isolate);
    HandleScope handle_scope (priv->isolate);

    if (priv->loaded)
    {
      priv->loaded = FALSE;

      gum_script_destroy_context (self);
    }
  }

  gum_script_task_return_pointer (task, NULL, NULL);
}

void
gum_script_post_message (GumScript * self,
                         const gchar * message)
{
  GumScriptPostMessageData * d = g_slice_new (GumScriptPostMessageData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);

  gum_script_scheduler_push_job_on_v8_thread (gum_script_get_scheduler (),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_script_do_post_message, d,
      (GDestroyNotify) gum_script_post_message_data_free, NULL);
}

static void
gum_script_do_post_message (GumScriptPostMessageData * d)
{
  _gum_script_core_post_message (&d->script->priv->core, d->message);
}

static void
gum_script_post_message_data_free (GumScriptPostMessageData * d)
{
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumScriptPostMessageData, d);
}

void
gum_script_set_debug_message_handler (GumScriptDebugMessageHandler handler,
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

  gum_script_scheduler_push_job_on_v8_thread (gum_script_get_scheduler (),
      G_PRIORITY_DEFAULT,
      (handler != NULL)
          ? (GumScriptJobFunc) gum_script_do_enable_debugger
          : (GumScriptJobFunc) gum_script_do_disable_debugger,
      NULL, NULL, NULL);
}

static void
gum_script_do_enable_debugger (void)
{
  Isolate * isolate = gum_script_get_isolate ();

  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  Debug::SetMessageHandler (gum_script_emit_debug_message);

  Local<Context> context = Debug::GetDebugContext ();
  gum_debug_context = new GumPersistent<Context>::type (isolate, context);
  Context::Scope context_scope (context);

  gum_script_bundle_run (gum_script_get_platform ()->GetDebugRuntime ());
}

static void
gum_script_do_disable_debugger (void)
{
  Isolate * isolate = gum_script_get_isolate ();

  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  delete gum_debug_context;
  gum_debug_context = nullptr;

  Debug::SetMessageHandler (nullptr);
}

static void
gum_script_emit_debug_message (const Debug::Message & message)
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
      (GSourceFunc) gum_script_do_emit_debug_message,
      g_strdup (*json_str),
      g_free);
  g_source_attach (source, context);
  g_source_unref (source);

  g_main_context_unref (context);
}

static gboolean
gum_script_do_emit_debug_message (const gchar * message)
{
  if (gum_debug_handler != NULL)
    gum_debug_handler (message, gum_debug_handler_data);

  return FALSE;
}

void
gum_script_post_debug_message (const gchar * message)
{
  if (gum_debug_handler == NULL)
    return;

  Isolate * isolate = gum_script_get_isolate ();

  glong command_length;
  uint16_t * command = g_utf8_to_utf16 (message, (glong) strlen (message), NULL,
      &command_length, NULL);
  g_assert (command != NULL);

  Debug::SendCommand (isolate, command, command_length);

  g_free (command);

  gum_script_scheduler_push_job_on_v8_thread (gum_script_get_scheduler (),
      G_PRIORITY_DEFAULT,
      (GumScriptJobFunc) gum_script_do_process_debug_messages, NULL, NULL,
      NULL);
}

static void
gum_script_do_process_debug_messages (void)
{
  Isolate * isolate = gum_script_get_isolate ();
  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);
  Local<Context> context (Local<Context>::New (isolate, *gum_debug_context));
  Context::Scope context_scope (context);

  Debug::ProcessDebugMessages ();
}

static void
gum_script_on_enter (GumInvocationListener * listener,
                     GumInvocationContext * context)
{
  GumScript * self = GUM_SCRIPT_CAST (listener);

  _gum_script_interceptor_on_enter (&self->priv->interceptor, context);
}

static void
gum_script_on_leave (GumInvocationListener * listener,
                     GumInvocationContext * context)
{
  GumScript * self = GUM_SCRIPT_CAST (listener);

  _gum_script_interceptor_on_leave (&self->priv->interceptor, context);
}

class ScriptScopeImpl
{
public:
  ScriptScopeImpl (GumScript * parent)
    : parent (parent),
      locker (parent->priv->isolate),
      isolate_scope (parent->priv->isolate),
      handle_scope (parent->priv->isolate),
      context (Local<Context>::New (parent->priv->isolate, *parent->priv->context)),
      context_scope (context)
  {
  }

  ~ScriptScopeImpl ()
  {
    GumScriptPrivate * priv = parent->priv;

    if (trycatch.HasCaught ())
    {
      Handle<Message> message = trycatch.Message ();
      Handle<Value> exception = trycatch.Exception ();
      String::Utf8Value exception_str (exception);
      gchar * exception_str_escaped = g_strescape (*exception_str, "");
      gchar * error = g_strdup_printf (
          "{\"type\":\"error\",\"lineNumber\":%d,\"description\":\"%s\"}",
          message->GetLineNumber (), exception_str_escaped);
      _gum_script_core_emit_message (&priv->core, error, NULL, 0);
      g_free (exception_str_escaped);
      g_free (error);
    }
  }

private:
  GumScript * parent;
  Locker locker;
  Isolate::Scope isolate_scope;
  HandleScope handle_scope;
  Local<Context> context;
  Context::Scope context_scope;
  TryCatch trycatch;
};

ScriptScope::ScriptScope (GumScript * parent)
  : parent (parent),
    impl (new ScriptScopeImpl (parent))
{
}

ScriptScope::~ScriptScope ()
{
  delete impl;
  impl = NULL;

  _gum_script_stalker_process_pending (&parent->priv->stalker);
}

