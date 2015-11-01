/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscscript.h"

#include "guminvocationlistener.h"
#include "gumjsccore.h"
#include "gumjscfile.h"
#include "gumjscinstruction.h"
#include "gumjscinterceptor.h"
#include "gumjsckernel.h"
#include "gumjscmemory.h"
#include "gumjscmodule.h"
#include "gumjscpolyfill.h"
#include "gumjscprocess.h"
#include "gumjscscript-priv.h"
#include "gumjscscript-runtime.h"
#include "gumjscscriptbackend.h"
#include "gumjscsocket.h"
#include "gumjscstalker.h"
#include "gumjscsymbol.h"
#include "gumjscthread.h"
#include "gumjscvalue.h"
#include "gumscripttask.h"

typedef struct _GumEmitMessageData GumEmitMessageData;
typedef struct _GumPostMessageData GumPostMessageData;

enum
{
  PROP_0,
  PROP_NAME,
  PROP_SOURCE,
  PROP_FLAVOR,
  PROP_MAIN_CONTEXT,
  PROP_BACKEND
};

struct _GumJscScriptPrivate
{
  gchar * name;
  gchar * source;
  GumScriptFlavor flavor;
  GMainContext * main_context;
  GumJscScriptBackend * backend;

  JSGlobalContextRef ctx;
  GumJscCore core;
  GumJscPolyfill polyfill;
  GumJscKernel kernel;
  GumJscMemory memory;
  GumJscProcess process;
  GumJscThread thread;
  GumJscModule module;
  GumJscFile file;
  GumJscSocket socket;
  GumJscInterceptor interceptor;
  GumJscStalker stalker;
  GumJscSymbol symbol;
  GumJscInstruction instruction;
  gboolean loaded;

  GumScriptMessageHandler message_handler;
  gpointer message_handler_data;
  GDestroyNotify message_handler_data_destroy;
};

struct _GumEmitMessageData
{
  GumJscScript * script;
  gchar * message;
  GBytes * data;
};

struct _GumPostMessageData
{
  GumJscScript * script;
  gchar * message;
};

static void gum_jsc_script_iface_init (gpointer g_iface, gpointer iface_data);
static void gum_jsc_script_listener_iface_init (gpointer g_iface,
    gpointer iface_data);

static void gum_jsc_script_dispose (GObject * object);
static void gum_jsc_script_finalize (GObject * object);
static void gum_jsc_script_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_jsc_script_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);
static void gum_jsc_script_destroy_context (GumJscScript * self);

static void gum_jsc_script_load (GumScript * script, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static void gum_jsc_script_load_finish (GumScript * script,
    GAsyncResult * result);
static void gum_jsc_script_load_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_jsc_script_do_load (GumScriptTask * task,
    gpointer source_object, gpointer task_data, GCancellable * cancellable);
static void gum_jsc_script_unload (GumScript * script,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_jsc_script_unload_finish (GumScript * script,
    GAsyncResult * result);
static void gum_jsc_script_unload_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_jsc_script_do_unload (GumScriptTask * task,
    gpointer source_object, gpointer task_data, GCancellable * cancellable);

static void gum_jsc_script_set_message_handler (GumScript * script,
    GumScriptMessageHandler handler, gpointer data,
    GDestroyNotify data_destroy);
static void gum_jsc_script_post_message (GumScript * script,
    const gchar * message);
static void gum_jsc_script_do_post_message (GumPostMessageData * d);
static void gum_jsc_post_message_data_free (GumPostMessageData * d);

static GumStalker * gum_jsc_script_get_stalker (GumScript * script);

static void gum_jsc_script_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_jsc_script_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);

static void gum_jsc_script_emit_message (GumJscScript * self,
    const gchar * message, GBytes * data);
static gboolean gum_jsc_script_do_emit_message (GumEmitMessageData * d);
static void gum_jsc_emit_message_data_free (GumEmitMessageData * d);

G_DEFINE_TYPE_EXTENDED (GumJscScript,
                        gum_jsc_script,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT,
                            gum_jsc_script_iface_init)
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_jsc_script_listener_iface_init));

static void
gum_jsc_script_class_init (GumJscScriptClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumJscScriptPrivate));

  object_class->dispose = gum_jsc_script_dispose;
  object_class->finalize = gum_jsc_script_finalize;
  object_class->get_property = gum_jsc_script_get_property;
  object_class->set_property = gum_jsc_script_set_property;

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
  g_object_class_install_property (object_class, PROP_BACKEND,
      g_param_spec_object ("backend", "Backend", "Backend being used",
      GUM_JSC_TYPE_SCRIPT_BACKEND,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
}

static void
gum_jsc_script_iface_init (gpointer g_iface,
                           gpointer iface_data)
{
  GumScriptIface * iface = (GumScriptIface *) g_iface;

  (void) iface_data;

  iface->load = gum_jsc_script_load;
  iface->load_finish = gum_jsc_script_load_finish;
  iface->load_sync = gum_jsc_script_load_sync;
  iface->unload = gum_jsc_script_unload;
  iface->unload_finish = gum_jsc_script_unload_finish;
  iface->unload_sync = gum_jsc_script_unload_sync;

  iface->set_message_handler = gum_jsc_script_set_message_handler;
  iface->post_message = gum_jsc_script_post_message;

  iface->get_stalker = gum_jsc_script_get_stalker;
}

static void
gum_jsc_script_listener_iface_init (gpointer g_iface,
                                    gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = gum_jsc_script_on_enter;
  iface->on_leave = gum_jsc_script_on_leave;
}

static void
gum_jsc_script_init (GumJscScript * self)
{
  GumJscScriptPrivate * priv;

  priv = self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_JSC_TYPE_SCRIPT, GumJscScriptPrivate);

  priv->loaded = FALSE;
}

static void
gum_jsc_script_dispose (GObject * object)
{
  GumJscScript * self = GUM_JSC_SCRIPT (object);
  GumJscScriptPrivate * priv = self->priv;
  GumScript * script = GUM_SCRIPT (self);

  gum_jsc_script_set_message_handler (script, NULL, NULL, NULL);

  if (priv->loaded)
  {
    /* dispose() will be triggered again at the end of unload() */
    gum_jsc_script_unload (script, NULL, NULL, NULL);
  }
  else
  {
    g_clear_pointer (&priv->main_context, g_main_context_unref);
  }

  G_OBJECT_CLASS (gum_jsc_script_parent_class)->dispose (object);
}

static void
gum_jsc_script_finalize (GObject * object)
{
  GumJscScript * self = GUM_JSC_SCRIPT (object);
  GumJscScriptPrivate * priv = self->priv;

  g_free (priv->name);
  g_free (priv->source);

  G_OBJECT_CLASS (gum_jsc_script_parent_class)->finalize (object);
}

static void
gum_jsc_script_get_property (GObject * object,
                             guint property_id,
                             GValue * value,
                             GParamSpec * pspec)
{
  GumJscScript * self = GUM_JSC_SCRIPT (object);
  GumJscScriptPrivate * priv = self->priv;

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
    case PROP_BACKEND:
      g_value_set_object (value, priv->backend);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_jsc_script_set_property (GObject * object,
                             guint property_id,
                             const GValue * value,
                             GParamSpec * pspec)
{
  GumJscScript * self = GUM_JSC_SCRIPT (object);
  GumJscScriptPrivate * priv = self->priv;

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
    case PROP_BACKEND:
      if (priv->backend != NULL)
        g_object_unref (priv->backend);
      priv->backend = GUM_JSC_SCRIPT_BACKEND (g_value_dup_object (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static JSStringRef
gum_jsc_script_create_url (GumJscScript * self)
{
  JSStringRef url;
  gchar * str;

  str = g_strconcat ("file:///", self->priv->name, ".js", NULL);
  url = JSStringCreateWithUTF8CString (str);
  g_free (str);

  return url;
}

gboolean
gum_jsc_script_create_context (GumJscScript * self,
                               GError ** error)
{
  GumJscScriptPrivate * priv = self->priv;
  JSClassDefinition def;
  JSClassRef ctx_class;
  JSGlobalContextRef ctx;
  JSStringRef source, url;
  JSValueRef exception;
  bool valid;
  JSObjectRef global;
  GumJscScope scope;

  g_assert (priv->ctx == NULL);

  def = kJSClassDefinitionEmpty;
  def.className = "Context";
  ctx_class = JSClassCreate (&def);

  ctx = JSGlobalContextCreate (ctx_class);

  JSClassRelease (ctx_class);

  source = JSStringCreateWithUTF8CString (priv->source);
  url = gum_jsc_script_create_url (self);

  valid = JSCheckScriptSyntax (ctx, source, url, 1, &exception);

  JSStringRelease (url);
  JSStringRelease (source);

  if (!valid)
  {
    gchar * message;
    guint line;

    message = _gumjs_string_from_value (ctx, exception);
    line = _gumjs_object_get_uint (ctx, (JSObjectRef) exception, "line");

    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "Script(line %u): %s",
        line,
        message);

    g_free (message);

    JSGlobalContextRelease (ctx);

    return FALSE;
  }

  priv->ctx = ctx;

  global = JSContextGetGlobalObject (ctx);

  _gum_jsc_core_init (&priv->core, self, gum_jsc_script_emit_message,
      gum_jsc_script_backend_get_scheduler (priv->backend), priv->ctx,
      global);
  _gum_jsc_polyfill_init (&priv->polyfill, &priv->core, global);
  if (priv->flavor == GUM_SCRIPT_FLAVOR_USER)
  {
    _gum_jsc_memory_init (&priv->memory, &priv->core, global);
    _gum_jsc_process_init (&priv->process, &priv->core, global);
    _gum_jsc_thread_init (&priv->thread, &priv->core, global);
    _gum_jsc_module_init (&priv->module, &priv->core, global);
    _gum_jsc_file_init (&priv->file, &priv->core, global);
    _gum_jsc_socket_init (&priv->socket, &priv->core, global);
    _gum_jsc_interceptor_init (&priv->interceptor, &priv->core, global);
    _gum_jsc_stalker_init (&priv->stalker, &priv->core, global);
    _gum_jsc_symbol_init (&priv->symbol, &priv->core, global);
    _gum_jsc_instruction_init (&priv->instruction, &priv->core, global);
  }
  else
  {
    _gum_jsc_kernel_init (&priv->kernel, &priv->core, global);
  }

  _gum_jsc_scope_enter (&scope, &priv->core);
  gum_jsc_bundle_load (gum_jsc_script_runtime_sources, priv->ctx);
  _gum_jsc_scope_leave (&scope);

  return TRUE;
}

static void
gum_jsc_script_destroy_context (GumJscScript * self)
{
  GumJscScriptPrivate * priv = self->priv;
  GumJscScope scope;

  g_assert (priv->ctx != NULL);

  _gum_jsc_scope_enter (&scope, &priv->core);

  if (priv->flavor == GUM_SCRIPT_FLAVOR_USER)
    _gum_jsc_stalker_flush (&priv->stalker);
  _gum_jsc_core_flush (&priv->core);

  if (priv->flavor == GUM_SCRIPT_FLAVOR_USER)
  {
    _gum_jsc_instruction_dispose (&priv->instruction);
    _gum_jsc_symbol_dispose (&priv->symbol);
    _gum_jsc_stalker_dispose (&priv->stalker);
    _gum_jsc_interceptor_dispose (&priv->interceptor);
    _gum_jsc_socket_dispose (&priv->socket);
    _gum_jsc_file_dispose (&priv->file);
    _gum_jsc_module_dispose (&priv->module);
    _gum_jsc_thread_dispose (&priv->thread);
    _gum_jsc_process_dispose (&priv->process);
    _gum_jsc_memory_dispose (&priv->memory);
  }
  else
  {
    _gum_jsc_kernel_dispose (&priv->kernel);
  }
  _gum_jsc_polyfill_dispose (&priv->polyfill);
  _gum_jsc_core_dispose (&priv->core);

  _gum_jsc_scope_leave (&scope);

  JSGlobalContextRelease (priv->ctx);
  priv->ctx = NULL;

  if (priv->flavor == GUM_SCRIPT_FLAVOR_USER)
  {
    _gum_jsc_instruction_finalize (&priv->instruction);
    _gum_jsc_symbol_finalize (&priv->symbol);
    _gum_jsc_stalker_finalize (&priv->stalker);
    _gum_jsc_interceptor_finalize (&priv->interceptor);
    _gum_jsc_socket_finalize (&priv->socket);
    _gum_jsc_file_finalize (&priv->file);
    _gum_jsc_module_finalize (&priv->module);
    _gum_jsc_thread_finalize (&priv->thread);
    _gum_jsc_process_finalize (&priv->process);
    _gum_jsc_memory_finalize (&priv->memory);
  }
  else
  {
    _gum_jsc_kernel_finalize (&priv->kernel);
  }
  _gum_jsc_polyfill_finalize (&priv->polyfill);
  _gum_jsc_core_finalize (&priv->core);

  priv->loaded = FALSE;
}

static void
gum_jsc_script_load (GumScript * script,
                     GCancellable * cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
  GumJscScript * self = GUM_JSC_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new (gum_jsc_script_do_load, self, cancellable,
      callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_jsc_script_backend_get_scheduler (self->priv->backend));
  g_object_unref (task);
}

static void
gum_jsc_script_load_finish (GumScript * script,
                            GAsyncResult * result)
{
  (void) script;

  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_jsc_script_load_sync (GumScript * script,
                          GCancellable * cancellable)
{
  GumJscScript * self = GUM_JSC_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new (gum_jsc_script_do_load, self, cancellable, NULL,
      NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_jsc_script_backend_get_scheduler (self->priv->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_jsc_script_do_load (GumScriptTask * task,
                        gpointer source_object,
                        gpointer task_data,
                        GCancellable * cancellable)
{
  GumJscScript * self = GUM_JSC_SCRIPT (source_object);
  GumJscScriptPrivate * priv = self->priv;

  if (priv->ctx == NULL)
  {
    gboolean created;

    created = gum_jsc_script_create_context (self, NULL);
    g_assert (created);
  }

  if (!priv->loaded)
  {
    JSStringRef source, url;
    GumJscScope scope;

    priv->loaded = TRUE;

    source = JSStringCreateWithUTF8CString (priv->source);
    url = gum_jsc_script_create_url (self);

    _gum_jsc_scope_enter (&scope, &priv->core);

    JSEvaluateScript (priv->ctx, source, JSContextGetGlobalObject (priv->ctx),
        url, 1, &scope.exception);

    _gum_jsc_scope_leave (&scope);

    JSStringRelease (url);
    JSStringRelease (source);
  }

  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_jsc_script_unload (GumScript * script,
                       GCancellable * cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
  GumJscScript * self = GUM_JSC_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new (gum_jsc_script_do_unload, self, cancellable,
      callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_jsc_script_backend_get_scheduler (self->priv->backend));
  g_object_unref (task);
}

static void
gum_jsc_script_unload_finish (GumScript * script,
                              GAsyncResult * result)
{
  (void) script;

  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_jsc_script_unload_sync (GumScript * script,
                            GCancellable * cancellable)
{
  GumJscScript * self = GUM_JSC_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new (gum_jsc_script_do_unload, self, cancellable, NULL,
      NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_jsc_script_backend_get_scheduler (self->priv->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_jsc_script_do_unload (GumScriptTask * task,
                          gpointer source_object,
                          gpointer task_data,
                          GCancellable * cancellable)
{
  GumJscScript * self = GUM_JSC_SCRIPT (source_object);
  GumJscScriptPrivate * priv = self->priv;

  if (priv->loaded)
  {
    priv->loaded = FALSE;

    gum_jsc_script_destroy_context (self);
  }

  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_jsc_script_set_message_handler (GumScript * script,
                                    GumScriptMessageHandler handler,
                                    gpointer data,
                                    GDestroyNotify data_destroy)
{
  GumJscScript * self = GUM_JSC_SCRIPT (script);
  GumJscScriptPrivate * priv = self->priv;

  if (priv->message_handler_data_destroy != NULL)
    priv->message_handler_data_destroy (priv->message_handler_data);
  priv->message_handler = handler;
  priv->message_handler_data = data;
  priv->message_handler_data_destroy = data_destroy;
}

static void
gum_jsc_script_post_message (GumScript * script,
                             const gchar * message)
{
  GumJscScript * self = GUM_JSC_SCRIPT (script);

  GumPostMessageData * d = g_slice_new (GumPostMessageData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);

  gum_script_scheduler_push_job_on_js_thread (
      gum_jsc_script_backend_get_scheduler (self->priv->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_jsc_script_do_post_message, d,
      (GDestroyNotify) gum_jsc_post_message_data_free, NULL);
}

static void
gum_jsc_script_do_post_message (GumPostMessageData * d)
{
  _gum_jsc_core_post_message (&d->script->priv->core, d->message);
}

static void
gum_jsc_post_message_data_free (GumPostMessageData * d)
{
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumPostMessageData, d);
}

static GumStalker *
gum_jsc_script_get_stalker (GumScript * script)
{
  GumJscScript * self = GUM_JSC_SCRIPT (script);

  return _gum_jsc_stalker_get (&self->priv->stalker);
}

static void
gum_jsc_script_on_enter (GumInvocationListener * listener,
                         GumInvocationContext * context)
{
  GumJscScript * self = GUM_JSC_SCRIPT_CAST (listener);

  _gum_jsc_interceptor_on_enter (&self->priv->interceptor, context);
}

static void
gum_jsc_script_on_leave (GumInvocationListener * listener,
                         GumInvocationContext * context)
{
  GumJscScript * self = GUM_JSC_SCRIPT_CAST (listener);

  _gum_jsc_interceptor_on_leave (&self->priv->interceptor, context);
}

static void
gum_jsc_script_emit_message (GumJscScript * self,
                             const gchar * message,
                             GBytes * data)
{
  GumEmitMessageData * d = g_slice_new (GumEmitMessageData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  GSource * source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_jsc_script_do_emit_message,
      d,
      (GDestroyNotify) gum_jsc_emit_message_data_free);
  g_source_attach (source, self->priv->main_context);
  g_source_unref (source);
}

static gboolean
gum_jsc_script_do_emit_message (GumEmitMessageData * d)
{
  GumJscScript * self = d->script;
  GumJscScriptPrivate * priv = self->priv;

  if (priv->message_handler != NULL)
  {
    priv->message_handler (GUM_SCRIPT (self), d->message, d->data,
        priv->message_handler_data);
  }

  return FALSE;
}

static void
gum_jsc_emit_message_data_free (GumEmitMessageData * d)
{
  g_bytes_unref (d->data);
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumEmitMessageData, d);
}

void
_gumjs_panic (JSContextRef ctx,
              JSValueRef exception)
{
  gchar * message, * stack;

  message = _gumjs_string_from_value (ctx, exception);
  stack = _gumjs_object_get_string (ctx, (JSObjectRef) exception, "stack");
  g_critical ("%s\n%s", message, stack);
  g_free (stack);
  g_free (message);

  abort ();
}
