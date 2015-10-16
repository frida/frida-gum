/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscript.h"

#include "guminvocationlistener.h"
#include "gumjscript-runtime.h"
#include "gumjscriptcore.h"
#include "gumscriptscheduler.h"
#include "gumscripttask.h"

#include <gum/gum-init.h>
#include <JavaScriptCore/JavaScriptCore.h>

typedef struct _GumScriptFromStringData GumScriptFromStringData;
typedef struct _GumScriptEmitMessageData GumScriptEmitMessageData;
typedef struct _GumScriptPostMessageData GumScriptPostMessageData;

enum
{
  PROP_0,
  PROP_NAME,
  PROP_SOURCE,
  PROP_FLAVOR,
  PROP_MAIN_CONTEXT
};

struct _GumScriptPrivate
{
  gchar * name;
  gchar * source;
  GumScriptFlavor flavor;
  GMainContext * main_context;

  JSGlobalContextRef ctx;
  GumScriptCore core;
  gboolean loaded;

  GumScriptMessageHandler message_handler;
  gpointer message_handler_data;
  GDestroyNotify message_handler_data_destroy;

  GumStalker * stalker;
};

struct _GumScriptFromStringData
{
  gchar * name;
  gchar * source;
  GumScriptFlavor flavor;
};

struct _GumScriptEmitMessageData
{
  GumScript * script;
  gchar * message;
  GBytes * data;
};

struct _GumScriptPostMessageData
{
  GumScript * script;
  gchar * message;
};

static GumScriptScheduler * gum_script_do_init (void);
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
    const gchar * source, GumScriptFlavor flavor, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static void gum_script_from_string_task_run (GumScriptTask * task,
    gpointer source_object, gpointer task_data, GCancellable * cancellable);
static void gum_script_from_string_data_free (GumScriptFromStringData * d);
static void gum_script_emit_message (GumScript * self,
    const gchar * message, GBytes * data);
static gboolean gum_script_do_emit_message (GumScriptEmitMessageData * d);
static void gum_script_emit_message_data_free (GumScriptEmitMessageData * d);
static void gum_script_do_load (GumScriptTask * task, gpointer source_object,
    gpointer task_data, GCancellable * cancellable);
static void gum_script_do_unload (GumScriptTask * task, gpointer source_object,
    gpointer task_data, GCancellable * cancellable);
static void gum_script_do_post_message (GumScriptPostMessageData * d);
static void gum_script_post_message_data_free (GumScriptPostMessageData * d);

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

static GumScriptScheduler *
gum_script_get_scheduler (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, (GThreadFunc) gum_script_do_init, NULL);

  return (GumScriptScheduler *) init_once.retval;
}

static GumScriptScheduler *
gum_script_do_init (void)
{
  GumScriptScheduler * scheduler;

  scheduler = gum_script_scheduler_new ();

  _gum_register_destructor (gum_script_do_deinit);

  return scheduler;
}

static void
gum_script_do_deinit (void)
{
  GumScriptScheduler * scheduler;

  scheduler = gum_script_get_scheduler ();
  g_object_unref (scheduler);
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

  priv->loaded = FALSE;

  priv->stalker = gum_stalker_new ();
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
    g_clear_pointer (&priv->stalker, g_object_unref);

    g_clear_pointer (&priv->main_context, g_main_context_unref);
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

static JSStringRef
gum_script_create_url (GumScript * self)
{
  JSStringRef url;
  gchar * str;

  str = g_strconcat ("file:///", self->priv->name, ".js", NULL);
  url = JSStringCreateWithUTF8CString (str);
  g_free (str);

  return url;
}

static gboolean
gum_script_create_context (GumScript * self,
                           GError ** error)
{
  GumScriptPrivate * priv = self->priv;
  JSClassDefinition def;
  JSClassRef global_class;
  JSGlobalContextRef ctx;
  JSStringRef source, url;
  JSValueRef exception;
  bool valid;
  JSObjectRef global;

  g_assert (priv->ctx == NULL);

  def = kJSClassDefinitionEmpty;
  def.className = "Context";
  global_class = JSClassCreate (&def);

  ctx = JSGlobalContextCreate (global_class);

  JSClassRelease (global_class);

  source = JSStringCreateWithUTF8CString (priv->source);
  url = gum_script_create_url (self);

  valid = JSCheckScriptSyntax (ctx, source, url, 1, &exception);

  JSStringRelease (url);
  JSStringRelease (source);

  if (!valid)
  {
    JSStringRef message;
    gchar * message_str;
    guint line;

    message = JSValueToStringCopy (ctx, exception, NULL);
    message_str = _gum_script_string_get (message);
    line = _gum_script_object_get_uint ((JSObjectRef) exception, "line",
        ctx);

    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "Script(line %u): %s",
        line,
        message_str);

    g_free (message_str);
    JSStringRelease (message);

    JSGlobalContextRelease (ctx);

    return FALSE;
  }

  priv->ctx = ctx;

  global = JSContextGetGlobalObject (ctx);

  _gum_script_core_init (&priv->core, self, gum_script_emit_message,
      gum_script_get_scheduler (), priv->ctx, global);

  _gum_script_core_realize (&priv->core);

  gum_script_bundle_load (gum_jscript_runtime_sources, priv->ctx);

  return TRUE;
}

static void
gum_script_destroy_context (GumScript * self)
{
  GumScriptPrivate * priv = self->priv;

  g_assert (priv->ctx != NULL);

  _gum_script_core_flush (&priv->core);

  _gum_script_core_dispose (&priv->core);

  _gum_script_core_finalize (&priv->core);

  JSGlobalContextRelease (priv->ctx);
  priv->ctx = NULL;

  priv->loaded = FALSE;
}

void
gum_script_from_string (const gchar * name,
                        const gchar * source,
                        GumScriptFlavor flavor,
                        GCancellable * cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
  GumScriptTask * task;

  task = gum_script_from_string_task_new (name, source, flavor, cancellable,
      callback, user_data);
  gum_script_task_run_in_js_thread (task, gum_script_get_scheduler ());
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
                             GumScriptFlavor flavor,
                             GCancellable * cancellable,
                             GError ** error)
{
  GumScript * script;
  GumScriptTask * task;

  task = gum_script_from_string_task_new (name, source, flavor, cancellable,
      NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task, gum_script_get_scheduler ());
  script = GUM_SCRIPT (gum_script_task_propagate_pointer (task, error));
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_script_from_string_task_new (const gchar * name,
                                 const gchar * source,
                                 GumScriptFlavor flavor,
                                 GCancellable * cancellable,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data)
{
  GumScriptFromStringData * d;
  GumScriptTask * task;

  d = g_slice_new (GumScriptFromStringData);
  d->name = g_strdup (name);
  d->source = g_strdup (source);
  d->flavor = flavor;

  task = gum_script_task_new (gum_script_from_string_task_run, NULL,
      cancellable, callback, user_data);
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
  GError * error = NULL;

  script = GUM_SCRIPT (g_object_new (GUM_TYPE_SCRIPT,
      "name", d->name,
      "source", d->source,
      "flavor", d->flavor,
      "main-context", gum_script_task_get_context (task),
      NULL));

  gum_script_create_context (script, &error);

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
  return self->priv->stalker;
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
                         GBytes * data)
{
  GumScriptEmitMessageData * d = g_slice_new (GumScriptEmitMessageData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

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
    priv->message_handler (self, d->message, d->data,
        priv->message_handler_data);
  }

  return FALSE;
}

static void
gum_script_emit_message_data_free (GumScriptEmitMessageData * d)
{
  g_bytes_unref (d->data);
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
  gum_script_task_run_in_js_thread (task, gum_script_get_scheduler ());
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
  gum_script_task_run_in_js_thread_sync (task, gum_script_get_scheduler ());
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

  if (priv->ctx == NULL)
  {
    gboolean created;

    created = gum_script_create_context (self, NULL);
    g_assert (created);
  }

  if (!priv->loaded)
  {
    JSStringRef source, url;
    JSValueRef result, exception;

    priv->loaded = TRUE;

    source = JSStringCreateWithUTF8CString (priv->source);
    url = gum_script_create_url (self);

    result = JSEvaluateScript (priv->ctx, source,
        JSContextGetGlobalObject (priv->ctx), url, 1, &exception);

    JSStringRelease (url);
    JSStringRelease (source);
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
  gum_script_task_run_in_js_thread (task, gum_script_get_scheduler ());
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
  gum_script_task_run_in_js_thread_sync (task, gum_script_get_scheduler ());
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

  if (priv->loaded)
  {
    priv->loaded = FALSE;

    gum_script_destroy_context (self);
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

  gum_script_scheduler_push_job_on_js_thread (gum_script_get_scheduler (),
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
}

void
gum_script_post_debug_message (const gchar * message)
{
}

static void
gum_script_on_enter (GumInvocationListener * listener,
                     GumInvocationContext * context)
{
}

static void
gum_script_on_leave (GumInvocationListener * listener,
                     GumInvocationContext * context)
{
}

