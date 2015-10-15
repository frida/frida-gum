/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscript.h"

#include "guminvocationlistener.h"
#import "gumjscript-runtime.h"
#import "gumjscriptcore.h"

#import <JavaScriptCore/JavaScriptCore.h>

typedef struct _GumScriptEmitMessageData GumScriptEmitMessageData;

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

  JSVirtualMachine * vm;
  JSContext * context;
  GumScriptCore * core;
  gboolean loaded;

  GumScriptMessageHandler message_handler;
  gpointer message_handler_data;
  GDestroyNotify message_handler_data_destroy;

  GumStalker * stalker;
};

struct _GumScriptEmitMessageData
{
  GumScript * script;
  gchar * message;
  GBytes * data;
};

static void gum_script_listener_iface_init (gpointer g_iface,
    gpointer iface_data);

static void gum_script_dispose (GObject * object);
static void gum_script_finalize (GObject * object);
static void gum_script_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_script_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);
static void gum_script_destroy_context (GumScript * self);

static void gum_script_emit_message (GumScript * self,
    const gchar * message, GBytes * data);
static gboolean gum_script_do_emit_message (GumScriptEmitMessageData * d);
static void gum_script_emit_message_data_free (GumScriptEmitMessageData * d);

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
    gum_script_unload_sync (self, NULL);

  g_clear_pointer (&priv->stalker, g_object_unref);

  g_clear_pointer (&priv->main_context, g_main_context_unref);

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

static gboolean
gum_script_create_context (GumScript * self,
                           GError ** error)
{
  GumScriptPrivate * priv = self->priv;

  g_assert (priv->context == nil);

  @autoreleasepool
  {
    priv->vm = [JSVirtualMachine new];
    priv->context = [[JSContext alloc] initWithVirtualMachine:priv->vm];

    [priv->context setExceptionHandler:^(JSContext * context, JSValue * value)
    {
      NSLog (@"%@", value);
    }];

    priv->core = [[GumScriptCore alloc] initWithScript:self
                                               emitter:gum_script_emit_message
                                               context:priv->context];

    JSStringRef source = JSStringCreateWithUTF8CString (priv->source);

    gchar * url_str = g_strconcat (priv->name, ".js", NULL);
    JSStringRef url = JSStringCreateWithUTF8CString (url_str);
    g_free (url_str);

    JSValueRef ex;
    bool valid = JSCheckScriptSyntax (priv->context.JSGlobalContextRef, source,
        url, 1, &ex);

    JSStringRelease (url);
    JSStringRelease (source);

    if (!valid)
    {
      JSValue * exception = [JSValue valueWithJSValueRef:ex
                                               inContext:priv->context];
      NSDictionary * properties = [exception toObject];
      NSNumber * line = [properties objectForKey:@"line"];
      g_set_error (error,
          G_IO_ERROR,
          G_IO_ERROR_FAILED,
          "Script(line %d): %s",
          [line intValue],
          [exception toString].UTF8String);

      gum_script_destroy_context (self);

      return FALSE;
    }
  }

  return TRUE;
}

static void
gum_script_destroy_context (GumScript * self)
{
  GumScriptPrivate * priv = self->priv;

  g_assert (priv->context != nil);

  [priv->core release];
  priv->core = nil;

  [priv->context release];
  priv->context = nil;

  [priv->vm release];
  priv->vm = nil;

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
  GTask * task;
  GError * error = NULL;
  GumScript * script;

  task = g_task_new (NULL, cancellable, callback, user_data);
  script = gum_script_from_string_sync (name, source, flavor, cancellable,
      &error);
  if (script != NULL)
    g_task_return_pointer (task, script, g_object_unref);
  else
    g_task_return_error (task, error);
  g_object_unref (task);
}

GumScript *
gum_script_from_string_finish (GAsyncResult * result,
                               GError ** error)
{
  return GUM_SCRIPT (g_task_propagate_pointer (G_TASK (result), error));
}

GumScript *
gum_script_from_string_sync (const gchar * name,
                             const gchar * source,
                             GumScriptFlavor flavor,
                             GCancellable * cancellable,
                             GError ** error)
{
  GumScript * script;

  script = GUM_SCRIPT (g_object_new (GUM_TYPE_SCRIPT,
      "name", name,
      "source", source,
      "flavor", flavor,
      "main-context", g_main_context_get_thread_default (),
      NULL));

  if (!gum_script_create_context (script, error))
  {
    g_object_unref (script);
    script = NULL;
  }

  return script;
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
  GTask * task;

  task = g_task_new (NULL, cancellable, callback, user_data);
  gum_script_load_sync (self, cancellable);
  g_task_return_pointer (task, NULL, NULL);
  g_object_unref (task);
}

void
gum_script_load_finish (GumScript * self,
                        GAsyncResult * result)
{
  GError * error = NULL;
  g_task_propagate_pointer (G_TASK (result), &error);
  g_clear_error (&error);
}

void
gum_script_load_sync (GumScript * self,
                      GCancellable * cancellable)
{
  GumScriptPrivate * priv = self->priv;

  if (priv->context == nil)
  {
    gboolean created;

    created = gum_script_create_context (self, NULL);
    g_assert (created);
  }

  if (!priv->loaded)
  {
    priv->loaded = TRUE;

    @autoreleasepool
    {
      [GumScriptBundle load:gum_jscript_runtime_sources
                intoContext:priv->context];

      NSString * source = [NSString stringWithUTF8String:priv->source];

      NSString * filename = [[NSString stringWithUTF8String:priv->name]
                                    stringByAppendingString:@".js"];
      NSURL * url = [NSURL URLWithString:
          [@"file:///" stringByAppendingString:filename]];

      [priv->context evaluateScript:source
                      withSourceURL:url];
    }
  }
}

void
gum_script_unload (GumScript * self,
                   GCancellable * cancellable,
                   GAsyncReadyCallback callback,
                   gpointer user_data)
{
  GTask * task;

  task = g_task_new (NULL, cancellable, callback, user_data);
  gum_script_unload_sync (self, cancellable);
  g_task_return_pointer (task, NULL, NULL);
  g_object_unref (task);
}

void
gum_script_unload_finish (GumScript * self,
                          GAsyncResult * result)
{
  GError * error = NULL;
  g_task_propagate_pointer (G_TASK (result), &error);
  g_clear_error (&error);
}

void
gum_script_unload_sync (GumScript * self,
                        GCancellable * cancellable)
{
  GumScriptPrivate * priv = self->priv;

  if (priv->loaded)
  {
    priv->loaded = FALSE;

    gum_script_destroy_context (self);
  }
}

void
gum_script_post_message (GumScript * self,
                         const gchar * message)
{
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

