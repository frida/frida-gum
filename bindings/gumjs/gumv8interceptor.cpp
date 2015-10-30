/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8interceptor.h"

#include "gumscript-priv.h"
#include "gumv8scope.h"

#include <gum/gum-init.h>
#include <gum/gumtls.h>
#include <errno.h>

#ifdef G_OS_WIN32
# define GUM_SYSTEM_ERROR_FIELD "lastError"
#else
# define GUM_SYSTEM_ERROR_FIELD "errno"
#endif

#define GUM_IC_INVOCATION   0
#define GUM_IC_DEPTH        1
#define GUM_IC_CPU          2

#define GUM_ARGS_INVOCATION 0

#define GUM_RV_VALUE        0
#define GUM_RV_INVOCATION   1

using namespace v8;

typedef struct _GumV8AttachEntry GumV8AttachEntry;
typedef struct _GumV8ReplaceEntry GumV8ReplaceEntry;

struct _GumV8AttachEntry
{
  GumPersistent<Function>::type * on_enter;
  GumPersistent<Function>::type * on_leave;
};

struct _GumV8ReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  GumPersistent<Value>::type * replacement;
};

static void gum_v8_interceptor_adjust_ignore_level_unlocked (
    GumThreadId thread_id, gint adjustment, GumInterceptor * interceptor);
static gboolean gum_flush_pending_unignores (gpointer user_data);

static Local<Object> gum_v8_interceptor_create_invocation_context_object (
    GumV8Interceptor * self, GumInvocationContext * context, int32_t depth);
static void gum_v8_interceptor_detach_cpu_context (
    GumV8Interceptor * self, Handle<Object> invocation_context);

static void gum_v8_interceptor_on_attach (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_interceptor_on_detach_all (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_interceptor_detach_all (GumV8Interceptor * self);
static void gum_v8_interceptor_on_replace (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_interceptor_on_revert (
    const FunctionCallbackInfo<Value> & info);
static void gum_v8_attach_entry_free (GumV8AttachEntry * entry);
static void gum_v8_replace_entry_free (GumV8ReplaceEntry * entry);

static void gumjs_invocation_context_on_get_return_address (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_context_on_get_context (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_context_on_get_system_error (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_context_on_set_system_error (
    Local<String> property, Local<Value> value,
    const PropertyCallbackInfo<void> & info);
static void gumjs_invocation_context_on_get_thread_id (
    Local<String> property, const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_context_on_get_depth (
    Local<String> property, const PropertyCallbackInfo<Value> & info);

static void gumjs_invocation_args_on_get_nth (uint32_t index,
    const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_args_on_set_nth (uint32_t index,
    Local<Value> value, const PropertyCallbackInfo<Value> & info);

static void gumjs_invocation_return_value_on_replace (
    const FunctionCallbackInfo<Value> & info);

static GHashTable * gum_ignored_threads = NULL;
static GSList * gum_pending_unignores = NULL;
static GSource * gum_pending_timeout = NULL;
static GumInterceptor * gum_interceptor_instance = NULL;
static GRWLock gum_ignored_lock;

static void
gum_ignored_threads_deinit (void)
{
  if (gum_pending_timeout != NULL)
  {
    g_source_destroy (gum_pending_timeout);
    g_source_unref (gum_pending_timeout);
    gum_pending_timeout = NULL;
  }
  g_slist_free (gum_pending_unignores);
  gum_pending_unignores = NULL;

  g_object_unref (gum_interceptor_instance);
  gum_interceptor_instance = NULL;

  g_hash_table_unref (gum_ignored_threads);
  gum_ignored_threads = NULL;
}

static void
gum_v8_interceptor_adjust_ignore_level (GumThreadId thread_id,
                                        gint adjustment)
{
  GumInterceptor * interceptor;

  interceptor = gum_interceptor_obtain ();
  gum_interceptor_ignore_current_thread (interceptor);

  g_rw_lock_writer_lock (&gum_ignored_lock);
  gum_v8_interceptor_adjust_ignore_level_unlocked (thread_id, adjustment,
      interceptor);
  g_rw_lock_writer_unlock (&gum_ignored_lock);

  gum_interceptor_unignore_current_thread (interceptor);
  g_object_unref (interceptor);
}

static void
gum_v8_interceptor_adjust_ignore_level_unlocked (GumThreadId thread_id,
                                                 gint adjustment,
                                                 GumInterceptor * interceptor)
{
  gpointer thread_id_ptr = GSIZE_TO_POINTER (thread_id);
  gint level;

  if (G_UNLIKELY (gum_ignored_threads == NULL))
  {
    gum_ignored_threads = g_hash_table_new_full (NULL, NULL, NULL, NULL);

    gum_interceptor_instance = interceptor;
    g_object_ref (interceptor);

    _gum_register_destructor (gum_ignored_threads_deinit);
  }

  level = GPOINTER_TO_INT (
      g_hash_table_lookup (gum_ignored_threads, thread_id_ptr));
  level += adjustment;

  if (level > 0)
  {
    g_hash_table_insert (gum_ignored_threads, thread_id_ptr,
        GINT_TO_POINTER (level));
  }
  else
  {
    g_hash_table_remove (gum_ignored_threads, thread_id_ptr);
  }
}

void
gum_v8_script_ignore (GumThreadId thread_id)
{
  gum_v8_interceptor_adjust_ignore_level (thread_id, 1);
}

void
gum_v8_script_unignore (GumThreadId thread_id)
{
  gum_v8_interceptor_adjust_ignore_level (thread_id, -1);
}

void
gum_v8_script_unignore_later (GumThreadId thread_id)
{
  GMainContext * main_context;
  GumInterceptor * interceptor;
  GSource * source;

  main_context = gum_script_scheduler_get_js_context (
      gum_v8_script_get_platform ()->GetScheduler ());

  interceptor = gum_interceptor_obtain ();
  gum_interceptor_ignore_current_thread (interceptor);

  g_rw_lock_writer_lock (&gum_ignored_lock);

  gum_pending_unignores = g_slist_prepend (gum_pending_unignores,
      GSIZE_TO_POINTER (thread_id));
  source = gum_pending_timeout;
  gum_pending_timeout = NULL;

  g_rw_lock_writer_unlock (&gum_ignored_lock);

  if (source != NULL)
  {
    g_source_destroy (source);
    g_source_unref (source);
  }
  source = g_timeout_source_new_seconds (5);
  g_source_set_callback (source, gum_flush_pending_unignores, source, NULL);
  g_source_attach (source, main_context);

  g_rw_lock_writer_lock (&gum_ignored_lock);

  if (gum_pending_timeout == NULL)
  {
    gum_pending_timeout = source;
    source = NULL;
  }

  g_rw_lock_writer_unlock (&gum_ignored_lock);

  if (source != NULL)
  {
    g_source_destroy (source);
    g_source_unref (source);
  }

  gum_interceptor_unignore_current_thread (interceptor);
  g_object_unref (interceptor);
}

static gboolean
gum_flush_pending_unignores (gpointer user_data)
{
  GSource * source = (GSource *) user_data;
  GumInterceptor * interceptor;

  interceptor = gum_interceptor_obtain ();
  gum_interceptor_ignore_current_thread (interceptor);

  g_rw_lock_writer_lock (&gum_ignored_lock);

  if (gum_pending_timeout == source)
  {
    g_source_unref (gum_pending_timeout);
    gum_pending_timeout = NULL;
  }

  while (gum_pending_unignores != NULL)
  {
    GumThreadId thread_id;

    thread_id = GPOINTER_TO_SIZE (gum_pending_unignores->data);
    gum_pending_unignores = g_slist_delete_link (gum_pending_unignores,
        gum_pending_unignores);
    gum_v8_interceptor_adjust_ignore_level_unlocked (thread_id, -1,
        interceptor);
  }

  g_rw_lock_writer_unlock (&gum_ignored_lock);

  gum_interceptor_unignore_current_thread (interceptor);
  g_object_unref (interceptor);

  return FALSE;
}

gboolean
gum_v8_script_is_ignoring (GumThreadId thread_id)
{
  gboolean is_ignored;

  g_rw_lock_reader_lock (&gum_ignored_lock);

  is_ignored = gum_ignored_threads != NULL &&
      g_hash_table_contains (gum_ignored_threads, GSIZE_TO_POINTER (thread_id));

  g_rw_lock_reader_unlock (&gum_ignored_lock);

  return is_ignored;
}

void
_gum_v8_interceptor_init (GumV8Interceptor * self,
                          GumV8Core * core,
                          Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->attach_entries = g_queue_new ();
  self->replacement_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      reinterpret_cast<GDestroyNotify> (gum_v8_replace_entry_free));

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> interceptor = ObjectTemplate::New (isolate);
  interceptor->Set (String::NewFromUtf8 (isolate, "_attach"),
      FunctionTemplate::New (isolate, gum_v8_interceptor_on_attach,
      data));
  interceptor->Set (String::NewFromUtf8 (isolate, "detachAll"),
      FunctionTemplate::New (isolate, gum_v8_interceptor_on_detach_all,
      data));
  interceptor->Set (String::NewFromUtf8 (isolate, "_replace"),
      FunctionTemplate::New (isolate, gum_v8_interceptor_on_replace,
      data));
  interceptor->Set (String::NewFromUtf8 (isolate, "revert"),
      FunctionTemplate::New (isolate, gum_v8_interceptor_on_revert,
      data));
  scope->Set (String::NewFromUtf8 (isolate, "Interceptor"), interceptor);
}

void
_gum_v8_interceptor_realize (GumV8Interceptor * self)
{
  Isolate * isolate = self->core->isolate;

  Local<External> data (External::New (isolate, self));

  Handle<ObjectTemplate> context = ObjectTemplate::New (isolate);
  context->SetInternalFieldCount (3);
  context->SetAccessor (String::NewFromUtf8 (isolate, "returnAddress"),
      gumjs_invocation_context_on_get_return_address, NULL, data);
  context->SetAccessor (String::NewFromUtf8 (isolate, "context"),
      gumjs_invocation_context_on_get_context, NULL, data);
  context->SetAccessor (String::NewFromUtf8 (isolate, GUM_SYSTEM_ERROR_FIELD),
      gumjs_invocation_context_on_get_system_error,
      gumjs_invocation_context_on_set_system_error);
  context->SetAccessor (String::NewFromUtf8 (isolate, "threadId"),
      gumjs_invocation_context_on_get_thread_id);
  context->SetAccessor (String::NewFromUtf8 (isolate, "depth"),
      gumjs_invocation_context_on_get_depth);
  Local<Object> context_value = context->NewInstance ();
  context_value->SetAlignedPointerInInternalField (GUM_IC_CPU, NULL);
  self->invocation_context_value =
      new GumPersistent<Object>::type (isolate, context_value);

  Handle<ObjectTemplate> args = ObjectTemplate::New (isolate);
  args->SetInternalFieldCount (1);
  args->SetIndexedPropertyHandler (
      gumjs_invocation_args_on_get_nth,
      gumjs_invocation_args_on_set_nth,
      0, 0, 0,
      data);
  self->invocation_args_value =
      new GumPersistent<Object>::type (isolate, args->NewInstance ());

  Local<FunctionTemplate> return_value = FunctionTemplate::New (isolate);
  return_value->SetClassName (String::NewFromUtf8 (isolate, "ReturnValue"));
  Local<FunctionTemplate> native_pointer (Local<FunctionTemplate>::New (isolate,
      *self->core->native_pointer));
  return_value->Inherit (native_pointer);
  return_value->PrototypeTemplate ()->Set (
      String::NewFromUtf8 (isolate, "replace"), FunctionTemplate::New (isolate,
      gumjs_invocation_return_value_on_replace, data));
  return_value->InstanceTemplate ()->SetInternalFieldCount (2);
  self->invocation_return_value = new GumPersistent<Object>::type (isolate, 
      return_value->GetFunction ()->NewInstance ());
}

void
_gum_v8_interceptor_dispose (GumV8Interceptor * self)
{
  gum_v8_interceptor_detach_all (self);

  g_hash_table_remove_all (self->replacement_by_address);

  delete self->invocation_return_value;
  self->invocation_return_value = NULL;

  delete self->invocation_args_value;
  self->invocation_args_value = NULL;

  delete self->invocation_context_value;
  self->invocation_context_value = NULL;
}

void
_gum_v8_interceptor_finalize (GumV8Interceptor * self)
{
  g_queue_free (self->attach_entries);
  g_hash_table_unref (self->replacement_by_address);

  g_object_unref (self->interceptor);
  self->interceptor = NULL;
}

void
_gum_v8_interceptor_on_enter (GumV8Interceptor * self,
                              GumInvocationContext * context)
{
  if (gum_v8_script_is_ignoring (gum_invocation_context_get_thread_id (context)))
    return;

  GumV8AttachEntry * entry = static_cast<GumV8AttachEntry *> (
      gum_invocation_context_get_listener_function_data (context));
  int32_t * depth = GUM_LINCTX_GET_THREAD_DATA (context, int32_t);

  if (entry->on_enter != nullptr)
  {
    GumV8Core * core = self->core;
    ScriptScope scope (core->script);
    Isolate * isolate = core->isolate;

    Local<Function> on_enter (Local<Function>::New (isolate, *entry->on_enter));

    Local<Object> receiver (
        gum_v8_interceptor_create_invocation_context_object (self, context,
        *depth));

    Local<Object> invocation_args_value (Local<Object>::New (isolate,
        *self->invocation_args_value));
    Local<Object> args (invocation_args_value->Clone ());
    args->SetAlignedPointerInInternalField (GUM_ARGS_INVOCATION, context);
    Handle<Value> argv[] = { args };

    on_enter->Call (receiver, 1, argv);

    gum_v8_interceptor_detach_cpu_context (self, receiver);

    if (entry->on_leave != nullptr)
    {
      GumPersistent<Value>::type * persistent_receiver =
          new GumPersistent<Value>::type (isolate, receiver);
      *GUM_LINCTX_GET_FUNC_INVDATA (context,
          GumPersistent<Value>::type *) = persistent_receiver;
    }
  }

  (*depth)++;
}

void
_gum_v8_interceptor_on_leave (GumV8Interceptor * self,
                              GumInvocationContext * context)
{
  if (gum_v8_script_is_ignoring (gum_invocation_context_get_thread_id (context)))
    return;

  GumV8AttachEntry * entry = static_cast<GumV8AttachEntry *> (
      gum_invocation_context_get_listener_function_data (context));
  int32_t * depth = GUM_LINCTX_GET_THREAD_DATA (context, int32_t);

  (*depth)--;

  if (entry->on_leave != nullptr)
  {
    ScriptScope scope (self->core->script);
    Isolate * isolate = self->core->isolate;

    Local<Function> on_leave (Local<Function>::New (isolate, *entry->on_leave));

    GumPersistent<Object>::type * persistent_receiver =
        (entry->on_enter != nullptr)
        ? *GUM_LINCTX_GET_FUNC_INVDATA (context, GumPersistent<Object>::type *)
        : nullptr;
    Local<Object> receiver ((persistent_receiver != nullptr)
        ? Local<Object>::New (isolate, *persistent_receiver)
        : gum_v8_interceptor_create_invocation_context_object (self,
        context, *depth));

    Local<Object> invocation_return_value (Local<Object>::New (isolate,
        *self->invocation_return_value));
    Local<Object> return_value (invocation_return_value->Clone ());
    return_value->SetInternalField (GUM_RV_VALUE, External::New (isolate,
        gum_invocation_context_get_return_value (context)));
    return_value->SetAlignedPointerInInternalField (GUM_RV_INVOCATION, context);

    Handle<Value> argv[] = { return_value };
    on_leave->Call (receiver, 1, argv);

    gum_v8_interceptor_detach_cpu_context (self, receiver);

    delete persistent_receiver;
  }
}

static Local<Object>
gum_v8_interceptor_create_invocation_context_object (
    GumV8Interceptor * self,
    GumInvocationContext * context,
    int32_t depth)
{
  Isolate * isolate = self->core->isolate;
  Local<Object> invocation_context_value (Local<Object>::New (isolate,
      *self->invocation_context_value));
  Local<Object> result (invocation_context_value->Clone ());
  result->SetAlignedPointerInInternalField (GUM_IC_INVOCATION, context);
  result->SetInternalField (GUM_IC_DEPTH, Integer::New (isolate, depth));
  return result;
}

static void
gum_v8_interceptor_detach_cpu_context (GumV8Interceptor * self,
                                       Handle<Object> invocation_context)
{
  GumPersistent<Object>::type * cpu_context =
      static_cast<GumPersistent<Object>::type *> (
          invocation_context->GetAlignedPointerFromInternalField (GUM_IC_CPU));
  if (cpu_context != NULL)
  {
    _gum_v8_cpu_context_free_later (cpu_context, self->core);
    invocation_context->SetAlignedPointerInInternalField (GUM_IC_CPU, NULL);
  }
}

/*
 * Prototype:
 * [PRIVATE] Interceptor._attach(target, callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_interceptor_on_attach (const FunctionCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  GumV8Core * core = self->core;
  Isolate * isolate = core->isolate;

  gpointer target;
  if (!_gum_v8_native_pointer_get (info[0], &target, self->core))
    return;

  Local<Value> callbacks_value = info[1];
  if (!callbacks_value->IsObject ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        "Interceptor.attach: second argument must be a callback object")));
    return;
  }

  Local<Function> on_enter, on_leave;

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_v8_callbacks_get_opt (callbacks, "onEnter", &on_enter, core))
    return;
  if (!_gum_v8_callbacks_get_opt (callbacks, "onLeave", &on_leave, core))
    return;

  GumV8AttachEntry * entry = g_slice_new0 (GumV8AttachEntry);
  if (!on_enter.IsEmpty ())
    entry->on_enter = new GumPersistent<Function>::type (isolate, on_enter);
  if (!on_leave.IsEmpty ())
    entry->on_leave = new GumPersistent<Function>::type (isolate, on_leave);

  /*
   * TODO: Create a helper object implementing the listener interface,
   *       and allow each to be detached individually.
   */
  GumAttachReturn attach_ret = gum_interceptor_attach_listener (
      self->interceptor, target, GUM_INVOCATION_LISTENER (self->core->script),
      entry);

  if (attach_ret == GUM_ATTACH_OK)
    g_queue_push_tail (self->attach_entries, entry);
  else
    gum_v8_attach_entry_free (entry);

  switch (attach_ret)
  {
    case GUM_ATTACH_OK:
      break;
    case GUM_ATTACH_WRONG_SIGNATURE:
    {
      gchar * message;

      message = g_strdup_printf ("unable to intercept function at %p; "
          "please file a bug", target);
      isolate->ThrowException (Exception::Error (String::NewFromUtf8 (
          isolate, message)));
      g_free (message);

      break;
    }
    case GUM_ATTACH_ALREADY_ATTACHED:
      isolate->ThrowException (Exception::Error (String::NewFromUtf8 (
          isolate, "already attached to this function")));
      break;
  }
}

/*
 * Prototype:
 * Interceptor.detachAll()
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_interceptor_on_detach_all (const FunctionCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());

  gum_v8_interceptor_detach_all (self);
}

static void
gum_v8_interceptor_detach_all (GumV8Interceptor * self)
{
  gum_interceptor_detach_listener (self->interceptor,
      GUM_INVOCATION_LISTENER (self->core->script));

  while (!g_queue_is_empty (self->attach_entries))
  {
    gum_v8_attach_entry_free (static_cast<GumV8AttachEntry *> (
        g_queue_pop_tail (self->attach_entries)));
  }
}

/*
 * Prototype:
 * [PRIVATE] Interceptor._replace(target, replacement)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_interceptor_on_replace (const FunctionCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;

  gpointer target;
  if (!_gum_v8_native_pointer_get (info[0], &target, self->core))
    return;

  gpointer replacement;
  if (!_gum_v8_native_pointer_get (info[1], &replacement, self->core))
    return;

  GumV8ReplaceEntry * entry = g_slice_new (GumV8ReplaceEntry);
  entry->interceptor = self->interceptor;
  entry->target = target;
  entry->replacement = new GumPersistent<Value>::type (isolate, info[1]);

  GumReplaceReturn replace_ret = gum_interceptor_replace_function (
      self->interceptor, target, replacement, NULL);

  if (replace_ret == GUM_REPLACE_OK)
  {
    g_hash_table_insert (self->replacement_by_address, target, entry);
  }
  else
  {
    delete entry->replacement;
    g_slice_free (GumV8ReplaceEntry, entry);
  }

  switch (replace_ret)
  {
    case GUM_REPLACE_OK:
      break;
    case GUM_REPLACE_WRONG_SIGNATURE:
    {
      gchar * message;

      message = g_strdup_printf ("unable to intercept function at %p; "
          "please file a bug", target);
      isolate->ThrowException (Exception::Error (String::NewFromUtf8 (
          isolate, message)));
      g_free (message);

      break;
    }
    case GUM_REPLACE_ALREADY_REPLACED:
      isolate->ThrowException (Exception::Error (String::NewFromUtf8 (
          isolate, "already replaced this function")));
      break;
  }
}

/*
 * Prototype:
 * Interceptor.revert(target)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_v8_interceptor_on_revert (const FunctionCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());

  gpointer target;
  if (!_gum_v8_native_pointer_get (info[0], &target, self->core))
    return;

  g_hash_table_remove (self->replacement_by_address, target);
}

static void
gum_v8_attach_entry_free (GumV8AttachEntry * entry)
{
  delete entry->on_enter;
  delete entry->on_leave;
  g_slice_free (GumV8AttachEntry, entry);
}

static void
gum_v8_replace_entry_free (GumV8ReplaceEntry * entry)
{
  gum_interceptor_revert_function (entry->interceptor, entry->target);
  delete entry->replacement;
  g_slice_free (GumV8ReplaceEntry, entry);
}

static void
gumjs_invocation_context_on_get_return_address (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_IC_INVOCATION));
  (void) property;
  gpointer return_address = gum_invocation_context_get_return_address (context);
  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (return_address, self->core));
}

static void
gumjs_invocation_context_on_get_context (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  Local<Object> instance = info.Holder ();
  Isolate * isolate = info.GetIsolate ();

  (void) property;

  GumPersistent<Object>::type * context =
      static_cast<GumPersistent<Object>::type *> (
          instance->GetAlignedPointerFromInternalField (GUM_IC_CPU));
  if (context == NULL)
  {
    GumInvocationContext * ic = static_cast<GumInvocationContext *> (
        instance->GetAlignedPointerFromInternalField (GUM_IC_INVOCATION));
    context = new GumPersistent<Object>::type (isolate,
        _gum_v8_cpu_context_new (ic->cpu_context, self->core));
    instance->SetAlignedPointerInInternalField (GUM_IC_CPU, context);
  }

  info.GetReturnValue ().Set (Local<Object>::New (isolate, *context));
}

static void
gumjs_invocation_context_on_get_system_error (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_IC_INVOCATION));
  (void) property;
  info.GetReturnValue ().Set (context->system_error);
}

static void
gumjs_invocation_context_on_set_system_error (
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void> & info)
{
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_IC_INVOCATION));
  (void) property;
  context->system_error = value->Int32Value ();
}

static void
gumjs_invocation_context_on_get_thread_id (
    Local<String> property,
    const PropertyCallbackInfo<Value> & info)
{
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_IC_INVOCATION));
  (void) property;
  info.GetReturnValue ().Set (gum_invocation_context_get_thread_id (context));
}

static void
gumjs_invocation_context_on_get_depth (Local<String> property,
                                       const PropertyCallbackInfo<Value> & info)
{
  int32_t depth = info.Holder ()->GetInternalField (GUM_IC_DEPTH)
      .As <Integer> ()->Int32Value ();
  (void) property;
  info.GetReturnValue ().Set (depth);
}

static void
gumjs_invocation_args_on_get_nth (uint32_t index,
                                  const PropertyCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  GumInvocationContext * ctx = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_ARGS_INVOCATION));
  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (
      gum_invocation_context_get_nth_argument (ctx, index), self->core));
}

static void
gumjs_invocation_args_on_set_nth (uint32_t index,
                                  Local<Value> value,
                                  const PropertyCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  GumInvocationContext * ctx = static_cast<GumInvocationContext *> (
      info.Holder ()->GetAlignedPointerFromInternalField (GUM_ARGS_INVOCATION));

  gpointer raw_value;
  if (!_gum_v8_native_pointer_get (value, &raw_value, self->core))
    return;

  gum_invocation_context_replace_nth_argument (ctx, index, raw_value);
}

static void
gumjs_invocation_return_value_on_replace (
    const FunctionCallbackInfo<Value> & info)
{
  GumV8Interceptor * self = static_cast<GumV8Interceptor *> (
      info.Data ().As<External> ()->Value ());
  Local<Object> holder (info.Holder ());
  GumInvocationContext * context = static_cast<GumInvocationContext *> (
      holder->GetAlignedPointerFromInternalField (GUM_RV_INVOCATION));

  gpointer value;
  Local<FunctionTemplate> native_pointer (
      Local<FunctionTemplate>::New (info.GetIsolate (),
      *self->core->native_pointer));
  if (native_pointer->HasInstance (info[0]))
    value = GUMJS_NATIVE_POINTER_VALUE (info[0].As<Object> ());
  else
    value = GSIZE_TO_POINTER (info[0].As<Integer> ()->Value ());
  gum_invocation_context_replace_return_value (context, value);
  holder->SetInternalField (GUM_RV_VALUE,
      External::New (info.GetIsolate (), value));
}
