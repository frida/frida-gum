/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptinterceptor.h"

#include "gumjscript-priv.h"
#include "gumjscriptmacros.h"

#include <gum/gum-init.h>

#define GUM_SCRIPT_INVOCATION_CONTEXT(o) \
  ((GumScriptInvocationContext *) JSObjectGetPrivate (o))

#ifdef G_OS_WIN32
# define GUM_SYSTEM_ERROR_FIELD "lastError"
#else
# define GUM_SYSTEM_ERROR_FIELD "errno"
#endif

typedef struct _GumScriptInvocationContext GumScriptInvocationContext;
typedef struct _GumScriptInvocationReturnValue GumScriptInvocationReturnValue;
typedef struct _GumScriptAttachEntry GumScriptAttachEntry;
typedef struct _GumScriptReplaceEntry GumScriptReplaceEntry;

struct _GumScriptInvocationContext
{
  GumInvocationContext * handle;
  JSObjectRef cpu_context;
  gint depth;
};

struct _GumScriptInvocationReturnValue
{
  GumScriptNativePointer parent;
  GumInvocationContext * ic;
};

struct _GumScriptAttachEntry
{
  JSObjectRef on_enter;
  JSObjectRef on_leave;
  JSContextRef ctx;
};

struct _GumScriptReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  JSValueRef replacement;
  JSContextRef ctx;
};

GUMJS_DECLARE_FUNCTION (gumjs_interceptor_attach)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_detach_all)

static void gum_script_interceptor_detach_all (GumScriptInterceptor * self);

static void gum_script_attach_entry_free (GumScriptAttachEntry * entry);
static void gum_script_replace_entry_free (GumScriptReplaceEntry * entry);

static JSObjectRef gumjs_invocation_context_new (JSContextRef ctx,
    GumInvocationContext * handle, gint depth,
    GumScriptInterceptor * interceptor);
GUMJS_DECLARE_FINALIZER (gumjs_invocation_context_finalize)
static void gumjs_invocation_context_update_handle (JSObjectRef jic,
    GumInvocationContext * handle);
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_system_error)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_depth)

static JSObjectRef gumjs_invocation_args_new (JSContextRef ctx,
    GumInvocationContext * ic, GumScriptInterceptor * interceptor);
static void gumjs_invocation_args_update_context (JSValueRef value,
    GumInvocationContext * context);
GUMJS_DECLARE_GETTER (gumjs_invocation_args_get_property)
GUMJS_DECLARE_SETTER (gumjs_invocation_args_set_property)

static JSObjectRef gumjs_invocation_return_value_new (JSContextRef ctx,
    GumInvocationContext * ic, GumScriptInterceptor * interceptor);
static void gumjs_invocation_return_value_update_context (JSValueRef value,
    GumInvocationContext * ic);
GUMJS_DECLARE_FUNCTION (gumjs_invocation_return_value_replace)

GUMJS_DECLARE_FUNCTION (gumjs_interceptor_throw_not_yet_available)

static void gum_script_interceptor_adjust_ignore_level_unlocked (
    GumThreadId thread_id, gint adjustment, GumInterceptor * interceptor);
static gboolean gum_flush_pending_unignores (gpointer user_data);

static const JSStaticFunction gumjs_interceptor_functions[] =
{
  { "_attach", gumjs_interceptor_attach, GUMJS_RO },
  { "detachAll", gumjs_interceptor_detach_all, GUMJS_RO },
  { "_replace", gumjs_interceptor_throw_not_yet_available, GUMJS_RO },
  { "revert", gumjs_interceptor_throw_not_yet_available, GUMJS_RO },

  { NULL, NULL, 0 }
};

static const JSStaticValue gumjs_invocation_context_values[] =
{
  {
    "returnAddress",
    gumjs_invocation_context_get_return_address,
    NULL,
    GUMJS_RO
  },
  {
    "context",
    gumjs_invocation_context_get_cpu_context,
    NULL,
    GUMJS_RO
  },
  {
    GUM_SYSTEM_ERROR_FIELD,
    gumjs_invocation_context_get_system_error,
    gumjs_invocation_context_set_system_error,
    GUMJS_RW
  },
  {
    "depth",
    gumjs_invocation_context_get_depth,
    NULL,
    GUMJS_RO
  },

  { NULL, NULL, NULL, 0 }
};

static const JSStaticFunction gumjs_invocation_return_value_functions[] =
{
  { "replace", gumjs_invocation_return_value_replace, GUMJS_RO },

  { NULL, NULL, 0 }
};

static GHashTable * gum_ignored_threads = NULL;
static GSList * gum_pending_unignores = NULL;
static GSource * gum_pending_timeout = NULL;
static GumInterceptor * gum_interceptor_instance = NULL;
static GRWLock gum_ignored_lock;

void
_gum_script_interceptor_init (GumScriptInterceptor * self,
                              GumScriptCore * core,
                              JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef interceptor;

  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->attach_entries = g_queue_new ();
  self->replacement_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_script_replace_entry_free);

  def = kJSClassDefinitionEmpty;
  def.className = "Interceptor";
  def.staticFunctions = gumjs_interceptor_functions;
  klass = JSClassCreate (&def);
  interceptor = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, "Interceptor", interceptor);

  def = kJSClassDefinitionEmpty;
  def.className = "InvocationContext";
  def.staticValues = gumjs_invocation_context_values;
  def.finalize = gumjs_invocation_context_finalize;
  self->invocation_context = JSClassCreate (&def);

  def = kJSClassDefinitionEmpty;
  def.className = "InvocationArgs";
  def.getProperty = gumjs_invocation_args_get_property;
  def.setProperty = gumjs_invocation_args_set_property;
  self->invocation_args = JSClassCreate (&def);

  def = kJSClassDefinitionEmpty;
  def.className = "InvocationReturnValue";
  def.parentClass = core->native_pointer;
  def.staticFunctions = gumjs_invocation_return_value_functions;
  self->invocation_retval = JSClassCreate (&def);
}

void
_gum_script_interceptor_dispose (GumScriptInterceptor * self)
{
  gum_script_interceptor_detach_all (self);

  g_hash_table_remove_all (self->replacement_by_address);

  JSClassRelease (self->invocation_context);
  self->invocation_context = NULL;

  JSClassRelease (self->invocation_args);
  self->invocation_args = NULL;

  JSClassRelease (self->invocation_retval);
  self->invocation_retval = NULL;
}

void
_gum_script_interceptor_finalize (GumScriptInterceptor * self)
{
  g_queue_free (self->attach_entries);
  g_hash_table_unref (self->replacement_by_address);

  g_object_unref (self->interceptor);
  self->interceptor = NULL;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_attach)
{
  GumScriptInterceptor * self;
  GumScriptCore * core = args->core;
  gpointer target;
  JSObjectRef on_enter, on_leave;
  GumScriptAttachEntry * entry;
  GumAttachReturn attach_ret;

  self = JSObjectGetPrivate (this_object);

  if (!_gumjs_args_parse (args, "pF{onEnter?,onLeave?}",
      &target, &on_enter, &on_leave))
    return NULL;

  entry = g_slice_new (GumScriptAttachEntry);
  JSValueProtect (ctx, on_enter);
  entry->on_enter = on_enter;
  JSValueProtect (ctx, on_leave);
  entry->on_leave = on_leave;
  entry->ctx = core->ctx;

  attach_ret = gum_interceptor_attach_listener (self->interceptor, target,
      GUM_INVOCATION_LISTENER (core->script), entry);
  if (attach_ret != GUM_ATTACH_OK)
    goto unable_to_attach;

  g_queue_push_tail (self->attach_entries, entry);

  return JSValueMakeUndefined (ctx);

unable_to_attach:
  {
    gum_script_attach_entry_free (entry);

    switch (attach_ret)
    {
      case GUM_ATTACH_WRONG_SIGNATURE:
        _gumjs_throw (ctx, exception, "unable to intercept function at %p; "
            "please file a bug", target);
        break;
      case GUM_ATTACH_ALREADY_ATTACHED:
        _gumjs_throw (ctx, exception, "already attached to this function");
        break;
      default:
        g_assert_not_reached ();
    }

    return NULL;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_detach_all)
{
  GumScriptInterceptor * self;

  self = JSObjectGetPrivate (this_object);

  gum_script_interceptor_detach_all (self);

  return JSValueMakeUndefined (ctx);
}

static void
gum_script_interceptor_detach_all (GumScriptInterceptor * self)
{
  gum_interceptor_detach_listener (self->interceptor,
      GUM_INVOCATION_LISTENER (self->core->script));

  while (!g_queue_is_empty (self->attach_entries))
  {
    gum_script_attach_entry_free (g_queue_pop_tail (self->attach_entries));
  }
}

void
_gum_script_interceptor_on_enter (GumScriptInterceptor * self,
                                  GumInvocationContext * ic)
{
  GumScriptAttachEntry * entry;
  gint * depth;

  if (gum_script_is_ignoring (gum_invocation_context_get_thread_id (ic)))
    return;

  entry = gum_invocation_context_get_listener_function_data (ic);
  depth = GUM_LINCTX_GET_THREAD_DATA (ic, gint);

  if (entry->on_enter != NULL)
  {
    GumScriptCore * core = self->core;
    JSContextRef ctx = core->ctx;
    GumScriptScope scope;
    JSObjectRef jic;
    JSValueRef args;

    _gum_script_scope_enter (&scope, core);

    jic = gumjs_invocation_context_new (ctx, ic, *depth, self);
    args = gumjs_invocation_args_new (ctx, ic, self);

    JSObjectCallAsFunction (ctx, entry->on_enter, jic, 1, &args,
        &scope.exception);

    gumjs_invocation_args_update_context (args, NULL);
    gumjs_invocation_context_update_handle (jic, NULL);

    if (entry->on_leave != NULL)
    {
      JSValueProtect (ctx, jic);
      *GUM_LINCTX_GET_FUNC_INVDATA (ic, JSObjectRef) = jic;
    }

    _gum_script_scope_leave (&scope);
  }

  (*depth)++;
}

void
_gum_script_interceptor_on_leave (GumScriptInterceptor * self,
                                  GumInvocationContext * ic)
{
  GumScriptAttachEntry * entry;
  gint * depth;

  if (gum_script_is_ignoring (gum_invocation_context_get_thread_id (ic)))
    return;

  entry = gum_invocation_context_get_listener_function_data (ic);
  depth = GUM_LINCTX_GET_THREAD_DATA (ic, gint);

  (*depth)--;

  if (entry->on_leave != NULL)
  {
    GumScriptCore * core = self->core;
    JSContextRef ctx = core->ctx;
    GumScriptScope scope;
    JSObjectRef jic;
    JSValueRef retval;

    _gum_script_scope_enter (&scope, core);

    jic = (entry->on_enter != NULL)
        ? *GUM_LINCTX_GET_FUNC_INVDATA (ic, JSObjectRef)
        : NULL;
    if (jic != NULL)
    {
      JSValueUnprotect (ctx, jic);
      gumjs_invocation_context_update_handle (jic, ic);
    }
    else
    {
      jic = gumjs_invocation_context_new (ctx, ic, *depth, self);
    }

    retval = gumjs_invocation_return_value_new (ctx, ic, self);

    JSObjectCallAsFunction (ctx, entry->on_leave, jic, 1, &retval,
        &scope.exception);

    gumjs_invocation_return_value_update_context (retval, NULL);
    gumjs_invocation_context_update_handle (jic, NULL);

    _gum_script_scope_leave (&scope);
  }
}

static void
gum_script_attach_entry_free (GumScriptAttachEntry * entry)
{
  JSValueUnprotect (entry->ctx, entry->on_enter);
  JSValueUnprotect (entry->ctx, entry->on_leave);
  g_slice_free (GumScriptAttachEntry, entry);
}

static void
gum_script_replace_entry_free (GumScriptReplaceEntry * entry)
{
  gum_interceptor_revert_function (entry->interceptor, entry->target);
  JSValueUnprotect (entry->ctx, entry->replacement);
  g_slice_free (GumScriptReplaceEntry, entry);
}

static JSObjectRef
gumjs_invocation_context_new (JSContextRef ctx,
                              GumInvocationContext * handle,
                              gint depth,
                              GumScriptInterceptor * interceptor)
{
  GumScriptInvocationContext * sic;

  sic = g_slice_new (GumScriptInvocationContext);
  sic->handle = handle;
  sic->cpu_context = NULL;
  sic->depth = depth;

  return JSObjectMake (ctx, interceptor->invocation_context, sic);
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_context_finalize)
{
  GumScriptInvocationContext * self = GUM_SCRIPT_INVOCATION_CONTEXT (object);

  g_slice_free (GumScriptInvocationContext, self);
}

static void
gumjs_invocation_context_update_handle (JSObjectRef jic,
                                        GumInvocationContext * handle)
{
  GumScriptInvocationContext * self = GUM_SCRIPT_INVOCATION_CONTEXT (jic);

  self->handle = handle;
  g_clear_pointer (&self->cpu_context, _gumjs_cpu_context_detach);
}

static gboolean
gumjs_invocation_context_check_valid (GumScriptInvocationContext * self,
                                      JSContextRef ctx,
                                      JSValueRef * exception)
{
  if (self->handle == NULL)
  {
    _gumjs_throw (ctx, exception, "invalid operation");
    return FALSE;
  }

  return TRUE;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_return_address)
{
  GumScriptInvocationContext * self = GUM_SCRIPT_INVOCATION_CONTEXT (object);

  if (!gumjs_invocation_context_check_valid (self, ctx, exception))
    return NULL;

  return _gumjs_native_pointer_new (ctx,
      gum_invocation_context_get_return_address (self->handle), args->core);
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_cpu_context)
{
  GumScriptInvocationContext * self = GUM_SCRIPT_INVOCATION_CONTEXT (object);

  if (!gumjs_invocation_context_check_valid (self, ctx, exception))
    return NULL;

  if (self->cpu_context == NULL)
  {
    self->cpu_context = _gumjs_cpu_context_new (ctx, self->handle->cpu_context,
        GUM_CPU_CONTEXT_READONLY, args->core);
  }

  return self->cpu_context;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_system_error)
{
  GumScriptInvocationContext * self = GUM_SCRIPT_INVOCATION_CONTEXT (object);

  if (!gumjs_invocation_context_check_valid (self, ctx, exception))
    return NULL;

  return JSValueMakeNumber (ctx, self->handle->system_error);
}

GUMJS_DEFINE_SETTER (gumjs_invocation_context_set_system_error)
{
  gint value;
  GumScriptInvocationContext * self;

  if (!_gumjs_args_parse (args, "i", &value))
    return false;

  self = GUM_SCRIPT_INVOCATION_CONTEXT (object);

  if (!gumjs_invocation_context_check_valid (self, ctx, exception))
    return false;

  self->handle->system_error = value;
  return true;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_depth)
{
  GumScriptInvocationContext * self = GUM_SCRIPT_INVOCATION_CONTEXT (object);

  if (!gumjs_invocation_context_check_valid (self, ctx, exception))
    return NULL;

  return JSValueMakeNumber (ctx, self->depth);
}

static JSObjectRef
gumjs_invocation_args_new (JSContextRef ctx,
                           GumInvocationContext * ic,
                           GumScriptInterceptor * interceptor)
{
  return JSObjectMake (ctx, interceptor->invocation_args, ic);
}

static gboolean
gumjs_invocation_args_try_get_context (JSContextRef ctx,
                                       JSValueRef value,
                                       GumInvocationContext ** result,
                                       JSValueRef * exception)
{
  GumInvocationContext * ic;

  ic = JSObjectGetPrivate ((JSObjectRef) value);
  if (ic == NULL)
  {
    _gumjs_throw (ctx, exception, "invalid operation");
    return FALSE;
  }

  *result = ic;
  return TRUE;
}

static void
gumjs_invocation_args_update_context (JSValueRef value,
                                      GumInvocationContext * ic)
{
  JSObjectSetPrivate ((JSObjectRef) value, ic);
}

GUMJS_DEFINE_GETTER (gumjs_invocation_args_get_property)
{
  guint n;
  GumInvocationContext * ic;

  if (!_gumjs_uint_try_parse (ctx, property_name, &n, NULL))
    return NULL;

  if (!gumjs_invocation_args_try_get_context (ctx, object, &ic, exception))
    return NULL;

  return _gumjs_native_pointer_new (ctx,
      gum_invocation_context_get_nth_argument (ic, n),
      args->core);
}

GUMJS_DEFINE_SETTER (gumjs_invocation_args_set_property)
{
  GumInvocationContext * ic;
  guint n;
  gpointer value;

  if (!_gumjs_uint_try_parse (ctx, property_name, &n, NULL))
    return false;

  if (!_gumjs_args_parse (args, "p", &value))
    return false;

  if (!gumjs_invocation_args_try_get_context (ctx, object, &ic, exception))
    return NULL;

  gum_invocation_context_replace_nth_argument (ic, n, value);
  return true;
}

static JSObjectRef
gumjs_invocation_return_value_new (JSContextRef ctx,
                                   GumInvocationContext * ic,
                                   GumScriptInterceptor * interceptor)
{
  GumScriptInvocationReturnValue * retval;
  GumScriptNativePointer * ptr;

  retval = g_slice_new (GumScriptInvocationReturnValue);

  ptr = &retval->parent;
  ptr->instance_size = sizeof (GumScriptInvocationReturnValue);
  ptr->value = gum_invocation_context_get_return_value (ic);

  retval->ic = ic;

  return JSObjectMake (ctx, interceptor->invocation_retval, retval);
}

static gboolean
gumjs_invocation_return_value_try_get_context (
    JSContextRef ctx,
    JSValueRef value,
    GumScriptInvocationReturnValue ** retval,
    GumInvocationContext ** ic,
    JSValueRef * exception)
{
  GumScriptInvocationReturnValue * self;

  self = JSObjectGetPrivate ((JSObjectRef) value);
  if (self->ic == NULL)
  {
    _gumjs_throw (ctx, exception, "invalid operation");
    return FALSE;
  }

  *retval = self;
  *ic = self->ic;
  return TRUE;
}

static void
gumjs_invocation_return_value_update_context (JSValueRef value,
                                              GumInvocationContext * ic)
{
  GumScriptInvocationReturnValue * self;

  self = JSObjectGetPrivate ((JSObjectRef) value);

  self->ic = NULL;
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_return_value_replace)
{
  GumScriptInvocationReturnValue * self;
  GumInvocationContext * ic;
  GumScriptNativePointer * ptr;

  if (!gumjs_invocation_return_value_try_get_context (ctx, this_object, &self,
      &ic, exception))
    return NULL;
  ptr = &self->parent;

  if (!_gumjs_args_parse (args, "p~", &ptr->value))
    return NULL;

  gum_invocation_context_replace_return_value (ic, ptr->value);

  return JSValueMakeUndefined (ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_throw_not_yet_available)
{
  _gumjs_throw (ctx, exception,
      "This part of the Interceptor API is not yet in the JavaScriptCore "
      "runtime");
  return NULL;
}

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
gum_script_interceptor_adjust_ignore_level (GumThreadId thread_id,
                                            gint adjustment)
{
  GumInterceptor * interceptor;

  interceptor = gum_interceptor_obtain ();
  gum_interceptor_ignore_current_thread (interceptor);

  g_rw_lock_writer_lock (&gum_ignored_lock);
  gum_script_interceptor_adjust_ignore_level_unlocked (thread_id, adjustment,
      interceptor);
  g_rw_lock_writer_unlock (&gum_ignored_lock);

  gum_interceptor_unignore_current_thread (interceptor);
  g_object_unref (interceptor);
}

static void
gum_script_interceptor_adjust_ignore_level_unlocked (
    GumThreadId thread_id,
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
gum_script_ignore (GumThreadId thread_id)
{
  gum_script_interceptor_adjust_ignore_level (thread_id, 1);
}

void
gum_script_unignore (GumThreadId thread_id)
{
  gum_script_interceptor_adjust_ignore_level (thread_id, -1);
}

void
gum_script_unignore_later (GumThreadId thread_id)
{
  GMainContext * main_context;
  GumInterceptor * interceptor;
  GSource * source;

  main_context = gum_script_scheduler_get_js_context (
      _gum_script_get_scheduler ());

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
    gum_script_interceptor_adjust_ignore_level_unlocked (thread_id, -1,
        interceptor);
  }

  g_rw_lock_writer_unlock (&gum_ignored_lock);

  gum_interceptor_unignore_current_thread (interceptor);
  g_object_unref (interceptor);

  return FALSE;
}

gboolean
gum_script_is_ignoring (GumThreadId thread_id)
{
  gboolean is_ignored;

  g_rw_lock_reader_lock (&gum_ignored_lock);

  is_ignored = gum_ignored_threads != NULL &&
      g_hash_table_contains (gum_ignored_threads, GSIZE_TO_POINTER (thread_id));

  g_rw_lock_reader_unlock (&gum_ignored_lock);

  return is_ignored;
}
