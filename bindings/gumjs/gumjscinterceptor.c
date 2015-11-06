/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscinterceptor.h"

#include "gumjscmacros.h"
#include "gumjscscript-priv.h"

#define GUM_JSC_INVOCATION_CONTEXT(o) \
  ((GumJscInvocationContext *) JSObjectGetPrivate (o))

#ifdef G_OS_WIN32
# define GUM_SYSTEM_ERROR_FIELD "lastError"
#else
# define GUM_SYSTEM_ERROR_FIELD "errno"
#endif

typedef struct _GumJscInvocationContext GumJscInvocationContext;
typedef struct _GumJscInvocationReturnValue GumJscInvocationReturnValue;
typedef struct _GumJscAttachEntry GumJscAttachEntry;
typedef struct _GumJscReplaceEntry GumJscReplaceEntry;

struct _GumJscInvocationContext
{
  GumInvocationContext * handle;
  JSObjectRef cpu_context;
  gint depth;
};

struct _GumJscInvocationReturnValue
{
  GumJscNativePointer parent;
  GumInvocationContext * ic;
};

struct _GumJscAttachEntry
{
  JSObjectRef on_enter;
  JSObjectRef on_leave;
  JSContextRef ctx;
};

struct _GumJscReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  JSValueRef replacement;
  GumJscCore * core;
};

GUMJS_DECLARE_FUNCTION (gumjs_interceptor_attach)
static void gum_jsc_attach_entry_free (GumJscAttachEntry * entry);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_detach_all)
static void gum_jsc_interceptor_detach_all (GumJscInterceptor * self);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_replace)
static void gum_jsc_replace_entry_free (GumJscReplaceEntry * entry);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_revert)

static JSObjectRef gumjs_invocation_context_new (JSContextRef ctx,
    GumInvocationContext * handle, gint depth,
    GumJscInterceptor * parent);
GUMJS_DECLARE_FINALIZER (gumjs_invocation_context_finalize)
static void gumjs_invocation_context_update_handle (JSObjectRef jic,
    GumInvocationContext * handle);
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_system_error)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_thread_id)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_depth)

static JSObjectRef gumjs_invocation_args_new (JSContextRef ctx,
    GumInvocationContext * ic, GumJscInterceptor * parent);
static void gumjs_invocation_args_update_context (JSValueRef value,
    GumInvocationContext * context);
GUMJS_DECLARE_GETTER (gumjs_invocation_args_get_property)
GUMJS_DECLARE_SETTER (gumjs_invocation_args_set_property)

static JSObjectRef gumjs_invocation_return_value_new (JSContextRef ctx,
    GumInvocationContext * ic, GumJscInterceptor * parent);
static void gumjs_invocation_return_value_update_context (JSValueRef value,
    GumInvocationContext * ic);
GUMJS_DECLARE_FUNCTION (gumjs_invocation_return_value_replace)

static const JSStaticFunction gumjs_interceptor_functions[] =
{
  { "_attach", gumjs_interceptor_attach, GUMJS_RO },
  { "detachAll", gumjs_interceptor_detach_all, GUMJS_RO },
  { "_replace", gumjs_interceptor_replace, GUMJS_RO },
  { "revert", gumjs_interceptor_revert, GUMJS_RO },

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
    "threadId",
    gumjs_invocation_context_get_thread_id,
    NULL,
    GUMJS_RO
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

void
_gum_jsc_interceptor_init (GumJscInterceptor * self,
                           GumJscCore * core,
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
      (GDestroyNotify) gum_jsc_replace_entry_free);

  def = kJSClassDefinitionEmpty;
  def.className = "Interceptor";
  def.staticFunctions = gumjs_interceptor_functions;
  klass = JSClassCreate (&def);
  interceptor = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, def.className, interceptor);

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
_gum_jsc_interceptor_flush (GumJscInterceptor * self)
{
  gum_jsc_interceptor_detach_all (self);

  g_hash_table_remove_all (self->replacement_by_address);
}

void
_gum_jsc_interceptor_dispose (GumJscInterceptor * self)
{
  g_clear_pointer (&self->invocation_retval, JSClassRelease);
  g_clear_pointer (&self->invocation_args, JSClassRelease);
  g_clear_pointer (&self->invocation_context, JSClassRelease);
}

void
_gum_jsc_interceptor_finalize (GumJscInterceptor * self)
{
  g_clear_pointer (&self->attach_entries, g_queue_free);
  g_clear_pointer (&self->replacement_by_address, g_hash_table_unref);

  g_clear_pointer (&self->interceptor, g_object_unref);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_attach)
{
  GumJscInterceptor * self;
  GumJscCore * core = args->core;
  gpointer target;
  JSObjectRef on_enter, on_leave;
  GumJscAttachEntry * entry;
  GumAttachReturn attach_ret;

  self = JSObjectGetPrivate (this_object);

  if (!_gumjs_args_parse (args, "pF{onEnter?,onLeave?}",
      &target, &on_enter, &on_leave))
    return NULL;

  entry = g_slice_new (GumJscAttachEntry);
  JSValueProtect (ctx, on_enter);
  entry->on_enter = on_enter;
  JSValueProtect (ctx, on_leave);
  entry->on_leave = on_leave;
  entry->ctx = core->ctx;

  attach_ret = gum_interceptor_attach_listener (self->interceptor, target,
      GUM_INVOCATION_LISTENER (core->script), entry);
  if (attach_ret != GUM_ATTACH_OK)
    goto unable_to_attach;

  GUM_JSC_CORE_LOCK (core);
  g_queue_push_tail (self->attach_entries, entry);
  GUM_JSC_CORE_UNLOCK (core);

  return JSValueMakeUndefined (ctx);

unable_to_attach:
  {
    gum_jsc_attach_entry_free (entry);

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

static void
gum_jsc_attach_entry_free (GumJscAttachEntry * entry)
{
  JSValueUnprotect (entry->ctx, entry->on_enter);
  JSValueUnprotect (entry->ctx, entry->on_leave);
  g_slice_free (GumJscAttachEntry, entry);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_detach_all)
{
  GumJscInterceptor * self;

  self = JSObjectGetPrivate (this_object);

  gum_jsc_interceptor_detach_all (self);

  return JSValueMakeUndefined (ctx);
}

static void
gum_jsc_interceptor_detach_all (GumJscInterceptor * self)
{
  GumJscCore * core = self->core;

  gum_interceptor_detach_listener (self->interceptor,
      GUM_INVOCATION_LISTENER (self->core->script));

  GUM_JSC_CORE_LOCK (core);
  while (!g_queue_is_empty (self->attach_entries))
  {
    GumJscAttachEntry * entry = g_queue_pop_tail (self->attach_entries);

    GUM_JSC_CORE_UNLOCK (core);
    gum_jsc_attach_entry_free (entry);
    GUM_JSC_CORE_LOCK (core);
  }
  GUM_JSC_CORE_UNLOCK (core);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace)
{
  GumJscInterceptor * self;
  GumJscCore * core = args->core;
  gpointer target, replacement;
  JSValueRef replacement_value;
  GumJscReplaceEntry * entry;
  GumReplaceReturn replace_ret;

  self = JSObjectGetPrivate (this_object);

  if (!_gumjs_args_parse (args, "pV", &target, &replacement_value))
    return NULL;

  if (!_gumjs_native_pointer_try_get (ctx, replacement_value, core,
      &replacement, exception))
    return NULL;

  entry = g_slice_new (GumJscReplaceEntry);
  entry->interceptor = self->interceptor;
  entry->target = target;
  entry->replacement = replacement_value;
  entry->core = core;

  replace_ret = gum_interceptor_replace_function (self->interceptor, target,
      replacement, NULL);
  if (replace_ret != GUM_REPLACE_OK)
    goto unable_to_replace;

  JSValueProtect (ctx, replacement_value);

  GUM_JSC_CORE_LOCK (core);
  g_hash_table_insert (self->replacement_by_address, target, entry);
  GUM_JSC_CORE_UNLOCK (core);

  return JSValueMakeUndefined (ctx);

unable_to_replace:
  {
    g_slice_free (GumJscReplaceEntry, entry);

    switch (replace_ret)
    {
      case GUM_REPLACE_WRONG_SIGNATURE:
        _gumjs_throw (ctx, exception, "unable to intercept function at %p; "
            "please file a bug", target);
        break;
      case GUM_REPLACE_ALREADY_REPLACED:
        _gumjs_throw (ctx, exception, "already replaced this function");
        break;
      default:
        g_assert_not_reached ();
    }

    return NULL;
  }
}

static void
gum_jsc_replace_entry_free (GumJscReplaceEntry * entry)
{
  GumJscCore * core = entry->core;

  GUM_JSC_CORE_UNLOCK (core);

  gum_interceptor_revert_function (entry->interceptor, entry->target);

  JSValueUnprotect (core->ctx, entry->replacement);

  g_slice_free (GumJscReplaceEntry, entry);

  GUM_JSC_CORE_LOCK (core);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_revert)
{
  GumJscInterceptor * self;
  GumJscCore * core;
  gpointer target;

  self = JSObjectGetPrivate (this_object);
  core = self->core;

  if (!_gumjs_args_parse (args, "p", &target))
    return NULL;

  GUM_JSC_CORE_LOCK (core);
  g_hash_table_remove (self->replacement_by_address, target);
  GUM_JSC_CORE_UNLOCK (core);

  return JSValueMakeUndefined (ctx);
}

void
_gum_jsc_interceptor_on_enter (GumJscInterceptor * self,
                               GumInvocationContext * ic)
{
  GumJscAttachEntry * entry;
  gint * depth;

  if (gum_script_backend_is_ignoring (GUM_SCRIPT_BACKEND (self->core->backend),
      gum_invocation_context_get_thread_id (ic)))
    return;

  entry = gum_invocation_context_get_listener_function_data (ic);
  depth = GUM_LINCTX_GET_THREAD_DATA (ic, gint);

  if (entry->on_enter != NULL)
  {
    GumJscCore * core = self->core;
    JSContextRef ctx = core->ctx;
    GumJscScope scope;
    JSObjectRef jic;
    JSValueRef args;

    _gum_jsc_scope_enter (&scope, core);

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

    _gum_jsc_scope_leave (&scope);
  }

  (*depth)++;
}

void
_gum_jsc_interceptor_on_leave (GumJscInterceptor * self,
                               GumInvocationContext * ic)
{
  GumJscAttachEntry * entry;
  gint * depth;

  if (gum_script_backend_is_ignoring (GUM_SCRIPT_BACKEND (self->core->backend),
      gum_invocation_context_get_thread_id (ic)))
    return;

  entry = gum_invocation_context_get_listener_function_data (ic);
  depth = GUM_LINCTX_GET_THREAD_DATA (ic, gint);

  (*depth)--;

  if (entry->on_leave != NULL)
  {
    GumJscCore * core = self->core;
    JSContextRef ctx = core->ctx;
    GumJscScope scope;
    JSObjectRef jic;
    JSValueRef retval;

    _gum_jsc_scope_enter (&scope, core);

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

    _gum_jsc_scope_leave (&scope);
  }
}

static JSObjectRef
gumjs_invocation_context_new (JSContextRef ctx,
                              GumInvocationContext * handle,
                              gint depth,
                              GumJscInterceptor * parent)
{
  GumJscInvocationContext * sic;

  sic = g_slice_new (GumJscInvocationContext);
  sic->handle = handle;
  sic->cpu_context = NULL;
  sic->depth = depth;

  return JSObjectMake (ctx, parent->invocation_context, sic);
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_context_finalize)
{
  GumJscInvocationContext * self = GUM_JSC_INVOCATION_CONTEXT (object);

  g_slice_free (GumJscInvocationContext, self);
}

static void
gumjs_invocation_context_update_handle (JSObjectRef jic,
                                        GumInvocationContext * handle)
{
  GumJscInvocationContext * self = GUM_JSC_INVOCATION_CONTEXT (jic);

  self->handle = handle;
  g_clear_pointer (&self->cpu_context, _gumjs_cpu_context_detach);
}

static gboolean
gumjs_invocation_context_check_valid (GumJscInvocationContext * self,
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
  GumJscInvocationContext * self = GUM_JSC_INVOCATION_CONTEXT (object);

  if (!gumjs_invocation_context_check_valid (self, ctx, exception))
    return NULL;

  return _gumjs_native_pointer_new (ctx,
      gum_invocation_context_get_return_address (self->handle), args->core);
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_cpu_context)
{
  GumJscInvocationContext * self = GUM_JSC_INVOCATION_CONTEXT (object);

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
  GumJscInvocationContext * self = GUM_JSC_INVOCATION_CONTEXT (object);

  if (!gumjs_invocation_context_check_valid (self, ctx, exception))
    return NULL;

  return JSValueMakeNumber (ctx, self->handle->system_error);
}

GUMJS_DEFINE_SETTER (gumjs_invocation_context_set_system_error)
{
  gint value;
  GumJscInvocationContext * self;

  if (!_gumjs_args_parse (args, "i", &value))
    return false;

  self = GUM_JSC_INVOCATION_CONTEXT (object);

  if (!gumjs_invocation_context_check_valid (self, ctx, exception))
    return false;

  self->handle->system_error = value;
  return true;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_thread_id)
{
  GumJscInvocationContext * self = GUM_JSC_INVOCATION_CONTEXT (object);

  if (!gumjs_invocation_context_check_valid (self, ctx, exception))
    return NULL;

  return JSValueMakeNumber (ctx,
      gum_invocation_context_get_thread_id (self->handle));
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_depth)
{
  GumJscInvocationContext * self = GUM_JSC_INVOCATION_CONTEXT (object);

  if (!gumjs_invocation_context_check_valid (self, ctx, exception))
    return NULL;

  return JSValueMakeNumber (ctx, self->depth);
}

static JSObjectRef
gumjs_invocation_args_new (JSContextRef ctx,
                           GumInvocationContext * ic,
                           GumJscInterceptor * parent)
{
  return JSObjectMake (ctx, parent->invocation_args, ic);
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
                                   GumJscInterceptor * parent)
{
  GumJscInvocationReturnValue * retval;
  GumJscNativePointer * ptr;

  retval = g_slice_new (GumJscInvocationReturnValue);

  ptr = &retval->parent;
  ptr->instance_size = sizeof (GumJscInvocationReturnValue);
  ptr->value = gum_invocation_context_get_return_value (ic);

  retval->ic = ic;

  return JSObjectMake (ctx, parent->invocation_retval, retval);
}

static gboolean
gumjs_invocation_return_value_try_get_context (
    JSContextRef ctx,
    JSValueRef value,
    GumJscInvocationReturnValue ** retval,
    GumInvocationContext ** ic,
    JSValueRef * exception)
{
  GumJscInvocationReturnValue * self;

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
  GumJscInvocationReturnValue * self;

  self = JSObjectGetPrivate ((JSObjectRef) value);

  self->ic = NULL;
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_return_value_replace)
{
  GumJscInvocationReturnValue * self;
  GumInvocationContext * ic;
  GumJscNativePointer * ptr;

  if (!gumjs_invocation_return_value_try_get_context (ctx, this_object, &self,
      &ic, exception))
    return NULL;
  ptr = &self->parent;

  if (!_gumjs_args_parse (args, "p~", &ptr->value))
    return NULL;

  gum_invocation_context_replace_return_value (ic, ptr->value);

  return JSValueMakeUndefined (ctx);
}
