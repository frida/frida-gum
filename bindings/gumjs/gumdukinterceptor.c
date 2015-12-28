/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukinterceptor.h"

#include "gumdukmacros.h"
#include "gumdukscript-priv.h"

#define GUM_DUK_INVOCATION_CONTEXT(o) \
  ((GumDukInvocationContext *) _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx)))

#ifdef G_OS_WIN32
# define GUM_SYSTEM_ERROR_FIELD "lastError"
#else
# define GUM_SYSTEM_ERROR_FIELD "errno"
#endif

typedef struct _GumDukInvocationContext GumDukInvocationContext;
typedef struct _GumDukInvocationReturnValue GumDukInvocationReturnValue;
typedef struct _GumDukAttachEntry GumDukAttachEntry;
typedef struct _GumDukReplaceEntry GumDukReplaceEntry;

struct _GumDukInvocationContext
{
  GumInvocationContext * handle;
  GumDukHeapPtr cpu_context;
  gint depth;
};

struct _GumDukInvocationReturnValue
{
  GumDukNativePointer parent;
  GumInvocationContext * ic;
};

struct _GumDukAttachEntry
{
  GumDukHeapPtr on_enter;
  GumDukHeapPtr on_leave;
  duk_context * ctx;
};

struct _GumDukReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  GumDukValue * replacement;
  GumDukCore * core;
};

GUMJS_DECLARE_FUNCTION (gumjs_interceptor_attach)
static void gum_duk_attach_entry_free (GumDukAttachEntry * entry);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_detach_all)
static void gum_duk_interceptor_detach_all (GumDukInterceptor * self);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_replace)
static void gum_duk_replace_entry_free (GumDukReplaceEntry * entry);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_revert)

static GumDukHeapPtr gumjs_invocation_context_new (duk_context * ctx,
    GumInvocationContext * handle, gint depth,
    GumDukInterceptor * parent);
GUMJS_DECLARE_FINALIZER (gumjs_invocation_context_finalize)
static void gumjs_invocation_context_update_handle (duk_context * ctx,
    GumDukHeapPtr jic, GumInvocationContext * handle);
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_system_error)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_thread_id)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_depth)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_invocation_args_construct)
static GumDukHeapPtr gumjs_invocation_args_new (duk_context * ctx,
    GumInvocationContext * ic, GumDukInterceptor * parent);
static void gumjs_invocation_args_update_context (duk_context * ctx,
    GumDukHeapPtr value, GumInvocationContext * context);
GUMJS_DECLARE_GETTER (gumjs_invocation_args_get_property)
GUMJS_DECLARE_SETTER (gumjs_invocation_args_set_property)

static GumDukHeapPtr gumjs_invocation_return_value_new (duk_context * ctx,
    GumInvocationContext * ic, GumDukInterceptor * parent);
static void gumjs_invocation_return_value_update_context (duk_context * ctx,
    GumDukHeapPtr value, GumInvocationContext * ic);
GUMJS_DECLARE_FUNCTION (gumjs_invocation_return_value_replace)

static const duk_function_list_entry gumjs_interceptor_functions[] =
{
  { "_attach", gumjs_interceptor_attach, 2 },
  { "detachAll", gumjs_interceptor_detach_all, 0 },
  { "_replace", gumjs_interceptor_replace, 2 },
  { "revert", gumjs_interceptor_revert, 1 },

  { NULL, NULL, 0 }
};

static const GumDukPropertyEntry gumjs_invocation_context_values[] =
{
  {
    "returnAddress",
    gumjs_invocation_context_get_return_address,
    NULL
  },
  {
    "context",
    gumjs_invocation_context_get_cpu_context,
    NULL
  },
  {
    GUM_SYSTEM_ERROR_FIELD,
    gumjs_invocation_context_get_system_error,
    gumjs_invocation_context_set_system_error
  },
  {
    "threadId",
    gumjs_invocation_context_get_thread_id,
    NULL
  },
  {
    "depth",
    gumjs_invocation_context_get_depth,
    NULL
  },

  { NULL, NULL, NULL }
};

static const duk_function_list_entry gumjs_invocation_return_value_functions[] =
{
  { "replace", gumjs_invocation_return_value_replace, 0 },

  { NULL, NULL, 0 }
};

void
_gum_duk_interceptor_init (GumDukInterceptor * self,
                           GumDukCore * core)
{
  duk_context * ctx = core->ctx;

  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->attach_entries = g_queue_new ();
  self->replacement_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_duk_replace_entry_free);

  printf ("here 1\n");
  duk_push_object (ctx);
  // [ newobject ]
  duk_push_object (ctx);
  // [ newobject newproto ]
  duk_put_function_list (ctx, -1, gumjs_interceptor_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_dump_context_stdout (ctx);
  // [ newobject ]
  duk_new (ctx, 0);
  duk_dump_context_stdout (ctx);
  // [ newinstance ]
  duk_put_global_string (ctx, "Interceptor");
  // [ ]

  printf ("here 2\n");
  duk_push_object (ctx);
  // [ newobject ]
  duk_push_object (ctx);
  // [ newobject newproto ]
  duk_push_c_function (ctx, gumjs_invocation_context_finalize, 1);
  // [ newobject newproto finalize ]
  duk_set_finalizer (ctx, -2);
  // [ newobject newproto ]
  duk_put_prop_string (ctx, -2, "prototype");
  // [ newobject ]
  duk_dup (ctx, -1);
  // [ newobject newobject ]
  duk_put_global_string (ctx, "InvocationContext");
  // [ newobject ]
  self->invocation_context = duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []
  _gumjs_duk_add_properties_to_class (ctx, "InvocationContext",
      gumjs_invocation_context_values);


  printf ("here 3\n");
  duk_push_object (ctx);
  duk_push_c_function (ctx, gumjs_invocation_args_construct, 0);
  // [ InvocationArgsCtor ]
  duk_push_object (ctx);
  // [ IncocationArgsCtor prototype ]
  duk_put_prop_string (ctx, -2, "prototype");
  // [ InvocationArgsCtor ]
  self->invocation_args = duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "InvocationArgs");
  // []

  printf ("here 4\n");
  _gumjs_duk_create_subclass (ctx, "NativePointer", "InvocationReturnValue",
      NULL, NULL);
  duk_get_global_string (ctx, "InvocationReturnValue");
  // [ InvocationReturnValue ]
  duk_get_prop_string (ctx, -1, "prototype");
  // [ InvocationReturnValue proto ]
  duk_put_function_list (ctx, -1, gumjs_invocation_return_value_functions);
  // [ InvocationReturnValue ]
  self->invocation_retval = duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []
  printf ("here 5\n");
}

void
_gum_duk_interceptor_flush (GumDukInterceptor * self)
{
  GumDukCore * core = self->core;

  gum_duk_interceptor_detach_all (self);

  GUM_DUK_CORE_LOCK (core);
  g_hash_table_remove_all (self->replacement_by_address);
  GUM_DUK_CORE_UNLOCK (core);
}

void
_gum_duk_interceptor_dispose (GumDukInterceptor * self)
{
}

void
_gum_duk_interceptor_finalize (GumDukInterceptor * self)
{
  GumDukCore * core = self->core;

  g_clear_pointer (&self->attach_entries, g_queue_free);
  GUM_DUK_CORE_LOCK (core);
  g_clear_pointer (&self->replacement_by_address, g_hash_table_unref);
  GUM_DUK_CORE_UNLOCK (core);

  g_clear_pointer (&self->interceptor, g_object_unref);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_attach)
{
  GumDukInterceptor * self;
  GumDukCore * core = args->core;
  gpointer target;
  GumDukHeapPtr on_enter, on_leave;
  GumDukAttachEntry * entry;
  GumAttachReturn attach_ret;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  if (!_gumjs_args_parse (ctx, "pF{onEnter?,onLeave?}",
      &target, &on_enter, &on_leave))
  {
    duk_push_null (ctx);
    return 1;
  }

  entry = g_slice_new (GumDukAttachEntry);
  //JSValueProtect (ctx, on_enter);
  entry->on_enter = on_enter;
  //JSValueProtect (ctx, on_leave);
  entry->on_leave = on_leave;
  entry->ctx = core->ctx;

  attach_ret = gum_interceptor_attach_listener (self->interceptor, target,
      GUM_INVOCATION_LISTENER (core->script), entry);
  if (attach_ret != GUM_ATTACH_OK)
    goto unable_to_attach;

  GUM_DUK_CORE_LOCK (core);
  g_queue_push_tail (self->attach_entries, entry);
  GUM_DUK_CORE_UNLOCK (core);

  duk_push_undefined (ctx);
  return 1;

unable_to_attach:
  {
    gum_duk_attach_entry_free (entry);

    switch (attach_ret)
    {
      case GUM_ATTACH_WRONG_SIGNATURE:
        _gumjs_throw (ctx, "unable to intercept function at %p; "
            "please file a bug", target);
        break;
      case GUM_ATTACH_ALREADY_ATTACHED:
        _gumjs_throw (ctx, "already attached to this function");
        break;
      default:
        g_assert_not_reached ();
    }

    duk_push_null (ctx);
    return 1;
  }
}

static void
gum_duk_attach_entry_free (GumDukAttachEntry * entry)
{
  //JSValueUnprotect (entry->ctx, entry->on_enter);
  //JSValueUnprotect (entry->ctx, entry->on_leave);
  g_slice_free (GumDukAttachEntry, entry);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_detach_all)
{
  GumDukInterceptor * self;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  gum_duk_interceptor_detach_all (self);

  duk_push_undefined (ctx);
  return 1;
}

static void
gum_duk_interceptor_detach_all (GumDukInterceptor * self)
{
  GumDukCore * core = self->core;

  gum_interceptor_detach_listener (self->interceptor,
      GUM_INVOCATION_LISTENER (self->core->script));

  GUM_DUK_CORE_LOCK (core);
  while (!g_queue_is_empty (self->attach_entries))
  {
    GumDukAttachEntry * entry = g_queue_pop_tail (self->attach_entries);

    GUM_DUK_CORE_UNLOCK (core);
    gum_duk_attach_entry_free (entry);
    GUM_DUK_CORE_LOCK (core);
  }
  GUM_DUK_CORE_UNLOCK (core);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace)
{
  GumDukInterceptor * self;
  GumDukCore * core = args->core;
  gpointer target, replacement;
  GumDukValue * replacement_value;
  GumDukReplaceEntry * entry;
  GumReplaceReturn replace_ret;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  if (!_gumjs_args_parse (ctx, "pV", &target, &replacement_value))
  {
    duk_push_null (ctx);
    return 1;
  }

  if (!_gumjs_value_native_pointer_try_get (ctx, replacement_value, core,
      &replacement))
  {
    duk_push_null (ctx);
    return 1;
  }

  entry = g_slice_new (GumDukReplaceEntry);
  entry->interceptor = self->interceptor;
  entry->target = target;
  entry->replacement = replacement_value;
  entry->core = core;

  replace_ret = gum_interceptor_replace_function (self->interceptor, target,
      replacement, NULL);
  if (replace_ret != GUM_REPLACE_OK)
    goto unable_to_replace;

  //JSValueProtect (ctx, replacement_value);

  GUM_DUK_CORE_LOCK (core);
  g_hash_table_insert (self->replacement_by_address, target, entry);
  GUM_DUK_CORE_UNLOCK (core);

  duk_push_undefined (ctx);
  return 1;

unable_to_replace:
  {
    g_slice_free (GumDukReplaceEntry, entry);

    switch (replace_ret)
    {
      case GUM_REPLACE_WRONG_SIGNATURE:
        _gumjs_throw (ctx, "unable to intercept function at %p; "
            "please file a bug", target);
        break;
      case GUM_REPLACE_ALREADY_REPLACED:
        _gumjs_throw (ctx, "already replaced this function");
        break;
      default:
        g_assert_not_reached ();
    }

    duk_push_null (ctx);
    return 1;
  }
}

static void
gum_duk_replace_entry_free (GumDukReplaceEntry * entry)
{
  GumDukCore * core = entry->core;

  GUM_DUK_CORE_UNLOCK (core);

  gum_interceptor_revert_function (entry->interceptor, entry->target);

  //JSValueUnprotect (core->ctx, entry->replacement);

  g_slice_free (GumDukReplaceEntry, entry);

  g_free (entry->replacement);

  GUM_DUK_CORE_LOCK (core);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_revert)
{
  GumDukInterceptor * self;
  GumDukCore * core;
  gpointer target;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));
  core = self->core;

  if (!_gumjs_args_parse (ctx, "p", &target))
  {
    duk_push_null (ctx);
    return 1;
  }

  GUM_DUK_CORE_LOCK (core);
  g_hash_table_remove (self->replacement_by_address, target);
  GUM_DUK_CORE_UNLOCK (core);

  duk_push_undefined (ctx);
  return 1;
}

void
_gum_duk_interceptor_on_enter (GumDukInterceptor * self,
                               GumInvocationContext * ic)
{
  GumDukAttachEntry * entry;
  gint * depth;

  if (gum_script_backend_is_ignoring (GUM_SCRIPT_BACKEND (self->core->backend),
      gum_invocation_context_get_thread_id (ic)))
    return;

  entry = gum_invocation_context_get_listener_function_data (ic);
  depth = GUM_LINCTX_GET_THREAD_DATA (ic, gint);

  if (entry->on_enter != NULL)
  {
    GumDukCore * core = self->core;
    duk_context * ctx = core->ctx;
    GumDukScope scope;
    GumDukHeapPtr jic;
    GumDukHeapPtr args;

    _gum_duk_scope_enter (&scope, core);

    jic = gumjs_invocation_context_new (ctx, ic, *depth, self);
    args = gumjs_invocation_args_new (ctx, ic, self);

    duk_push_heapptr (ctx, entry->on_enter);
    duk_push_heapptr (ctx, jic);
    duk_push_heapptr (ctx, args);

    duk_call (ctx, 2);
    duk_pop (ctx);

    gumjs_invocation_args_update_context (ctx, args, NULL);
    gumjs_invocation_context_update_handle (ctx, jic, NULL);

    if (entry->on_leave != NULL)
    {
      //JSValueProtect (ctx, jic);
      *GUM_LINCTX_GET_FUNC_INVDATA (ic, GumDukHeapPtr) = jic;
    }

    _gum_duk_scope_leave (&scope);
  }

  (*depth)++;
}

void
_gum_duk_interceptor_on_leave (GumDukInterceptor * self,
                               GumInvocationContext * ic)
{
  GumDukAttachEntry * entry;
  gint * depth;

  if (gum_script_backend_is_ignoring (GUM_SCRIPT_BACKEND (self->core->backend),
      gum_invocation_context_get_thread_id (ic)))
    return;

  entry = gum_invocation_context_get_listener_function_data (ic);
  depth = GUM_LINCTX_GET_THREAD_DATA (ic, gint);

  (*depth)--;

  if (entry->on_leave != NULL)
  {
    GumDukCore * core = self->core;
    duk_context * ctx = core->ctx;
    GumDukScope scope;
    GumDukHeapPtr jic;
    GumDukHeapPtr retval;

    _gum_duk_scope_enter (&scope, core);

    jic = (entry->on_enter != NULL)
        ? *GUM_LINCTX_GET_FUNC_INVDATA (ic, GumDukHeapPtr)
        : NULL;
    if (jic != NULL)
    {
      //JSValueUnprotect (ctx, jic);
      gumjs_invocation_context_update_handle (ctx, jic, ic);
    }
    else
    {
      jic = gumjs_invocation_context_new (ctx, ic, *depth, self);
    }

    retval = gumjs_invocation_return_value_new (ctx, ic, self);

    duk_push_heapptr (ctx, entry->on_leave);
    duk_push_heapptr (ctx, jic);
    duk_push_heapptr (ctx, retval);

    duk_call (ctx, 2);
    duk_pop (ctx);

    gumjs_invocation_return_value_update_context (ctx, retval, NULL);
    gumjs_invocation_context_update_handle (ctx, jic, NULL);

    _gum_duk_scope_leave (&scope);
  }
}

static GumDukHeapPtr
gumjs_invocation_context_new (duk_context * ctx,
                              GumInvocationContext * handle,
                              gint depth,
                              GumDukInterceptor * parent)
{
  GumDukInvocationContext * sic;
  GumDukHeapPtr result;

  sic = g_slice_new (GumDukInvocationContext);
  sic->handle = handle;
  sic->cpu_context = NULL;
  sic->depth = depth;

  duk_push_heapptr (ctx, parent->invocation_context);
  // [ InvocationContext ]
  duk_new (ctx, 0);
  // [ invocationcontextinst ]
  result = duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  // []

  _gumjs_set_private_data (ctx, result, sic);
  return result;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_context_finalize)
{
  if (_gumjs_is_arg0_equal_to_prototype (ctx, "InvocationContext"))
    return 0;

  GumDukInvocationContext * self = GUM_DUK_INVOCATION_CONTEXT (object);

  g_slice_free (GumDukInvocationContext, self);
  return 0;
}

static void
gumjs_invocation_context_update_handle (duk_context * ctx,
                                        GumDukHeapPtr jic,
                                        GumInvocationContext * handle)
{
  GumDukInvocationContext * self = GUM_DUK_INVOCATION_CONTEXT (jic);

  self->handle = handle;
  g_clear_pointer (&self->cpu_context, _gumjs_cpu_context_detach);
}

static gboolean
gumjs_invocation_context_check_valid (GumDukInvocationContext * self,
                                      duk_context * ctx)
{
  if (self->handle == NULL)
  {
    _gumjs_throw (ctx, "invalid operation");
    return FALSE;
  }

  return TRUE;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_return_address)
{
  GumDukInvocationContext * self = GUM_DUK_INVOCATION_CONTEXT (_gumjs_duk_get_this (ctx));

  if (!gumjs_invocation_context_check_valid (self, ctx))
  {
    duk_push_null (ctx);
    return 1;
  }

  duk_push_heapptr (ctx, _gumjs_native_pointer_new (ctx,
      gum_invocation_context_get_return_address (self->handle), args->core));
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_cpu_context)
{
  GumDukInvocationContext * self = GUM_DUK_INVOCATION_CONTEXT (_gumjs_duk_get_this (ctx));

  if (!gumjs_invocation_context_check_valid (self, ctx))
  {
    duk_push_null (ctx);
    return 1;
  }

  if (self->cpu_context == NULL)
  {
    self->cpu_context = _gumjs_cpu_context_new (ctx, self->handle->cpu_context,
        GUM_CPU_CONTEXT_READONLY, args->core);
  }

  duk_push_heapptr (ctx, self->cpu_context);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_system_error)
{
  GumDukInvocationContext * self = GUM_DUK_INVOCATION_CONTEXT (_gumjs_duk_get_this (ctx));

  if (!gumjs_invocation_context_check_valid (self, ctx))
  {
    duk_push_null (ctx);
    return 1;
  }

  duk_push_number (ctx, self->handle->system_error);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_invocation_context_set_system_error)
{
  gint value;
  GumDukInvocationContext * self;

  if (!_gumjs_args_parse (ctx, "i", &value))
  {
    duk_push_boolean (ctx, FALSE);
    return 1;
  }

  self = GUM_DUK_INVOCATION_CONTEXT (_gumjs_duk_get_this (ctx));

  if (!gumjs_invocation_context_check_valid (self, ctx))
  {
    duk_push_boolean (ctx, FALSE);
    return 1;
  }

  self->handle->system_error = value;
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_thread_id)
{
  GumDukInvocationContext * self = GUM_DUK_INVOCATION_CONTEXT (_gumjs_duk_get_this (ctx));

  if (!gumjs_invocation_context_check_valid (self, ctx))
  {
    duk_push_null (ctx);
    return 1;
  }

  duk_push_number (ctx,
      gum_invocation_context_get_thread_id (self->handle));
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_depth)
{
  GumDukInvocationContext * self = GUM_DUK_INVOCATION_CONTEXT (_gumjs_duk_get_this (ctx));

  if (!gumjs_invocation_context_check_valid (self, ctx))
  {
    duk_push_null (ctx);
    return 1;
  }

  duk_push_number (ctx, self->depth);
  return 1;
}

static GumDukHeapPtr
gumjs_invocation_args_new (duk_context * ctx,
                           GumInvocationContext * ic,
                           GumDukInterceptor * parent)
{
  GumDukHeapPtr result;
  duk_push_heapptr (ctx, parent->invocation_args);
  duk_new (ctx, 0);
  result = duk_require_heapptr (ctx, -1);
  _gumjs_set_private_data (ctx, result, ic);
  return result;
}

static gboolean
gumjs_invocation_args_try_get_context (duk_context * ctx,
                                       GumDukHeapPtr value,
                                       GumInvocationContext ** result)
{
  GumInvocationContext * ic;

  ic = _gumjs_get_private_data (ctx, value);
  if (ic == NULL)
  {
    _gumjs_throw (ctx, "invalid operation");
    return FALSE;
  }

  *result = ic;
  return TRUE;
}

static void
gumjs_invocation_args_update_context (duk_context * ctx,
                                      GumDukHeapPtr value,
                                      GumInvocationContext * ic)
{
  _gumjs_set_private_data (ctx, value, ic);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_invocation_args_construct)
{
  duk_push_heapptr (ctx, _gumjs_duk_create_proxy_accessors (ctx, gumjs_invocation_args_get_property,
      gumjs_invocation_args_set_property));
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_args_get_property)
{
  guint n;
  GumInvocationContext * ic;

  if (!_gumjs_uint_try_parse (ctx, duk_get_string (ctx, 1), &n))
  {
    duk_push_null (ctx);
    return 1;
  }

  if (!gumjs_invocation_args_try_get_context (ctx, _gumjs_duk_get_this (ctx), &ic))
  {
    duk_push_null (ctx);
    return 1;
  }

  duk_push_heapptr (ctx, _gumjs_native_pointer_new (ctx,
      gum_invocation_context_get_nth_argument (ic, n),
      args->core));
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_invocation_args_set_property)
{
  GumInvocationContext * ic;
  guint n;
  gpointer value;

  if (!_gumjs_uint_try_parse (ctx, duk_get_string (ctx, 1), &n))
  {
    duk_push_boolean (ctx, FALSE);
    return 1;
  }

  if (!_gumjs_args_parse (ctx, "p", &value))
  {
    duk_push_boolean (ctx, FALSE);
    return 1;
  }

  if (!gumjs_invocation_args_try_get_context (ctx, _gumjs_duk_get_this (ctx), &ic))
  {
    duk_push_null (ctx);
    return 1;
  }

  gum_invocation_context_replace_nth_argument (ic, n, value);
  return 0;
}

static GumDukHeapPtr
gumjs_invocation_return_value_new (duk_context * ctx,
                                   GumInvocationContext * ic,
                                   GumDukInterceptor * parent)
{
  GumDukHeapPtr result;
  GumDukInvocationReturnValue * retval;
  GumDukNativePointer * ptr;

  retval = g_slice_new (GumDukInvocationReturnValue);

  ptr = &retval->parent;
  ptr->instance_size = sizeof (GumDukInvocationReturnValue);
  ptr->value = gum_invocation_context_get_return_value (ic);

  retval->ic = ic;
  duk_push_heapptr (ctx, parent->invocation_retval);
  duk_new (ctx, 0);
  result = duk_require_heapptr (ctx, -1);
  duk_pop (ctx);
  _gumjs_set_private_data (ctx, result, retval);
  return result;
}

static gboolean
gumjs_invocation_return_value_try_get_context (
    duk_context * ctx,
    GumDukHeapPtr value,
    GumDukInvocationReturnValue ** retval,
    GumInvocationContext ** ic)
{
  GumDukInvocationReturnValue * self;

  self = _gumjs_get_private_data (ctx, value);
  if (self->ic == NULL)
  {
    _gumjs_throw (ctx, "invalid operation");
    return FALSE;
  }

  *retval = self;
  *ic = self->ic;
  return TRUE;
}

static void
gumjs_invocation_return_value_update_context (duk_context * ctx,
                                              GumDukHeapPtr value,
                                              GumInvocationContext * ic)
{
  GumDukInvocationReturnValue * self;

  self = _gumjs_get_private_data (ctx, value);

  self->ic = NULL;
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_return_value_replace)
{
  GumDukInvocationReturnValue * self;
  GumInvocationContext * ic;
  GumDukNativePointer * ptr;

  if (!gumjs_invocation_return_value_try_get_context (ctx, _gumjs_duk_get_this (ctx), &self,
      &ic))
  {
    duk_push_null (ctx);
    return 1;
  }
  ptr = &self->parent;

  if (!_gumjs_args_parse (ctx, "p~", &ptr->value))
  {
    duk_push_null (ctx);
    return 1;
  }

  gum_invocation_context_replace_return_value (ic, ptr->value);

  duk_push_undefined (ctx);
  return 1;
}
