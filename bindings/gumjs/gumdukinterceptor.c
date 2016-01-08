/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukinterceptor.h"

#include "gumdukmacros.h"
#include "gumdukscript-priv.h"

#define GUM_DUK_INVOCATION_CONTEXT(o) \
  ((GumDukInvocationContext *) _gumjs_get_private_data (ctx, o))
#define GUM_DUK_INVOCATION_ARGS(o) \
  ((GumDukInvocationArgs *) _gumjs_get_private_data (ctx, o))
#define GUM_DUK_INVOCATION_RETURN_VALUE(o) \
  ((GumDukInvocationReturnValue *) _gumjs_get_private_data (ctx, o))

#ifdef G_OS_WIN32
# define GUM_SYSTEM_ERROR_FIELD "lastError"
#else
# define GUM_SYSTEM_ERROR_FIELD "errno"
#endif

typedef struct _GumDukAttachEntry GumDukAttachEntry;
typedef struct _GumDukReplaceEntry GumDukReplaceEntry;

struct _GumDukInvocationContext
{
  GumDukHeapPtr object;
  GumInvocationContext * handle;
  GumDukHeapPtr cpu_context;
  gint depth;

  GumDukInterceptor * interceptor;
};

struct _GumDukInvocationArgs
{
  GumDukHeapPtr object;
  GumInvocationContext * ic;

  duk_context * ctx;
};

struct _GumDukInvocationReturnValue
{
  GumDukNativePointer parent;

  GumDukHeapPtr object;
  GumInvocationContext * ic;

  duk_context * ctx;
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
  GumDukHeapPtr replacement;
  GumDukCore * core;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_interceptor_construct)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_attach)
static void gum_duk_attach_entry_free (GumDukAttachEntry * entry);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_detach_all)
static void gum_duk_interceptor_detach_all (GumDukInterceptor * self);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_replace)
static void gum_duk_replace_entry_free (GumDukReplaceEntry * entry);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_revert)

static GumDukInvocationContext * gumjs_invocation_context_new (
    GumDukInterceptor * parent);
static void gumjs_invocation_context_release (GumDukInvocationContext * self);
static void gumjs_invocation_context_reset (GumDukInvocationContext * self,
    GumInvocationContext * handle, gint depth);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_invocation_context_construct)
GUMJS_DECLARE_FINALIZER (gumjs_invocation_context_finalize)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_system_error)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_thread_id)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_depth)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_property)

static GumDukInvocationArgs * gumjs_invocation_args_new (
    GumDukInterceptor * parent);
static void gumjs_invocation_args_release (GumDukInvocationArgs * self);
static void gumjs_invocation_args_reset (GumDukInvocationArgs * self,
    GumInvocationContext * ic);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_invocation_args_construct)
GUMJS_DECLARE_FINALIZER (gumjs_invocation_args_finalize)
GUMJS_DECLARE_GETTER (gumjs_invocation_args_get_property)
GUMJS_DECLARE_SETTER (gumjs_invocation_args_set_property)

static GumDukInvocationReturnValue * gumjs_invocation_return_value_new (
    GumDukInterceptor * parent);
static void gumjs_invocation_return_value_release (
    GumDukInvocationReturnValue * self);
static void gumjs_invocation_return_value_reset (
    GumDukInvocationReturnValue * self, GumInvocationContext * ic);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_invocation_return_value_construct)
GUMJS_DECLARE_FINALIZER (gumjs_invocation_return_value_finalize)
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
  { "replace", gumjs_invocation_return_value_replace, 1 },

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

  duk_push_c_function (ctx, gumjs_interceptor_construct, 0);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_interceptor_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_new (ctx, 0);
  _gumjs_set_private_data (ctx, duk_require_heapptr (ctx, -1), self);
  duk_put_global_string (ctx, "Interceptor");

  duk_push_c_function (ctx, gumjs_invocation_context_construct, 0);
  duk_push_object (ctx);
  duk_push_c_function (ctx, gumjs_invocation_context_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->invocation_context = _gumjs_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "InvocationContext");
  _gumjs_duk_add_properties_to_class (ctx, "InvocationContext",
      gumjs_invocation_context_values);

  duk_push_c_function (ctx, gumjs_invocation_args_construct, 0);
  duk_push_object (ctx);
  duk_push_c_function (ctx, gumjs_invocation_args_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->invocation_args = _gumjs_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "InvocationArgs");

  _gumjs_duk_create_subclass (ctx, "NativePointer", "InvocationReturnValue",
      gumjs_invocation_return_value_construct, 1, NULL);
  duk_get_global_string (ctx, "InvocationReturnValue");
  duk_get_prop_string (ctx, -1, "prototype");
  duk_push_c_function (ctx, gumjs_invocation_return_value_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_function_list (ctx, -1, gumjs_invocation_return_value_functions);
  duk_pop (ctx);
  self->invocation_retval = _gumjs_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  self->cached_invocation_context = gumjs_invocation_context_new (self);
  self->cached_invocation_context_in_use = FALSE;

  self->cached_invocation_args = gumjs_invocation_args_new (self);
  self->cached_invocation_args_in_use = FALSE;

  self->cached_invocation_return_value = gumjs_invocation_return_value_new (
      self);
  self->cached_invocation_return_value_in_use = FALSE;
}

void
_gum_duk_interceptor_flush (GumDukInterceptor * self)
{
  gum_duk_interceptor_detach_all (self);

  g_hash_table_remove_all (self->replacement_by_address);
}

void
_gum_duk_interceptor_dispose (GumDukInterceptor * self)
{
  duk_context * ctx = self->core->ctx;

  gumjs_invocation_context_release (self->cached_invocation_context);
  gumjs_invocation_args_release (self->cached_invocation_args);
  gumjs_invocation_return_value_release (self->cached_invocation_return_value);

  _gumjs_duk_release_heapptr (ctx, self->invocation_context);
  _gumjs_duk_release_heapptr (ctx, self->invocation_args);
  _gumjs_duk_release_heapptr (ctx, self->invocation_retval);
}

void
_gum_duk_interceptor_finalize (GumDukInterceptor * self)
{
  g_clear_pointer (&self->attach_entries, g_queue_free);
  g_clear_pointer (&self->replacement_by_address, g_hash_table_unref);

  g_clear_pointer (&self->interceptor, g_object_unref);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_interceptor_construct)
{
  return 0;
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

  _gum_duk_require_args (ctx, "pF{onEnter?,onLeave?}", &target,
      &on_enter, &on_leave);

  entry = g_slice_new (GumDukAttachEntry);
  _gumjs_duk_protect (ctx, on_enter);
  entry->on_enter = on_enter;
  _gumjs_duk_protect (ctx, on_leave);
  entry->on_leave = on_leave;
  entry->ctx = core->ctx;

  attach_ret = gum_interceptor_attach_listener (self->interceptor, target,
      GUM_INVOCATION_LISTENER (core->script), entry);

  if (attach_ret != GUM_ATTACH_OK)
    goto unable_to_attach;

  g_queue_push_tail (self->attach_entries, entry);

  return 0;

unable_to_attach:
  {
    gum_duk_attach_entry_free (entry);

    switch (attach_ret)
    {
      case GUM_ATTACH_WRONG_SIGNATURE:
        _gumjs_throw (ctx, "unable to intercept function at %p; "
            "please file a bug", target);
      case GUM_ATTACH_ALREADY_ATTACHED:
        _gumjs_throw (ctx, "already attached to this function");
      default:
        g_assert_not_reached ();
    }

    return 0;
  }
}

static void
gum_duk_attach_entry_free (GumDukAttachEntry * entry)
{
  _gumjs_duk_unprotect (entry->ctx, entry->on_enter);
  _gumjs_duk_unprotect (entry->ctx, entry->on_leave);

  g_slice_free (GumDukAttachEntry, entry);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_detach_all)
{
  GumDukInterceptor * self;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  gum_duk_interceptor_detach_all (self);

  return 0;
}

static void
gum_duk_interceptor_detach_all (GumDukInterceptor * self)
{
  gum_interceptor_detach_listener (self->interceptor,
      GUM_INVOCATION_LISTENER (self->core->script));

  while (!g_queue_is_empty (self->attach_entries))
  {
    GumDukAttachEntry * entry = g_queue_pop_tail (self->attach_entries);

    gum_duk_attach_entry_free (entry);
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace)
{
  GumDukInterceptor * self;
  GumDukCore * core = args->core;
  gpointer target, replacement;
  GumDukHeapPtr replacement_value;
  GumDukReplaceEntry * entry;
  GumReplaceReturn replace_ret;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));

  _gum_duk_require_args (ctx, "pO", &target, &replacement_value);

  duk_push_heapptr (ctx, replacement_value);
  if (!_gum_duk_get_pointer (ctx, -1, &replacement))
    _gumjs_throw (ctx, "expected a pointer");
  duk_pop (ctx);

  entry = g_slice_new (GumDukReplaceEntry);
  entry->interceptor = self->interceptor;
  entry->target = target;
  entry->replacement = replacement_value;
  entry->core = core;

  replace_ret = gum_interceptor_replace_function (self->interceptor, target,
      replacement, NULL);
  if (replace_ret != GUM_REPLACE_OK)
    goto unable_to_replace;

  _gumjs_duk_protect (ctx, replacement_value);

  g_hash_table_insert (self->replacement_by_address, target, entry);

  return 0;

unable_to_replace:
  {
    g_slice_free (GumDukReplaceEntry, entry);

    switch (replace_ret)
    {
      case GUM_REPLACE_WRONG_SIGNATURE:
        _gumjs_throw (ctx, "unable to intercept function at %p; "
            "please file a bug", target);
      case GUM_REPLACE_ALREADY_REPLACED:
        _gumjs_throw (ctx, "already replaced this function");
      default:
        g_assert_not_reached ();
    }

    return 0;
  }
}

static void
gum_duk_replace_entry_free (GumDukReplaceEntry * entry)
{
  GumDukCore * core = entry->core;

  gum_interceptor_revert_function (entry->interceptor, entry->target);

  _gumjs_duk_unprotect (core->ctx, entry->replacement);

  g_slice_free (GumDukReplaceEntry, entry);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_revert)
{
  GumDukInterceptor * self;
  GumDukCore * core;
  gpointer target;

  self = _gumjs_get_private_data (ctx, _gumjs_duk_get_this (ctx));
  core = self->core;

  _gum_duk_require_args (ctx, "p", &target);

  g_hash_table_remove (self->replacement_by_address, target);

  return 0;
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
    GumDukInvocationContext * jic;
    GumDukInvocationArgs * args;

    _gum_duk_scope_enter (&scope, core);

    if (!self->cached_invocation_context_in_use)
    {
      jic = self->cached_invocation_context;
      self->cached_invocation_context_in_use = TRUE;
    }
    else
    {
      jic = gumjs_invocation_context_new (self);
    }
    gumjs_invocation_context_reset (jic, ic, *depth);

    if (!self->cached_invocation_args_in_use)
    {
      args = self->cached_invocation_args;
      self->cached_invocation_args_in_use = TRUE;
    }
    else
    {
      args = gumjs_invocation_args_new (self);
    }
    gumjs_invocation_args_reset (args, ic);

    duk_push_heapptr (ctx, entry->on_enter);
    duk_push_heapptr (ctx, jic->object);
    duk_push_heapptr (ctx, args->object);
    _gum_duk_scope_call_method (&scope, 1);
    duk_pop (ctx);

    gumjs_invocation_args_reset (args, NULL);
    if (args == self->cached_invocation_args)
      self->cached_invocation_args_in_use = FALSE;
    else
      gumjs_invocation_args_release (args);

    gumjs_invocation_context_reset (jic, NULL, 0);
    if (entry->on_leave != NULL)
    {
      *GUM_LINCTX_GET_FUNC_INVDATA (ic, GumDukHeapPtr) = jic;
    }
    else
    {
      if (jic == self->cached_invocation_context)
        self->cached_invocation_context_in_use = FALSE;
      else
        gumjs_invocation_context_release (jic);
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
    GumDukInvocationContext * jic;
    GumDukInvocationReturnValue * retval;

    _gum_duk_scope_enter (&scope, core);

    jic = (entry->on_enter != NULL)
        ? *GUM_LINCTX_GET_FUNC_INVDATA (ic, GumDukInvocationContext *)
        : NULL;
    if (jic == NULL)
    {
      if (!self->cached_invocation_context_in_use)
      {
        jic = self->cached_invocation_context;
        self->cached_invocation_context_in_use = TRUE;
      }
      else
      {
        jic = gumjs_invocation_context_new (self);
      }
    }
    gumjs_invocation_context_reset (jic, ic, *depth);

    if (!self->cached_invocation_return_value_in_use)
    {
      retval = self->cached_invocation_return_value;
      self->cached_invocation_return_value_in_use = TRUE;
    }
    else
    {
      retval = gumjs_invocation_return_value_new (self);
    }
    gumjs_invocation_return_value_reset (retval, ic);

    duk_push_heapptr (ctx, entry->on_leave);
    duk_push_heapptr (ctx, jic->object);
    duk_push_heapptr (ctx, retval->object);
    _gum_duk_scope_call_method (&scope, 1);
    duk_pop (ctx);

    gumjs_invocation_return_value_reset (retval, NULL);
    if (retval == self->cached_invocation_return_value)
      self->cached_invocation_return_value_in_use = FALSE;
    else
      gumjs_invocation_return_value_release (retval);

    gumjs_invocation_context_reset (jic, NULL, 0);
    if (jic == self->cached_invocation_context)
      self->cached_invocation_context_in_use = FALSE;
    else
      gumjs_invocation_context_release (jic);

    _gum_duk_scope_leave (&scope);
  }
}

static GumDukInvocationContext *
gumjs_invocation_context_new (GumDukInterceptor * parent)
{
  duk_context * ctx = parent->core->ctx;
  GumDukInvocationContext * jic;
  GumDukHeapPtr target;

  jic = g_slice_new (GumDukInvocationContext);

  duk_push_heapptr (ctx, parent->invocation_context);
  duk_new (ctx, 0);
  target = duk_require_heapptr (ctx, -1);
  _gumjs_set_private_data (ctx, target, jic);
  jic->object = _gumjs_duk_create_proxy_accessors (ctx, target, NULL,
      gumjs_invocation_context_set_property);
  duk_pop (ctx);

  jic->handle = NULL;
  jic->cpu_context = NULL;
  jic->depth = 0;

  jic->interceptor = parent;

  return jic;
}

static void
gumjs_invocation_context_release (GumDukInvocationContext * self)
{
  _gumjs_duk_release_heapptr (self->interceptor->core->ctx, self->object);
}

static void
gumjs_invocation_context_reset (GumDukInvocationContext * self,
                                GumInvocationContext * handle,
                                gint depth)
{
  self->handle = handle;
  self->depth = depth;

  if (self->cpu_context != NULL)
  {
    duk_context * ctx = self->interceptor->core->ctx;

    _gumjs_cpu_context_detach (ctx, self->cpu_context);
    _gumjs_duk_release_heapptr (ctx, self->cpu_context);
    self->cpu_context = NULL;
  }
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_invocation_context_construct)
{
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_context_finalize)
{
  GumDukInvocationContext * self;

  if (_gumjs_is_arg0_equal_to_prototype (ctx, "InvocationContext"))
    return 0;

  self = GUM_DUK_INVOCATION_CONTEXT (duk_require_heapptr (ctx, 0));

  g_slice_free (GumDukInvocationContext, self);

  return 0;
}

static void
gumjs_invocation_context_check_valid (GumDukInvocationContext * self,
                                      duk_context * ctx)
{
  if (self->handle == NULL)
    _gumjs_throw (ctx, "invalid operation");
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_return_address)
{
  GumDukInvocationContext * self;

  self = GUM_DUK_INVOCATION_CONTEXT (_gumjs_duk_get_this (ctx));

  gumjs_invocation_context_check_valid (self, ctx);

  _gumjs_native_pointer_push (ctx,
      gum_invocation_context_get_return_address (self->handle), args->core);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_cpu_context)
{
  GumDukInvocationContext * self;

  self = GUM_DUK_INVOCATION_CONTEXT (_gumjs_duk_get_this (ctx));

  gumjs_invocation_context_check_valid (self, ctx);

  if (self->cpu_context == NULL)
  {
    self->cpu_context = _gumjs_cpu_context_new (ctx, self->handle->cpu_context,
        GUM_CPU_CONTEXT_READWRITE, args->core);
  }

  duk_push_heapptr (ctx, self->cpu_context);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_system_error)
{
  GumDukInvocationContext * self;

  self = GUM_DUK_INVOCATION_CONTEXT (_gumjs_duk_get_this (ctx));

  gumjs_invocation_context_check_valid (self, ctx);

  duk_push_number (ctx, self->handle->system_error);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_invocation_context_set_system_error)
{
  gint value;
  GumDukInvocationContext * self;

  _gum_duk_require_args (ctx, "i", &value);

  self = GUM_DUK_INVOCATION_CONTEXT (_gumjs_duk_get_this (ctx));

  gumjs_invocation_context_check_valid (self, ctx);

  self->handle->system_error = value;
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_thread_id)
{
  GumDukInvocationContext * self;

  self = GUM_DUK_INVOCATION_CONTEXT (_gumjs_duk_get_this (ctx));

  gumjs_invocation_context_check_valid (self, ctx);

  duk_push_number (ctx,
      gum_invocation_context_get_thread_id (self->handle));
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_depth)
{
  GumDukInvocationContext * self;

  self = GUM_DUK_INVOCATION_CONTEXT (_gumjs_duk_get_this (ctx));

  gumjs_invocation_context_check_valid (self, ctx);

  duk_push_number (ctx, self->depth);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_invocation_context_set_property)
{
  GumDukHeapPtr target;
  const gchar * property;
  GumDukHeapPtr receiver;
  GumDukInvocationContext * self;
  GumDukInterceptor * interceptor;

  target = _gumjs_duk_require_heapptr (ctx, 0);
  property = duk_safe_to_string (ctx, 1);
  receiver = _gumjs_duk_require_heapptr (ctx, 3);
  self = GUM_DUK_INVOCATION_CONTEXT (target);
  interceptor = self->interceptor;

  duk_dup (ctx, 2);
  duk_put_prop_string (ctx, 0, property);

  if (receiver == interceptor->cached_invocation_context->object)
  {
    interceptor->cached_invocation_context =
        gumjs_invocation_context_new (interceptor);
    interceptor->cached_invocation_context_in_use = FALSE;
  }

  duk_push_true (ctx);
  return 1;
}

static GumDukInvocationArgs *
gumjs_invocation_args_new (GumDukInterceptor * parent)
{
  duk_context * ctx = parent->core->ctx;
  GumDukInvocationArgs * args;

  args = g_slice_new (GumDukInvocationArgs);

  duk_push_heapptr (ctx, parent->invocation_args);
  duk_new (ctx, 0);
  args->object = _gumjs_duk_require_heapptr (ctx, -1);
  _gumjs_set_private_data (ctx, args->object, args);
  duk_pop (ctx);

  args->ic = NULL;
  args->ctx = ctx;

  return args;
}

static void
gumjs_invocation_args_release (GumDukInvocationArgs * self)
{
  _gumjs_duk_release_heapptr (self->ctx, self->object);
}

static void
gumjs_invocation_args_reset (GumDukInvocationArgs * self,
                             GumInvocationContext * ic)
{
  self->ic = ic;
}

static GumInvocationContext *
gumjs_invocation_args_require_context (duk_context * ctx,
                                       duk_idx_t index)
{
  GumDukInvocationArgs * self;

  self = GUM_DUK_INVOCATION_ARGS (duk_require_heapptr (ctx, index));

  if (self->ic == NULL)
    _gumjs_throw (self->ctx, "invalid operation");

  return self->ic;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_invocation_args_construct)
{
  GumDukHeapPtr result;

  result = _gumjs_duk_create_proxy_accessors (ctx, _gumjs_duk_get_this (ctx),
      gumjs_invocation_args_get_property, gumjs_invocation_args_set_property);
  duk_push_heapptr (ctx, result);
  _gumjs_duk_release_heapptr (ctx, result);
  return 1;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_args_finalize)
{
  GumDukInvocationArgs * self;

  if (_gumjs_is_arg0_equal_to_prototype (ctx, "InvocationArgs"))
    return 0;

  self = GUM_DUK_INVOCATION_ARGS (duk_require_heapptr (ctx, 0));

  g_slice_free (GumDukInvocationArgs, self);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_args_get_property)
{
  const gchar * property;
  GumInvocationContext * ic;
  guint n;

  property = duk_safe_to_string (ctx, 1);

  if (strcmp ("toJSON", property) == 0)
  {
    duk_push_string (ctx, "invocation-args");
    return 1;
  }

  ic = gumjs_invocation_args_require_context (ctx, 0);
  n = _gumjs_uint_parse (ctx, property);

  _gumjs_native_pointer_push (ctx,
      gum_invocation_context_get_nth_argument (ic, n), args->core);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_invocation_args_set_property)
{
  GumInvocationContext * ic;
  guint n;
  gpointer value = NULL;

  ic = gumjs_invocation_args_require_context (ctx, 0);
  n = _gumjs_uint_parse (ctx, duk_safe_to_string (ctx, 1));

  if (_gumjs_is_instanceof (ctx, duk_get_heapptr (ctx, 2), "NativePointer"))
  {
    value = _gumjs_native_pointer_value (ctx, duk_require_heapptr (ctx, 2));
  }
  else if (duk_is_object (ctx, 2))
  {
    duk_get_prop_string (ctx, 2, "handle");
    if (_gumjs_is_instanceof (ctx, duk_get_heapptr (ctx, -1), "NativePointer"))
      value = _gumjs_native_pointer_value (ctx, duk_require_heapptr (ctx, -2));
    else
      _gumjs_throw (ctx, "invalid pointer value");
    duk_pop (ctx);
  }
  else
  {
    duk_push_false (ctx);
    return 1;
  }

  gum_invocation_context_replace_nth_argument (ic, n, value);

  duk_push_true (ctx);
  return 1;
}

static GumDukInvocationReturnValue *
gumjs_invocation_return_value_new (GumDukInterceptor * parent)
{
  duk_context * ctx = parent->core->ctx;
  GumDukInvocationReturnValue * retval;
  GumDukNativePointer * ptr;

  retval = g_slice_new (GumDukInvocationReturnValue);

  ptr = &retval->parent;
  ptr->instance_size = sizeof (GumDukInvocationReturnValue);
  ptr->value = NULL;

  duk_push_heapptr (ctx, parent->invocation_retval);
  duk_new (ctx, 0);
  retval->object = _gumjs_duk_require_heapptr (ctx, -1);
  _gumjs_set_private_data (ctx, retval->object, retval);
  duk_pop (ctx);

  retval->ic = NULL;
  retval->ctx = ctx;

  return retval;
}

static void
gumjs_invocation_return_value_release (GumDukInvocationReturnValue * self)
{
  _gumjs_duk_release_heapptr (self->ctx, self->object);
}

static void
gumjs_invocation_return_value_reset (GumDukInvocationReturnValue * self,
                                     GumInvocationContext * ic)
{
  GumDukNativePointer * ptr;

  ptr = &self->parent;
  if (ic != NULL)
    ptr->value = gum_invocation_context_get_return_value (ic);
  else
    ptr->value = NULL;

  self->ic = ic;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_invocation_return_value_construct)
{
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_return_value_finalize)
{
  GumDukInvocationReturnValue * self;

  if (_gumjs_is_arg0_equal_to_prototype (ctx, "InvocationReturnValue"))
    return 0;

  self = GUM_DUK_INVOCATION_RETURN_VALUE (duk_require_heapptr (ctx, 0));

  g_slice_free (GumDukInvocationReturnValue, self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_return_value_replace)
{
  GumDukInvocationReturnValue * self;
  GumDukNativePointer * ptr;

  self = GUM_DUK_INVOCATION_RETURN_VALUE (_gumjs_duk_get_this (ctx));
  if (self->ic == NULL)
    _gumjs_throw (ctx, "invalid operation");

  ptr = &self->parent;
  _gum_duk_require_args (ctx, "p~", &ptr->value);

  gum_invocation_context_replace_return_value (self->ic, ptr->value);

  return 0;
}
