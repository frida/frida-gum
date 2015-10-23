/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptinterceptor.h"

#include "gumjscript-priv.h"
#include "gumjscriptmacros.h"

#include <gum/gum-init.h>

typedef struct _GumScriptAttachEntry GumScriptAttachEntry;
typedef struct _GumScriptReplaceEntry GumScriptReplaceEntry;

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

GUMJS_DECLARE_GETTER (gumjs_invocation_args_get_property)
GUMJS_DECLARE_SETTER (gumjs_invocation_args_set_property)

GUMJS_DECLARE_FUNCTION (gumjs_interceptor_throw_not_yet_available)

static void gum_script_interceptor_adjust_ignore_level_unlocked (
    GumThreadId thread_id, gint adjustment, GumInterceptor * interceptor);
static gboolean gum_flush_pending_unignores (gpointer user_data);

static const JSPropertyAttributes gumjs_attrs =
    kJSPropertyAttributeReadOnly | kJSPropertyAttributeDontDelete;

static const JSStaticFunction gumjs_interceptor_functions[] =
{
  { "_attach", gumjs_interceptor_attach, gumjs_attrs },
  { "detachAll", gumjs_interceptor_detach_all, gumjs_attrs },
  { "_replace", gumjs_interceptor_throw_not_yet_available, gumjs_attrs },
  { "revert", gumjs_interceptor_throw_not_yet_available, gumjs_attrs },

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
  def.className = "InvocationArgs";
  def.getProperty = gumjs_invocation_args_get_property;
  def.setProperty = gumjs_invocation_args_set_property;
  self->invocation_args = JSClassCreate (&def);
}

void
_gum_script_interceptor_dispose (GumScriptInterceptor * self)
{
  gum_script_interceptor_detach_all (self);

  g_hash_table_remove_all (self->replacement_by_address);

  JSClassRelease (self->invocation_args);
  self->invocation_args = NULL;
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

  if (!_gumjs_args_parse (args, "pC{onEnter?,onLeave?}",
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
    JSValueRef args;

    _gum_script_scope_enter (&scope, core);

    args = JSObjectMake (ctx, self->invocation_args, ic);

    JSObjectCallAsFunction (ctx, entry->on_enter, NULL, 1, &args,
        &scope.exception);

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
    GumScriptScope scope;

    _gum_script_scope_enter (&scope, core);

    JSObjectCallAsFunction (entry->ctx, entry->on_leave, NULL, 0, NULL,
        &scope.exception);

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

GUMJS_DEFINE_GETTER (gumjs_invocation_args_get_property)
{
  GumInvocationContext * ic;
  guint n;

  ic = JSObjectGetPrivate (object);

  if (!_gumjs_uint_try_parse (ctx, property_name, &n, NULL))
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

  ic = JSObjectGetPrivate (object);

  if (!_gumjs_uint_try_parse (ctx, property_name, &n, NULL))
    return false;

  if (!_gumjs_args_parse (args, "p", &value))
    return false;

  gum_invocation_context_replace_nth_argument (ic, n, value);
  return true;
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
