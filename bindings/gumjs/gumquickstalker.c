/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickstalker.h"

#include "gumquickeventsink.h"
#include "gumquickmacros.h"

#define GUM_QUICK_TYPE_CALLBACK_TRANSFORMER \
    (gum_quick_callback_transformer_get_type ())
#define GUM_QUICK_CALLBACK_TRANSFORMER_CAST(obj) \
    ((GumQuickCallbackTransformer *) (obj))

typedef struct _GumQuickCallbackTransformer GumQuickCallbackTransformer;
typedef struct _GumQuickCallbackTransformerClass GumQuickCallbackTransformerClass;
typedef struct _GumQuickStalkerIterator GumQuickStalkerIterator;
typedef struct _GumQuickCallout GumQuickCallout;
typedef struct _GumQuickCallProbe GumQuickCallProbe;

struct _GumQuickCallbackTransformer
{
  GObject parent;

  GumThreadId thread_id;
  GumQuickHeapPtr callback;

  GumQuickStalker * module;
};

struct _GumQuickCallbackTransformerClass
{
  GObjectClass parent_class;
};

struct _GumQuickStalkerIterator
{
  GumStalkerIterator * handle;
  GumQuickInstructionValue * instruction;

  GumQuickStalker * module;
};

struct _GumQuickStalkerDefaultIterator
{
  GumQuickDefaultWriter parent;
  GumQuickStalkerIterator iterator;
};

struct _GumQuickStalkerSpecialIterator
{
  GumQuickSpecialWriter parent;
  GumQuickStalkerIterator iterator;
};

struct _GumQuickCallout
{
  GumQuickHeapPtr callback;

  GumQuickStalker * module;
};

struct _GumQuickCallProbe
{
  GumQuickHeapPtr callback;

  GumQuickStalker * module;
};

struct _GumQuickProbeArgs
{
  GumQuickHeapPtr object;
  GumCallSite * site;

  GumQuickCore * core;
};

static gboolean gum_quick_stalker_on_flush_timer_tick (GumQuickStalker * self);

GUMJS_DECLARE_GETTER (gumjs_stalker_get_trust_threshold)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_trust_threshold)

GUMJS_DECLARE_GETTER (gumjs_stalker_get_queue_capacity)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_queue_capacity)

GUMJS_DECLARE_GETTER (gumjs_stalker_get_queue_drain_interval)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_queue_drain_interval)

GUMJS_DECLARE_FUNCTION (gumjs_stalker_flush)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_garbage_collect)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_exclude)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_follow)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_unfollow)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_add_call_probe)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_remove_call_probe)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_parse)

static void gum_quick_callback_transformer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_callback_transformer_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumQuickCallbackTransformer,
                        gum_quick_callback_transformer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_STALKER_TRANSFORMER,
                            gum_quick_callback_transformer_iface_init))

static GumQuickStalkerDefaultIterator * gum_quick_stalker_default_iterator_new (
    GumQuickStalker * parent);
static void gum_quick_stalker_default_iterator_release (
    GumQuickStalkerDefaultIterator * self);
static void gum_quick_stalker_default_iterator_reset (
    GumQuickStalkerDefaultIterator * self, GumStalkerIterator * handle,
    GumStalkerOutput * output);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_stalker_default_iterator_construct)
GUMJS_DECLARE_FINALIZER (gumjs_stalker_default_iterator_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_default_iterator_next)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_default_iterator_keep)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_default_iterator_put_callout)

static GumQuickStalkerSpecialIterator * gum_quick_stalker_special_iterator_new (
    GumQuickStalker * parent);
static void gum_quick_stalker_special_iterator_release (
    GumQuickStalkerSpecialIterator * self);
static void gum_quick_stalker_special_iterator_reset (
    GumQuickStalkerSpecialIterator * self, GumStalkerIterator * handle,
    GumStalkerOutput * output);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_stalker_special_iterator_construct)
GUMJS_DECLARE_FINALIZER (gumjs_stalker_special_iterator_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_special_iterator_next)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_special_iterator_keep)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_special_iterator_put_callout)

static void gum_quick_callout_free (GumQuickCallout * callout);
static void gum_quick_callout_on_invoke (GumCpuContext * cpu_context,
    GumQuickCallout * self);

static void gum_quick_call_probe_free (GumQuickCallProbe * probe);
static void gum_quick_call_probe_on_fire (GumCallSite * site,
    GumQuickCallProbe * self);

static GumQuickProbeArgs * gum_quick_probe_args_new (GumQuickStalker * parent);
static void gum_quick_probe_args_release (GumQuickProbeArgs * self);
static void gum_quick_probe_args_reset (GumQuickProbeArgs * self,
    GumCallSite * site);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_probe_args_construct)
GUMJS_DECLARE_FINALIZER (gumjs_probe_args_finalize)
GUMJS_DECLARE_GETTER (gumjs_probe_args_get_property)
GUMJS_DECLARE_SETTER (gumjs_probe_args_set_property)

static GumQuickStalkerDefaultIterator * gum_quick_stalker_obtain_default_iterator (
    GumQuickStalker * self);
static void gum_quick_stalker_release_default_iterator (GumQuickStalker * self,
    GumQuickStalkerDefaultIterator * iterator);
static GumQuickStalkerSpecialIterator * gum_quick_stalker_obtain_special_iterator (
    GumQuickStalker * self);
static void gum_quick_stalker_release_special_iterator (GumQuickStalker * self,
    GumQuickStalkerSpecialIterator * iterator);
static GumQuickInstructionValue * gum_quick_stalker_obtain_instruction (
    GumQuickStalker * self);
static void gum_quick_stalker_release_instruction (GumQuickStalker * self,
    GumQuickInstructionValue * value);
static GumQuickCpuContext * gum_quick_stalker_obtain_cpu_context (
    GumQuickStalker * self);
static void gum_quick_stalker_release_cpu_context (GumQuickStalker * self,
    GumQuickCpuContext * cpu_context);
static GumQuickProbeArgs * gum_quick_stalker_obtain_probe_args (
    GumQuickStalker * self);
static void gum_quick_stalker_release_probe_args (GumQuickStalker * self,
    GumQuickProbeArgs * args);

static void gum_push_pointer (quick_context * ctx, gpointer value,
    gboolean stringify, GumQuickCore * core);

static const JSCFunctionListEntry gumjs_stalker_entries[] =
{
  JS_CGETSET_DEF ("trustThreshold", gumjs_stalker_get_trust_threshold,
      gumjs_stalker_set_trust_threshold),
  JS_CGETSET_DEF ("queueCapacity", gumjs_stalker_get_queue_capacity,
      gumjs_stalker_set_queue_capacity),
  JS_CGETSET_DEF ("queueDrainInterval", gumjs_stalker_get_queue_drain_interval,
      gumjs_stalker_set_queue_drain_interval),
  JS_CFUNC_DEF ("flush", 0, gumjs_stalker_flush),
  JS_CFUNC_DEF ("garbageCollect", 0, gumjs_stalker_garbage_collect),
  JS_CFUNC_DEF ("_exclude", 0, gumjs_stalker_exclude),
  JS_CFUNC_DEF ("_follow", 0, gumjs_stalker_follow),
  JS_CFUNC_DEF ("unfollow", 0, gumjs_stalker_unfollow),
  JS_CFUNC_DEF ("addCallProbe", 0, gumjs_stalker_add_call_probe),
  JS_CFUNC_DEF ("removeCallProbe", 0, gumjs_stalker_remove_call_probe),
  JS_CFUNC_DEF ("_parse", 0, gumjs_stalker_parse),
};

static const JSClassDef gumjs_stalker_default_iterator_def =
{
  .class_name = "StalkerDefaultIterator",
  .finalizer = gumjs_stalker_default_iterator_finalize,
};

static const JSCFunctionListEntry gumjs_stalker_default_iterator_entries[] = {
  JS_CFUNC_DEF ("next", 0, gumjs_stalker_default_iterator_next),
  JS_CFUNC_DEF ("keep", 0, gumjs_stalker_default_iterator_keep),
  JS_CFUNC_DEF ("putCallout", 0, gumjs_stalker_default_iterator_put_callout),
};

static const JSCFunctionListEntry gumjs_stalker_special_iterator_entries[] = {
  JS_CFUNC_DEF ("next", 0, gumjs_stalker_special_iterator_next),
  JS_CFUNC_DEF ("keep", 0, gumjs_stalker_special_iterator_keep),
  JS_CFUNC_DEF ("putCallout", 0, gumjs_stalker_special_iterator_put_callout),
};

void
_gum_quick_stalker_init (GumQuickStalker * self,
                         JSValue ns,
                         GumQuickCodeWriter * writer,
                         GumQuickInstruction * instruction,
                         GumQuickCore * core)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  quick_context * ctx = scope.ctx;

  self->writer = writer;
  self->instruction = instruction;
  self->core = core;

  self->stalker = NULL;
  self->queue_capacity = 16384;
  self->queue_drain_interval = 250;

  self->flush_timer = NULL;

  _gum_quick_core_store_module_data (core, "stalker", self);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_stalker_entries,
      G_N_ELEMENTS (gumjs_stalker_entries));
  JS_DefinePropertyValueStr (ctx, ns, "Stalker", obj, JS_PROP_C_W_E);

  _gum_quick_create_subclass (ctx, &gumjs_stalker_default_iterator_def,
      writer->default_writer_class, writer->default_writer_proto, core,
      &self->default_iterator_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto,
      gumjs_stalker_default_iterator_entries,
      G_N_ELEMENTS (gumjs_stalker_default_iterator_entries));

  _gum_quick_create_subclass (ctx, &gumjs_stalker_special_iterator_def,
      writer->special_writer_class, writer->special_writer_proto, core,
      &self->special_iterator_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto,
      gumjs_stalker_special_iterator_entries,
      G_N_ELEMENTS (gumjs_stalker_special_iterator_entries));

  _gum_quick_create_class (ctx, &gumjs_probe_args_def, core,
      &self->probe_args_class, &proto);

  self->cached_default_iterator = gum_quick_stalker_default_iterator_new (self);
  self->cached_default_iterator_in_use = FALSE;

  self->cached_special_iterator = gum_quick_stalker_special_iterator_new (self);
  self->cached_special_iterator_in_use = FALSE;

  self->cached_instruction = _gum_quick_instruction_new (instruction);
  self->cached_instruction_in_use = FALSE;

  self->cached_cpu_context = _gum_quick_cpu_context_new (core);
  self->cached_cpu_context_in_use = FALSE;

  self->cached_probe_args = gum_quick_probe_args_new (self);
  self->cached_probe_args_in_use = FALSE;
}

void
_gum_quick_stalker_flush (GumQuickStalker * self)
{
  GumQuickCore * core = self->core;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  gboolean pending_garbage;

  if (self->stalker == NULL)
    return;

  _gum_quick_scope_suspend (&scope);

  gum_stalker_stop (self->stalker);

  pending_garbage = gum_stalker_garbage_collect (self->stalker);

  _gum_quick_scope_resume (&scope);

  if (pending_garbage)
  {
    if (self->flush_timer == NULL)
    {
      GSource * source;

      source = g_timeout_source_new (10);
      g_source_set_callback (source,
          (GSourceFunc) gum_quick_stalker_on_flush_timer_tick, self, NULL);
      self->flush_timer = source;

      _gum_quick_core_pin (core);
      _gum_quick_scope_suspend (&scope);

      g_source_attach (source,
          gum_script_scheduler_get_js_context (core->scheduler));
      g_source_unref (source);

      _gum_quick_scope_resume (&scope);
    }
  }
  else
  {
    g_object_unref (self->stalker);
    self->stalker = NULL;
  }
}

static gboolean
gum_quick_stalker_on_flush_timer_tick (GumQuickStalker * self)
{
  gboolean pending_garbage;

  pending_garbage = gum_stalker_garbage_collect (self->stalker);
  if (!pending_garbage)
  {
    GumQuickCore * core = self->core;
    GumQuickScope scope;

    _gum_quick_scope_enter (&scope, core);
    _gum_quick_core_unpin (core);
    self->flush_timer = NULL;
    _gum_quick_scope_leave (&scope);
  }

  return pending_garbage;
}

void
_gum_quick_stalker_dispose (GumQuickStalker * self)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (self->core);
  quick_context * ctx = scope.ctx;

  g_assert (self->flush_timer == NULL);

  gum_quick_probe_args_release (self->cached_probe_args);
  _gum_quick_cpu_context_release (self->cached_cpu_context);
  _gum_quick_instruction_release (self->cached_instruction);
  gum_quick_stalker_special_iterator_release (self->cached_special_iterator);
  gum_quick_stalker_default_iterator_release (self->cached_default_iterator);

  _gum_quick_release_heapptr (ctx, self->probe_args);
  _gum_quick_release_heapptr (ctx, self->special_iterator);
  _gum_quick_release_heapptr (ctx, self->default_iterator);
}

void
_gum_quick_stalker_finalize (GumQuickStalker * self)
{
}

GumStalker *
_gum_quick_stalker_get (GumQuickStalker * self)
{
  if (self->stalker == NULL)
    self->stalker = gum_stalker_new ();

  return self->stalker;
}

void
_gum_quick_stalker_process_pending (GumQuickStalker * self,
                                  GumQuickScope * scope)
{
  if (scope->pending_stalker_level > 0)
  {
    gum_stalker_follow_me (_gum_quick_stalker_get (self),
        scope->pending_stalker_transformer, scope->pending_stalker_sink);
  }
  else if (scope->pending_stalker_level < 0)
  {
    gum_stalker_unfollow_me (_gum_quick_stalker_get (self));
  }
  scope->pending_stalker_level = 0;

  g_clear_object (&scope->pending_stalker_sink);
  g_clear_object (&scope->pending_stalker_transformer);
}

static GumQuickStalker *
gumjs_module_from_args (const GumQuickArgs * args)
{
  return _gum_quick_load_module_data (args->ctx, "stalker");
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_trust_threshold)
{
  GumStalker * stalker = _gum_quick_stalker_get (gumjs_module_from_args (args));

  quick_push_number (ctx, gum_stalker_get_trust_threshold (stalker));
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_trust_threshold)
{
  GumStalker * stalker;
  gint threshold;

  stalker = _gum_quick_stalker_get (gumjs_module_from_args (args));

  _gum_quick_args_parse (args, "i", &threshold);

  gum_stalker_set_trust_threshold (stalker, threshold);
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_capacity)
{
  GumQuickStalker * self = gumjs_module_from_args (args);

  quick_push_number (ctx, self->queue_capacity);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_capacity)
{
  GumQuickStalker * self = gumjs_module_from_args (args);

  _gum_quick_args_parse (args, "u", &self->queue_capacity);
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_drain_interval)
{
  GumQuickStalker * self = gumjs_module_from_args (args);

  quick_push_number (ctx, self->queue_drain_interval);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_drain_interval)
{
  GumQuickStalker * self = gumjs_module_from_args (args);

  _gum_quick_args_parse (args, "u", &self->queue_drain_interval);
  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_flush)
{
  GumStalker * stalker;

  stalker = _gum_quick_stalker_get (gumjs_module_from_args (args));

  gum_stalker_flush (stalker);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_garbage_collect)
{
  GumStalker * stalker;

  stalker = _gum_quick_stalker_get (gumjs_module_from_args (args));

  gum_stalker_garbage_collect (stalker);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_exclude)
{
  GumQuickStalker * module;
  gpointer base;
  gsize size;
  GumMemoryRange range;

  module = gumjs_module_from_args (args);

  _gum_quick_args_parse (args, "pZ", &base, &size);

  range.base_address = GUM_ADDRESS (base);
  range.size = size;

  gum_stalker_exclude (_gum_quick_stalker_get (module), &range);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_follow)
{
  GumQuickStalker * module;
  GumStalker * stalker;
  GumQuickCore * core;
  GumThreadId thread_id;
  GumQuickHeapPtr transformer_callback_js;
  GumStalkerTransformerCallback transformer_callback_c;
  GumQuickEventSinkOptions so;
  gpointer user_data;
  GumStalkerTransformer * transformer;
  GumEventSink * sink;

  module = gumjs_module_from_args (args);
  stalker = _gum_quick_stalker_get (module);
  core = module->core;

  so.core = core;
  so.main_context = gum_script_scheduler_get_js_context (core->scheduler);
  so.queue_capacity = module->queue_capacity;
  so.queue_drain_interval = module->queue_drain_interval;

  _gum_quick_args_parse (args, "ZF*?uF?F?pp", &thread_id,
      &transformer_callback_js, &transformer_callback_c, &so.event_mask,
      &so.on_receive, &so.on_call_summary, &so.on_event, &user_data);

  so.user_data = user_data;

  if (transformer_callback_js != NULL)
  {
    GumQuickCallbackTransformer * cbt;

    cbt = g_object_new (GUM_QUICK_TYPE_CALLBACK_TRANSFORMER, NULL);
    cbt->thread_id = thread_id;
    _gum_quick_protect (ctx, transformer_callback_js);
    cbt->callback = transformer_callback_js;
    cbt->module = module;

    transformer = GUM_STALKER_TRANSFORMER (cbt);
  }
  else if (transformer_callback_c != NULL)
  {
    transformer = gum_stalker_transformer_make_from_callback (
        transformer_callback_c, user_data, NULL);
  }
  else
  {
    transformer = NULL;
  }

  sink = gum_quick_event_sink_new (ctx, &so);

  if (thread_id == gum_process_get_current_thread_id ())
  {
    GumQuickScope * scope = core->current_scope;

    scope->pending_stalker_level = 1;

    g_clear_object (&scope->pending_stalker_transformer);
    g_clear_object (&scope->pending_stalker_sink);
    scope->pending_stalker_transformer = transformer;
    scope->pending_stalker_sink = sink;
  }
  else
  {
    gum_stalker_follow (stalker, thread_id, transformer, sink);
    g_object_unref (sink);
    g_clear_object (&transformer);
  }

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_unfollow)
{
  GumQuickStalker * module;
  GumStalker * stalker;
  GumThreadId current_thread_id, thread_id;

  module = gumjs_module_from_args (args);
  stalker = _gum_quick_stalker_get (module);

  current_thread_id = gum_process_get_current_thread_id ();

  thread_id = current_thread_id;
  _gum_quick_args_parse (args, "|Z", &thread_id);

  if (thread_id == current_thread_id)
    module->core->current_scope->pending_stalker_level--;
  else
    gum_stalker_unfollow (stalker, thread_id);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_add_call_probe)
{
  GumProbeId id;
  GumQuickStalker * module;
  GumStalker * stalker;
  gpointer target_address;
  GumQuickHeapPtr callback_js;
  GumCallProbeCallback callback_c;
  gpointer user_data;
  GumQuickCallProbe * probe;

  module = gumjs_module_from_args (args);
  stalker = _gum_quick_stalker_get (module);

  user_data = NULL;
  _gum_quick_args_parse (args, "pF*|p", &target_address, &callback_js,
      &callback_c, &user_data);

  if (callback_js != NULL)
  {
    probe = g_slice_new (GumQuickCallProbe);
    _gum_quick_protect (ctx, callback_js);
    probe->callback = callback_js;
    probe->module = module;

    id = gum_stalker_add_call_probe (stalker, target_address,
        (GumCallProbeCallback) gum_quick_call_probe_on_fire, probe,
        (GDestroyNotify) gum_quick_call_probe_free);
  }
  else
  {
    id = gum_stalker_add_call_probe (stalker, target_address, callback_c,
        user_data, NULL);
  }

  quick_push_uint (ctx, id);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_remove_call_probe)
{
  GumQuickStalker * module;
  GumProbeId id;

  module = gumjs_module_from_args (args);

  _gum_quick_args_parse (args, "u", &id);

  gum_stalker_remove_call_probe (_gum_quick_stalker_get (module), id);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_parse)
{
  GumQuickStalker * module;
  GumQuickCore * core;
  GumQuickHeapPtr events_value;
  gboolean annotate, stringify;
  const GumEvent * events;
  quick_size_t size, count;
  quick_uarridx_t row_index;
  const GumEvent * ev;

  module = gumjs_module_from_args (args);
  core = module->core;

  _gum_quick_args_parse (args, "Vtt", &events_value, &annotate, &stringify);

  events = quick_get_buffer_data (ctx, 0, &size);
  if (events == NULL)
    _gum_quick_throw (ctx, "expected an ArrayBuffer");

  if (size % sizeof (GumEvent) != 0)
    _gum_quick_throw (ctx, "invalid buffer shape");

  count = size / sizeof (GumEvent);

  quick_push_array (ctx);

  for (ev = events, row_index = 0; row_index != count; ev++, row_index++)
  {
    quick_uarridx_t column_index = 0;

    quick_push_array (ctx);

    switch (ev->type)
    {
      case GUM_CALL:
      {
        const GumCallEvent * call = &ev->call;

        if (annotate)
        {
          quick_push_string (ctx, "call");
          quick_put_prop_index (ctx, -2, column_index++);
        }

        gum_push_pointer (ctx, call->location, stringify, core);
        quick_put_prop_index (ctx, -2, column_index++);

        gum_push_pointer (ctx, call->target, stringify, core);
        quick_put_prop_index (ctx, -2, column_index++);

        quick_push_int (ctx, call->depth);
        quick_put_prop_index (ctx, -2, column_index++);

        break;
      }
      case GUM_RET:
      {
        const GumRetEvent * ret = &ev->ret;

        if (annotate)
        {
          quick_push_string (ctx, "ret");
          quick_put_prop_index (ctx, -2, column_index++);
        }

        gum_push_pointer (ctx, ret->location, stringify, core);
        quick_put_prop_index (ctx, -2, column_index++);

        gum_push_pointer (ctx, ret->target, stringify, core);
        quick_put_prop_index (ctx, -2, column_index++);

        quick_push_int (ctx, ret->depth);
        quick_put_prop_index (ctx, -2, column_index++);

        break;
      }
      case GUM_EXEC:
      {
        const GumExecEvent * exec = &ev->exec;

        if (annotate)
        {
          quick_push_string (ctx, "exec");
          quick_put_prop_index (ctx, -2, column_index++);
        }

        gum_push_pointer (ctx, exec->location, stringify, core);
        quick_put_prop_index (ctx, -2, column_index++);

        break;
      }
      case GUM_BLOCK:
      {
        const GumBlockEvent * block = &ev->block;

        if (annotate)
        {
          quick_push_string (ctx, "block");
          quick_put_prop_index (ctx, -2, column_index++);
        }

        gum_push_pointer (ctx, block->begin, stringify, core);
        quick_put_prop_index (ctx, -2, column_index++);

        gum_push_pointer (ctx, block->end, stringify, core);
        quick_put_prop_index (ctx, -2, column_index++);

        break;
      }
      case GUM_COMPILE:
      {
        const GumCompileEvent * compile = &ev->compile;

        if (annotate)
        {
          quick_push_string (ctx, "compile");
          quick_put_prop_index (ctx, -2, column_index++);
        }

        gum_push_pointer (ctx, compile->begin, stringify, core);
        quick_put_prop_index (ctx, -2, column_index++);

        gum_push_pointer (ctx, compile->end, stringify, core);
        quick_put_prop_index (ctx, -2, column_index++);

        break;
      }
      default:
        _gum_quick_throw (ctx, "invalid event type");
        return 0;
    }

    quick_put_prop_index (ctx, -2, row_index);
  }

  return 1;
}

static void
gum_quick_callback_transformer_transform_block (
    GumStalkerTransformer * transformer,
    GumStalkerIterator * iterator,
    GumStalkerOutput * output)
{
  GumQuickCallbackTransformer * self =
      GUM_QUICK_CALLBACK_TRANSFORMER_CAST (transformer);
  GumQuickStalker * module = self->module;
  gint saved_system_error;
  quick_context * ctx;
  GumQuickScope scope;
  GumQuickStalkerDefaultIterator * default_iter = NULL;
  GumQuickStalkerSpecialIterator * special_iter = NULL;
  GumQuickHeapPtr iter_object;
  gboolean transform_threw_an_exception;

  saved_system_error = gum_thread_get_system_error ();

  ctx = _gum_quick_scope_enter (&scope, module->core);

  if (output->encoding == GUM_INSTRUCTION_DEFAULT)
  {
    default_iter = gum_quick_stalker_obtain_default_iterator (module);
    gum_quick_stalker_default_iterator_reset (default_iter, iterator, output);
    iter_object = default_iter->parent.object;
  }
  else
  {
    special_iter = gum_quick_stalker_obtain_special_iterator (module);
    gum_quick_stalker_special_iterator_reset (special_iter, iterator, output);
    iter_object = special_iter->parent.object;
  }

  quick_push_heapptr (ctx, self->callback);
  quick_push_heapptr (ctx, iter_object);
  transform_threw_an_exception = !_gum_quick_scope_call (&scope, 1);
  quick_pop (ctx);

  if (default_iter != NULL)
  {
    gum_quick_stalker_default_iterator_reset (default_iter, NULL, NULL);
    gum_quick_stalker_release_default_iterator (module, default_iter);
  }
  else
  {
    gum_quick_stalker_special_iterator_reset (special_iter, NULL, NULL);
    gum_quick_stalker_release_special_iterator (module, special_iter);
  }

  _gum_quick_scope_leave (&scope);

  if (transform_threw_an_exception)
    gum_stalker_unfollow (module->stalker, self->thread_id);

  gum_thread_set_system_error (saved_system_error);
}

static void
gum_quick_callback_transformer_class_init (GumQuickCallbackTransformerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_callback_transformer_dispose;
}

static void
gum_quick_callback_transformer_iface_init (gpointer g_iface,
                                         gpointer iface_data)
{
  GumStalkerTransformerInterface * iface = g_iface;

  iface->transform_block = gum_quick_callback_transformer_transform_block;
}

static void
gum_quick_callback_transformer_init (GumQuickCallbackTransformer * self)
{
}

static void
gum_quick_callback_transformer_dispose (GObject * object)
{
  GumQuickCallbackTransformer * self = GUM_QUICK_CALLBACK_TRANSFORMER_CAST (object);
  GumQuickCore * core = self->module->core;
  GumQuickScope scope;
  quick_context * ctx;

  ctx = _gum_quick_scope_enter (&scope, core);

  if (self->callback != NULL)
  {
    _gum_quick_unprotect (ctx, self->callback);
    self->callback = NULL;
  }

  _gum_quick_scope_leave (&scope);

  G_OBJECT_CLASS (gum_quick_callback_transformer_parent_class)->dispose (object);
}

static void
gum_quick_stalker_iterator_init (GumQuickStalkerIterator * iter,
                               GumQuickStalker * parent)
{
  iter->handle = NULL;
  iter->instruction = NULL;

  iter->module = parent;
}

static void
gum_quick_stalker_iterator_reset (GumQuickStalkerIterator * self,
                                GumStalkerIterator * handle)
{
  self->handle = handle;

  if (self->instruction != NULL)
  {
    self->instruction->insn = NULL;
    gum_quick_stalker_release_instruction (self->module, self->instruction);
  }
  self->instruction = (handle != NULL)
      ? gum_quick_stalker_obtain_instruction (self->module)
      : NULL;
}

static void
gum_quick_stalker_iterator_check_valid (GumQuickStalkerIterator * self,
                                      quick_context * ctx)
{
  if (self->handle == NULL)
    _gum_quick_throw (ctx, "invalid operation");
}

static int
gum_quick_stalker_iterator_next (GumQuickStalkerIterator * self,
                               quick_context * ctx)
{
  if (gum_stalker_iterator_next (self->handle, &self->instruction->insn))
    quick_push_heapptr (ctx, self->instruction->object);
  else
    quick_push_null (ctx);

  return 1;
}

static int
gum_quick_stalker_iterator_keep (GumQuickStalkerIterator * self,
                               quick_context * ctx)
{
  gum_stalker_iterator_keep (self->handle);

  return 0;
}

static int
gum_quick_stalker_iterator_put_callout (GumQuickStalkerIterator * self,
                                      quick_context * ctx,
                                      const GumQuickArgs * args)
{
  GumQuickHeapPtr callback_js;
  GumStalkerCallout callback_c;
  gpointer user_data;

  user_data = NULL;
  _gum_quick_args_parse (args, "F*|p", &callback_js, &callback_c, &user_data);

  if (callback_js != NULL)
  {
    GumQuickCallout * callout;

    callout = g_slice_new (GumQuickCallout);
    _gum_quick_protect (ctx, callback_js);
    callout->callback = callback_js;
    callout->module = self->module;

    gum_stalker_iterator_put_callout (self->handle,
        (GumStalkerCallout) gum_quick_callout_on_invoke, callout,
        (GDestroyNotify) gum_quick_callout_free);
  }
  else
  {
    gum_stalker_iterator_put_callout (self->handle, callback_c, user_data,
        NULL);
  }

  return 0;
}

static GumQuickStalkerDefaultIterator *
gum_quick_stalker_default_iterator_new (GumQuickStalker * parent)
{
  GumQuickCore * core = parent->core;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  quick_context * ctx = scope.ctx;
  GumQuickStalkerDefaultIterator * iter;
  GumQuickDefaultWriter * writer;

  iter = g_slice_new (GumQuickStalkerDefaultIterator);

  writer = &iter->parent;
  _gum_quick_default_writer_init (writer, parent->writer);

  gum_quick_stalker_iterator_init (&iter->iterator, parent);

  quick_push_heapptr (ctx, parent->default_iterator);
  quick_new (ctx, 0);
  _gum_quick_put_data (ctx, -1, iter);
  writer->object = _gum_quick_require_heapptr (ctx, -1);
  quick_pop (ctx);

  return iter;
}

static void
gum_quick_stalker_default_iterator_release (GumQuickStalkerDefaultIterator * self)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (self->iterator.module->core);

  _gum_quick_release_heapptr (scope.ctx, self->parent.object);
}

static void
gum_quick_stalker_default_iterator_reset (GumQuickStalkerDefaultIterator * self,
                                        GumStalkerIterator * handle,
                                        GumStalkerOutput * output)
{
  _gum_quick_default_writer_reset (&self->parent,
      (output != NULL) ? output->writer.instance : NULL);
  gum_quick_stalker_iterator_reset (&self->iterator, handle);
}

static GumQuickStalkerDefaultIterator *
gumjs_stalker_default_iterator_from_args (const GumQuickArgs * args)
{
  quick_context * ctx = args->ctx;
  GumQuickStalkerDefaultIterator * self;

  quick_push_this (ctx);
  self = _gum_quick_require_data (ctx, -1);
  gum_quick_stalker_iterator_check_valid (&self->iterator, ctx);
  quick_pop (ctx);

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_stalker_default_iterator_construct)
{
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_stalker_default_iterator_finalize)
{
  GumQuickStalkerDefaultIterator * self;

  self = _gum_quick_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  _gum_quick_default_writer_finalize (&self->parent);

  g_slice_free (GumQuickStalkerDefaultIterator, self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_default_iterator_next)
{
  GumQuickStalkerDefaultIterator * self;

  self = gumjs_stalker_default_iterator_from_args (args);

  return gum_quick_stalker_iterator_next (&self->iterator, ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_default_iterator_keep)
{
  GumQuickStalkerDefaultIterator * self;

  self = gumjs_stalker_default_iterator_from_args (args);

  return gum_quick_stalker_iterator_keep (&self->iterator, ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_default_iterator_put_callout)
{
  GumQuickStalkerDefaultIterator * self;

  self = gumjs_stalker_default_iterator_from_args (args);

  return gum_quick_stalker_iterator_put_callout (&self->iterator, ctx, args);
}

static GumQuickStalkerSpecialIterator *
gum_quick_stalker_special_iterator_new (GumQuickStalker * parent)
{
  GumQuickCore * core = parent->core;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  quick_context * ctx = scope.ctx;
  GumQuickStalkerSpecialIterator * iter;
  GumQuickSpecialWriter * writer;

  iter = g_slice_new (GumQuickStalkerSpecialIterator);

  writer = &iter->parent;
  _gum_quick_special_writer_init (writer, parent->writer);

  gum_quick_stalker_iterator_init (&iter->iterator, parent);

  quick_push_heapptr (ctx, parent->special_iterator);
  quick_new (ctx, 0);
  _gum_quick_put_data (ctx, -1, iter);
  writer->object = _gum_quick_require_heapptr (ctx, -1);
  quick_pop (ctx);

  return iter;
}

static void
gum_quick_stalker_special_iterator_release (GumQuickStalkerSpecialIterator * self)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (self->iterator.module->core);

  _gum_quick_release_heapptr (scope.ctx, self->parent.object);
}

static void
gum_quick_stalker_special_iterator_reset (GumQuickStalkerSpecialIterator * self,
                                        GumStalkerIterator * handle,
                                        GumStalkerOutput * output)
{
  _gum_quick_special_writer_reset (&self->parent,
      (output != NULL) ? output->writer.instance : NULL);
  gum_quick_stalker_iterator_reset (&self->iterator, handle);
}

static GumQuickStalkerSpecialIterator *
gumjs_stalker_special_iterator_from_args (const GumQuickArgs * args)
{
  quick_context * ctx = args->ctx;
  GumQuickStalkerSpecialIterator * self;

  quick_push_this (ctx);
  self = _gum_quick_require_data (ctx, -1);
  gum_quick_stalker_iterator_check_valid (&self->iterator, ctx);
  quick_pop (ctx);

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_stalker_special_iterator_construct)
{
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_stalker_special_iterator_finalize)
{
  GumQuickStalkerSpecialIterator * self;

  self = _gum_quick_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  _gum_quick_special_writer_finalize (&self->parent);

  g_slice_free (GumQuickStalkerSpecialIterator, self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_special_iterator_next)
{
  GumQuickStalkerSpecialIterator * self;

  self = gumjs_stalker_special_iterator_from_args (args);

  return gum_quick_stalker_iterator_next (&self->iterator, ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_special_iterator_keep)
{
  GumQuickStalkerSpecialIterator * self;

  self = gumjs_stalker_special_iterator_from_args (args);

  return gum_quick_stalker_iterator_keep (&self->iterator, ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_special_iterator_put_callout)
{
  GumQuickStalkerSpecialIterator * self;

  self = gumjs_stalker_special_iterator_from_args (args);

  return gum_quick_stalker_iterator_put_callout (&self->iterator, ctx, args);
}

static void
gum_quick_callout_free (GumQuickCallout * callout)
{
  GumQuickCore * core = callout->module->core;
  GumQuickScope scope;
  quick_context * ctx;

  ctx = _gum_quick_scope_enter (&scope, core);

  _gum_quick_unprotect (ctx, callout->callback);

  _gum_quick_scope_leave (&scope);

  g_slice_free (GumQuickCallout, callout);
}

static void
gum_quick_callout_on_invoke (GumCpuContext * cpu_context,
                           GumQuickCallout * self)
{
  GumQuickStalker * module = self->module;
  gint saved_system_error;
  quick_context * ctx;
  GumQuickScope scope;
  GumQuickCpuContext * cpu_context_value;

  saved_system_error = gum_thread_get_system_error ();

  ctx = _gum_quick_scope_enter (&scope, module->core);

  cpu_context_value = gum_quick_stalker_obtain_cpu_context (module);
  _gum_quick_cpu_context_reset (cpu_context_value, cpu_context,
      GUM_CPU_CONTEXT_READWRITE);

  quick_push_heapptr (ctx, self->callback);
  quick_push_heapptr (ctx, cpu_context_value->object);
  _gum_quick_scope_call (&scope, 1);
  quick_pop (ctx);

  _gum_quick_cpu_context_reset (cpu_context_value, NULL,
      GUM_CPU_CONTEXT_READWRITE);
  gum_quick_stalker_release_cpu_context (module, cpu_context_value);

  _gum_quick_scope_leave (&scope);

  gum_thread_set_system_error (saved_system_error);
}

static void
gum_quick_call_probe_free (GumQuickCallProbe * probe)
{
  GumQuickCore * core = probe->module->core;
  GumQuickScope scope;
  quick_context * ctx;

  ctx = _gum_quick_scope_enter (&scope, core);

  _gum_quick_unprotect (ctx, probe->callback);

  _gum_quick_scope_leave (&scope);

  g_slice_free (GumQuickCallProbe, probe);
}

static void
gum_quick_call_probe_on_fire (GumCallSite * site,
                            GumQuickCallProbe * self)
{
  GumQuickStalker * module = self->module;
  gint saved_system_error;
  quick_context * ctx;
  GumQuickScope scope;
  GumQuickProbeArgs * args;

  saved_system_error = gum_thread_get_system_error ();

  ctx = _gum_quick_scope_enter (&scope, module->core);

  args = gum_quick_stalker_obtain_probe_args (module);
  gum_quick_probe_args_reset (args, site);

  quick_push_heapptr (ctx, self->callback);
  quick_push_heapptr (ctx, args->object);
  _gum_quick_scope_call (&scope, 1);
  quick_pop (ctx);

  gum_quick_probe_args_reset (args, NULL);
  gum_quick_stalker_release_probe_args (module, args);

  _gum_quick_scope_leave (&scope);

  gum_thread_set_system_error (saved_system_error);
}

static GumQuickProbeArgs *
gum_quick_probe_args_new (GumQuickStalker * parent)
{
  GumQuickCore * core = parent->core;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  quick_context * ctx = scope.ctx;
  GumQuickProbeArgs * args;

  args = g_slice_new (GumQuickProbeArgs);

  quick_push_heapptr (ctx, parent->probe_args);
  quick_new (ctx, 0);
  _gum_quick_put_data (ctx, -1, args);
  args->object = _gum_quick_require_heapptr (ctx, -1);
  quick_pop (ctx);

  args->site = NULL;
  args->core = core;

  return args;
}

static void
gum_quick_probe_args_release (GumQuickProbeArgs * self)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (self->core);

  _gum_quick_release_heapptr (scope.ctx, self->object);
}

static void
gum_quick_probe_args_reset (GumQuickProbeArgs * self,
                          GumCallSite * site)
{
  self->site = site;
}

static GumCallSite *
gumjs_probe_args_require_call_site (quick_context * ctx,
                                    quick_idx_t index)
{
  GumQuickProbeArgs * self = _gum_quick_require_data (ctx, index);

  if (self->site == NULL)
    _gum_quick_throw (ctx, "invalid operation");

  return self->site;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_probe_args_construct)
{
  quick_push_this (ctx);
  _gum_quick_push_proxy (ctx, -1, gumjs_probe_args_get_property,
      gumjs_probe_args_set_property);
  return 1;
}

GUMJS_DEFINE_FINALIZER (gumjs_probe_args_finalize)
{
  GumQuickProbeArgs * self;

  self = _gum_quick_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_slice_free (GumQuickProbeArgs, self);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_probe_args_get_property)
{
  GumCallSite * site;
  guint n;

  if (quick_is_string (ctx, 1) &&
      strcmp (quick_require_string (ctx, 1), "toJSON") == 0)
  {
    quick_push_string (ctx, "probe-args");
    return 1;
  }

  site = gumjs_probe_args_require_call_site (ctx, 0);
  n = _gum_quick_require_index (ctx, 1);

  _gum_quick_push_native_pointer (ctx, gum_call_site_get_nth_argument (site, n),
      args->core);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_probe_args_set_property)
{
  GumCallSite * site;
  guint n;
  gpointer value;

  site = gumjs_probe_args_require_call_site (ctx, 0);
  n = _gum_quick_require_index (ctx, 1);
  if (!_gum_quick_get_pointer (ctx, 2, args->core, &value))
  {
    quick_push_false (ctx);
    return 1;
  }

  gum_call_site_replace_nth_argument (site, n, value);

  quick_push_true (ctx);
  return 1;
}

static GumQuickStalkerDefaultIterator *
gum_quick_stalker_obtain_default_iterator (GumQuickStalker * self)
{
  GumQuickStalkerDefaultIterator * iterator;

  if (!self->cached_default_iterator_in_use)
  {
    iterator = self->cached_default_iterator;
    self->cached_default_iterator_in_use = TRUE;
  }
  else
  {
    iterator = gum_quick_stalker_default_iterator_new (self);
  }

  return iterator;
}

static void
gum_quick_stalker_release_default_iterator (
    GumQuickStalker * self,
    GumQuickStalkerDefaultIterator * iterator)
{
  if (iterator == self->cached_default_iterator)
  {
    self->cached_default_iterator_in_use = FALSE;
  }
  else
  {
    gum_quick_stalker_default_iterator_release (iterator);
  }
}

static GumQuickStalkerSpecialIterator *
gum_quick_stalker_obtain_special_iterator (GumQuickStalker * self)
{
  GumQuickStalkerSpecialIterator * iterator;

  if (!self->cached_special_iterator_in_use)
  {
    iterator = self->cached_special_iterator;
    self->cached_special_iterator_in_use = TRUE;
  }
  else
  {
    iterator = gum_quick_stalker_special_iterator_new (self);
  }

  return iterator;
}

static void
gum_quick_stalker_release_special_iterator (
    GumQuickStalker * self,
    GumQuickStalkerSpecialIterator * iterator)
{
  if (iterator == self->cached_special_iterator)
  {
    self->cached_special_iterator_in_use = FALSE;
  }
  else
  {
    gum_quick_stalker_special_iterator_release (iterator);
  }
}

static GumQuickInstructionValue *
gum_quick_stalker_obtain_instruction (GumQuickStalker * self)
{
  GumQuickInstructionValue * value;

  if (!self->cached_instruction_in_use)
  {
    value = self->cached_instruction;
    self->cached_instruction_in_use = TRUE;
  }
  else
  {
    value = _gum_quick_instruction_new (self->instruction);
  }

  return value;
}

static void
gum_quick_stalker_release_instruction (GumQuickStalker * self,
                                     GumQuickInstructionValue * value)
{
  if (value == self->cached_instruction)
  {
    self->cached_instruction_in_use = FALSE;
  }
  else
  {
    _gum_quick_instruction_release (value);
  }
}

static GumQuickCpuContext *
gum_quick_stalker_obtain_cpu_context (GumQuickStalker * self)
{
  GumQuickCpuContext * cpu_context;

  if (!self->cached_cpu_context_in_use)
  {
    cpu_context = self->cached_cpu_context;
    self->cached_cpu_context_in_use = TRUE;
  }
  else
  {
    cpu_context = _gum_quick_cpu_context_new (self->core);
  }

  return cpu_context;
}

static void
gum_quick_stalker_release_cpu_context (GumQuickStalker * self,
                                     GumQuickCpuContext * cpu_context)
{
  if (cpu_context == self->cached_cpu_context)
  {
    self->cached_cpu_context_in_use = FALSE;
  }
  else
  {
    _gum_quick_cpu_context_release (cpu_context);
  }
}

static GumQuickProbeArgs *
gum_quick_stalker_obtain_probe_args (GumQuickStalker * self)
{
  GumQuickProbeArgs * args;

  if (!self->cached_probe_args_in_use)
  {
    args = self->cached_probe_args;
    self->cached_probe_args_in_use = TRUE;
  }
  else
  {
    args = gum_quick_probe_args_new (self);
  }

  return args;
}

static void
gum_quick_stalker_release_probe_args (GumQuickStalker * self,
                                    GumQuickProbeArgs * args)
{
  if (args == self->cached_probe_args)
    self->cached_probe_args_in_use = FALSE;
  else
    gum_quick_probe_args_release (args);
}

static void
gum_push_pointer (quick_context * ctx,
                  gpointer value,
                  gboolean stringify,
                  GumQuickCore * core)
{
  if (stringify)
  {
    gchar str[32];

    sprintf (str, "0x%" G_GSIZE_MODIFIER "x", GPOINTER_TO_SIZE (value));
    quick_push_string (ctx, str);
  }
  else
  {
    _gum_quick_push_native_pointer (ctx, value, core);
  }
}
