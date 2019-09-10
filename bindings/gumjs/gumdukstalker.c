/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukstalker.h"

#include "gumdukeventsink.h"
#include "gumdukmacros.h"

#define GUM_DUK_TYPE_CALLBACK_TRANSFORMER \
    (gum_duk_callback_transformer_get_type ())
#define GUM_DUK_CALLBACK_TRANSFORMER_CAST(obj) \
    ((GumDukCallbackTransformer *) (obj))

typedef struct _GumDukCallbackTransformer GumDukCallbackTransformer;
typedef struct _GumDukCallbackTransformerClass GumDukCallbackTransformerClass;
typedef struct _GumDukCallout GumDukCallout;
typedef struct _GumDukCallProbe GumDukCallProbe;

struct _GumDukCallbackTransformer
{
  GObject parent;

  GumDukHeapPtr callback;

  GumDukStalker * module;
};

struct _GumDukCallbackTransformerClass
{
  GObjectClass parent_class;
};

struct _GumDukCallout
{
  GumDukHeapPtr callback;

  GumDukStalker * module;
};

struct _GumDukCallProbe
{
  GumDukHeapPtr callback;

  GumDukStalker * module;
};

struct _GumDukStalkerIterator
{
  GumDukNativeWriter parent;

  GumStalkerIterator * handle;
  GumDukInstructionValue * instruction;

  GumDukStalker * module;
};

struct _GumDukProbeArgs
{
  GumDukHeapPtr object;
  GumCallSite * site;

  GumDukCore * core;
};

static gboolean gum_duk_stalker_on_flush_timer_tick (GumDukStalker * self);

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

static void gum_duk_callback_transformer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_duk_callback_transformer_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumDukCallbackTransformer,
                        gum_duk_callback_transformer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_STALKER_TRANSFORMER,
                            gum_duk_callback_transformer_iface_init))

static void gum_duk_call_probe_free (GumDukCallProbe * probe);
static void gum_duk_call_probe_on_fire (GumCallSite * site,
    GumDukCallProbe * self);

static GumDukStalkerIterator * gum_duk_stalker_iterator_new (
    GumDukStalker * parent);
static void gum_duk_stalker_iterator_release (GumDukStalkerIterator * self);
static void gum_duk_stalker_iterator_reset (GumDukStalkerIterator * self,
    GumStalkerIterator * handle);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_stalker_iterator_construct)
GUMJS_DECLARE_FINALIZER (gumjs_stalker_iterator_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_iterator_next)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_iterator_keep)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_iterator_put_callout)

static void gum_duk_callout_free (GumDukCallout * callout);
static void gum_duk_callout_on_invoke (GumCpuContext * cpu_context,
    GumDukCallout * self);

static GumDukProbeArgs * gum_duk_probe_args_new (GumDukStalker * parent);
static void gum_duk_probe_args_release (GumDukProbeArgs * self);
static void gum_duk_probe_args_reset (GumDukProbeArgs * self,
    GumCallSite * site);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_probe_args_construct)
GUMJS_DECLARE_FINALIZER (gumjs_probe_args_finalize)
GUMJS_DECLARE_GETTER (gumjs_probe_args_get_property)
GUMJS_DECLARE_SETTER (gumjs_probe_args_set_property)

static GumDukStalkerIterator * gum_duk_stalker_obtain_iterator (
    GumDukStalker * self);
static void gum_duk_stalker_release_iterator (GumDukStalker * self,
    GumDukStalkerIterator * iterator);
static GumDukInstructionValue * gum_duk_stalker_obtain_instruction (
    GumDukStalker * self);
static void gum_duk_stalker_release_instruction (GumDukStalker * self,
    GumDukInstructionValue * value);
static GumDukCpuContext * gum_duk_stalker_obtain_cpu_context (
    GumDukStalker * self);
static void gum_duk_stalker_release_cpu_context (GumDukStalker * self,
    GumDukCpuContext * cpu_context);
static GumDukProbeArgs * gum_duk_stalker_obtain_probe_args (
    GumDukStalker * self);
static void gum_duk_stalker_release_probe_args (GumDukStalker * self,
    GumDukProbeArgs * args);

static void gum_push_pointer (duk_context * ctx, gpointer value,
    gboolean stringify, GumDukCore * core);

static const GumDukPropertyEntry gumjs_stalker_values[] =
{
  {
    "trustThreshold",
    gumjs_stalker_get_trust_threshold,
    gumjs_stalker_set_trust_threshold
  },
  {
    "queueCapacity",
    gumjs_stalker_get_queue_capacity,
    gumjs_stalker_set_queue_capacity
  },
  {
    "queueDrainInterval",
    gumjs_stalker_get_queue_drain_interval,
    gumjs_stalker_set_queue_drain_interval
  },

  { NULL, NULL, NULL }
};

static const duk_function_list_entry gumjs_stalker_functions[] =
{
  { "flush", gumjs_stalker_flush, 0 },
  { "garbageCollect", gumjs_stalker_garbage_collect, 0 },
  { "_exclude", gumjs_stalker_exclude, 2 },
  { "_follow", gumjs_stalker_follow, 5 },
  { "unfollow", gumjs_stalker_unfollow, 1 },
  { "addCallProbe", gumjs_stalker_add_call_probe, 2 },
  { "removeCallProbe", gumjs_stalker_remove_call_probe, 1 },
  { "_parse", gumjs_stalker_parse, 3 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_stalker_iterator_functions[] =
{
  { "next", gumjs_stalker_iterator_next, 0 },
  { "keep", gumjs_stalker_iterator_keep, 0 },
  { "putCallout", gumjs_stalker_iterator_put_callout, 1 },

  { NULL, NULL, 0 }
};

void
_gum_duk_stalker_init (GumDukStalker * self,
                       GumDukCodeWriter * writer,
                       GumDukInstruction * instruction,
                       GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->writer = writer;
  self->instruction = instruction;
  self->core = core;

  self->stalker = NULL;
  self->queue_capacity = 16384;
  self->queue_drain_interval = 250;

  self->flush_timer = NULL;

  _gum_duk_store_module_data (ctx, "stalker", self);

  duk_push_object (ctx);
  _gum_duk_add_properties_to_class_by_heapptr (ctx,
      duk_require_heapptr (ctx, -1), gumjs_stalker_values);
  duk_put_function_list (ctx, -1, gumjs_stalker_functions);
  duk_put_global_string (ctx, "Stalker");

  _gum_duk_create_subclass (ctx, GUM_DUK_NATIVE_WRITER_CLASS_NAME,
      "StalkerIterator", gumjs_stalker_iterator_construct, 0,
      gumjs_stalker_iterator_finalize);
  duk_get_global_string (ctx, "StalkerIterator");
  self->iterator = _gum_duk_require_heapptr (ctx, -1);
  duk_get_prop_string (ctx, -1, "prototype");
  duk_put_function_list (ctx, -1, gumjs_stalker_iterator_functions);
  duk_pop_2 (ctx);

  duk_push_c_function (ctx, gumjs_probe_args_construct, 0);
  duk_push_object (ctx);
  duk_push_c_function (ctx, gumjs_probe_args_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->probe_args = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "ProbeArgs");

  self->cached_iterator = gum_duk_stalker_iterator_new (self);
  self->cached_iterator_in_use = FALSE;

  self->cached_instruction = _gum_duk_instruction_new (instruction);
  self->cached_instruction_in_use = FALSE;

  self->cached_cpu_context = _gum_duk_cpu_context_new (core);
  self->cached_cpu_context_in_use = FALSE;

  self->cached_probe_args = gum_duk_probe_args_new (self);
  self->cached_probe_args_in_use = FALSE;
}

void
_gum_duk_stalker_flush (GumDukStalker * self)
{
  GumDukCore * core = self->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  gboolean pending_garbage;

  if (self->stalker == NULL)
    return;

  _gum_duk_scope_suspend (&scope);

  gum_stalker_stop (self->stalker);

  pending_garbage = gum_stalker_garbage_collect (self->stalker);

  _gum_duk_scope_resume (&scope);

  if (pending_garbage)
  {
    if (self->flush_timer == NULL)
    {
      GSource * source;

      source = g_timeout_source_new (10);
      g_source_set_callback (source,
          (GSourceFunc) gum_duk_stalker_on_flush_timer_tick, self, NULL);
      self->flush_timer = source;

      _gum_duk_core_pin (core);
      _gum_duk_scope_suspend (&scope);

      g_source_attach (source,
          gum_script_scheduler_get_js_context (core->scheduler));
      g_source_unref (source);

      _gum_duk_scope_resume (&scope);
    }
  }
  else
  {
    g_object_unref (self->stalker);
    self->stalker = NULL;
  }
}

static gboolean
gum_duk_stalker_on_flush_timer_tick (GumDukStalker * self)
{
  gboolean pending_garbage;

  pending_garbage = gum_stalker_garbage_collect (self->stalker);
  if (!pending_garbage)
  {
    GumDukCore * core = self->core;
    GumDukScope scope;

    _gum_duk_scope_enter (&scope, core);
    _gum_duk_core_unpin (core);
    self->flush_timer = NULL;
    _gum_duk_scope_leave (&scope);
  }

  return pending_garbage;
}

void
_gum_duk_stalker_dispose (GumDukStalker * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);
  duk_context * ctx = scope.ctx;

  g_assert (self->flush_timer == NULL);

  gum_duk_probe_args_release (self->cached_probe_args);
  _gum_duk_cpu_context_release (self->cached_cpu_context);
  _gum_duk_instruction_release (self->cached_instruction);
  gum_duk_stalker_iterator_release (self->cached_iterator);

  _gum_duk_release_heapptr (ctx, self->probe_args);
  _gum_duk_release_heapptr (ctx, self->iterator);
}

void
_gum_duk_stalker_finalize (GumDukStalker * self)
{
}

GumStalker *
_gum_duk_stalker_get (GumDukStalker * self)
{
  if (self->stalker == NULL)
    self->stalker = gum_stalker_new ();

  return self->stalker;
}

void
_gum_duk_stalker_process_pending (GumDukStalker * self,
                                  GumDukScope * scope)
{
  if (scope->pending_stalker_level > 0)
  {
    gum_stalker_follow_me (_gum_duk_stalker_get (self),
        scope->pending_stalker_transformer, scope->pending_stalker_sink);
  }
  else if (scope->pending_stalker_level < 0)
  {
    gum_stalker_unfollow_me (_gum_duk_stalker_get (self));
  }
  scope->pending_stalker_level = 0;

  g_clear_object (&scope->pending_stalker_sink);
  g_clear_object (&scope->pending_stalker_transformer);
}

static GumDukStalker *
gumjs_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "stalker");
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_trust_threshold)
{
  GumStalker * stalker = _gum_duk_stalker_get (gumjs_module_from_args (args));

  duk_push_number (ctx, gum_stalker_get_trust_threshold (stalker));
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_trust_threshold)
{
  GumStalker * stalker;
  gint threshold;

  stalker = _gum_duk_stalker_get (gumjs_module_from_args (args));

  _gum_duk_args_parse (args, "i", &threshold);

  gum_stalker_set_trust_threshold (stalker, threshold);
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_capacity)
{
  GumDukStalker * self = gumjs_module_from_args (args);

  duk_push_number (ctx, self->queue_capacity);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_capacity)
{
  GumDukStalker * self = gumjs_module_from_args (args);

  _gum_duk_args_parse (args, "u", &self->queue_capacity);
  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_drain_interval)
{
  GumDukStalker * self = gumjs_module_from_args (args);

  duk_push_number (ctx, self->queue_drain_interval);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_drain_interval)
{
  GumDukStalker * self = gumjs_module_from_args (args);

  _gum_duk_args_parse (args, "u", &self->queue_drain_interval);
  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_flush)
{
  GumStalker * stalker;

  stalker = _gum_duk_stalker_get (gumjs_module_from_args (args));

  gum_stalker_flush (stalker);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_garbage_collect)
{
  GumStalker * stalker;

  stalker = _gum_duk_stalker_get (gumjs_module_from_args (args));

  gum_stalker_garbage_collect (stalker);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_exclude)
{
  GumDukStalker * module;
  gpointer base;
  gsize size;
  GumMemoryRange range;

  module = gumjs_module_from_args (args);

  _gum_duk_args_parse (args, "pZ", &base, &size);

  range.base_address = GUM_ADDRESS (base);
  range.size = size;

  gum_stalker_exclude (_gum_duk_stalker_get (module), &range);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_follow)
{
  GumDukStalker * module;
  GumStalker * stalker;
  GumDukCore * core;
  GumThreadId thread_id;
  GumDukHeapPtr transformer_callback;
  GumDukEventSinkOptions so;
  GumStalkerTransformer * transformer;
  GumEventSink * sink;

  module = gumjs_module_from_args (args);
  stalker = _gum_duk_stalker_get (module);
  core = module->core;

  so.core = core;
  so.main_context = gum_script_scheduler_get_js_context (core->scheduler);
  so.queue_capacity = module->queue_capacity;
  so.queue_drain_interval = module->queue_drain_interval;

  _gum_duk_args_parse (args, "ZF?uF?F?", &thread_id, &transformer_callback,
      &so.event_mask, &so.on_receive, &so.on_call_summary);

  if (transformer_callback != NULL)
  {
    GumDukCallbackTransformer * cbt;

    cbt = g_object_new (GUM_DUK_TYPE_CALLBACK_TRANSFORMER, NULL);
    _gum_duk_protect (ctx, transformer_callback);
    cbt->callback = transformer_callback;
    cbt->module = module;

    transformer = GUM_STALKER_TRANSFORMER (cbt);
  }
  else
  {
    transformer = NULL;
  }

  sink = gum_duk_event_sink_new (ctx, &so);

  if (thread_id == gum_process_get_current_thread_id ())
  {
    GumDukScope * scope = core->current_scope;

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
  GumDukStalker * module;
  GumStalker * stalker;
  GumThreadId current_thread_id, thread_id;

  module = gumjs_module_from_args (args);
  stalker = _gum_duk_stalker_get (module);

  current_thread_id = gum_process_get_current_thread_id ();

  thread_id = current_thread_id;
  _gum_duk_args_parse (args, "|Z", &thread_id);

  if (thread_id == current_thread_id)
    module->core->current_scope->pending_stalker_level--;
  else
    gum_stalker_unfollow (stalker, thread_id);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_add_call_probe)
{
  GumDukStalker * module;
  gpointer target_address;
  GumDukHeapPtr callback;
  GumDukCallProbe * probe;
  GumProbeId id;

  module = gumjs_module_from_args (args);

  _gum_duk_args_parse (args, "pF", &target_address, &callback);

  probe = g_slice_new (GumDukCallProbe);
  _gum_duk_protect (ctx, callback);
  probe->callback = callback;
  probe->module = module;

  id = gum_stalker_add_call_probe (_gum_duk_stalker_get (module),
      target_address, (GumCallProbeCallback) gum_duk_call_probe_on_fire, probe,
      (GDestroyNotify) gum_duk_call_probe_free);

  duk_push_uint (ctx, id);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_remove_call_probe)
{
  GumDukStalker * module;
  GumProbeId id;

  module = gumjs_module_from_args (args);

  _gum_duk_args_parse (args, "u", &id);

  gum_stalker_remove_call_probe (_gum_duk_stalker_get (module), id);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_parse)
{
  GumDukStalker * module;
  GumDukCore * core;
  GumDukHeapPtr events_value;
  gboolean annotate, stringify;
  const GumEvent * events;
  duk_size_t size, count;
  duk_uarridx_t row_index;
  const GumEvent * ev;

  module = gumjs_module_from_args (args);
  core = module->core;

  _gum_duk_args_parse (args, "Vtt", &events_value, &annotate, &stringify);

  events = duk_get_buffer_data (ctx, 0, &size);
  if (events == NULL)
    _gum_duk_throw (ctx, "expected an ArrayBuffer");

  if (size % sizeof (GumEvent) != 0)
    _gum_duk_throw (ctx, "invalid buffer shape");

  count = size / sizeof (GumEvent);

  duk_push_array (ctx);

  for (ev = events, row_index = 0; row_index != count; ev++, row_index++)
  {
    duk_uarridx_t column_index = 0;

    duk_push_array (ctx);

    switch (ev->type)
    {
      case GUM_CALL:
      {
        const GumCallEvent * call = &ev->call;

        if (annotate)
        {
          duk_push_string (ctx, "call");
          duk_put_prop_index (ctx, -2, column_index++);
        }

        gum_push_pointer (ctx, call->location, stringify, core);
        duk_put_prop_index (ctx, -2, column_index++);

        gum_push_pointer (ctx, call->target, stringify, core);
        duk_put_prop_index (ctx, -2, column_index++);

        duk_push_int (ctx, call->depth);
        duk_put_prop_index (ctx, -2, column_index++);

        break;
      }
      case GUM_RET:
      {
        const GumRetEvent * ret = &ev->ret;

        if (annotate)
        {
          duk_push_string (ctx, "ret");
          duk_put_prop_index (ctx, -2, column_index++);
        }

        gum_push_pointer (ctx, ret->location, stringify, core);
        duk_put_prop_index (ctx, -2, column_index++);

        gum_push_pointer (ctx, ret->target, stringify, core);
        duk_put_prop_index (ctx, -2, column_index++);

        duk_push_int (ctx, ret->depth);
        duk_put_prop_index (ctx, -2, column_index++);

        break;
      }
      case GUM_EXEC:
      {
        const GumExecEvent * exec = &ev->exec;

        if (annotate)
        {
          duk_push_string (ctx, "exec");
          duk_put_prop_index (ctx, -2, column_index++);
        }

        gum_push_pointer (ctx, exec->location, stringify, core);
        duk_put_prop_index (ctx, -2, column_index++);

        break;
      }
      case GUM_BLOCK:
      {
        const GumBlockEvent * block = &ev->block;

        if (annotate)
        {
          duk_push_string (ctx, "block");
          duk_put_prop_index (ctx, -2, column_index++);
        }

        gum_push_pointer (ctx, block->begin, stringify, core);
        duk_put_prop_index (ctx, -2, column_index++);

        gum_push_pointer (ctx, block->end, stringify, core);
        duk_put_prop_index (ctx, -2, column_index++);

        break;
      }
      case GUM_COMPILE:
      {
        const GumCompileEvent * compile = &ev->compile;

        if (annotate)
        {
          duk_push_string (ctx, "compile");
          duk_put_prop_index (ctx, -2, column_index++);
        }

        gum_push_pointer (ctx, compile->begin, stringify, core);
        duk_put_prop_index (ctx, -2, column_index++);

        gum_push_pointer (ctx, compile->end, stringify, core);
        duk_put_prop_index (ctx, -2, column_index++);

        break;
      }
      default:
        _gum_duk_throw (ctx, "invalid event type");
        return 0;
    }

    duk_put_prop_index (ctx, -2, row_index);
  }

  return 1;
}

static void
gum_duk_callback_transformer_transform_block (
    GumStalkerTransformer * transformer,
    GumStalkerIterator * iterator,
    GumStalkerWriter * output)
{
  GumDukCallbackTransformer * self =
      GUM_DUK_CALLBACK_TRANSFORMER_CAST (transformer);
  GumDukStalker * module = self->module;
  duk_context * ctx;
  GumDukScope scope;
  GumDukStalkerIterator * iterator_value;
  GumDukNativeWriter * output_value;

  ctx = _gum_duk_scope_enter (&scope, module->core);

  iterator_value = gum_duk_stalker_obtain_iterator (module);
  output_value = &iterator_value->parent;
  _gum_duk_native_writer_reset (output_value,
      (GumDukNativeWriterImpl *) output);
  gum_duk_stalker_iterator_reset (iterator_value, iterator);

  duk_push_heapptr (ctx, self->callback);
  duk_push_heapptr (ctx, output_value->object);
  _gum_duk_scope_call (&scope, 1);
  duk_pop (ctx);

  gum_duk_stalker_iterator_reset (iterator_value, NULL);
  _gum_duk_native_writer_reset (output_value, NULL);
  gum_duk_stalker_release_iterator (module, iterator_value);

  _gum_duk_scope_leave (&scope);
}

static void
gum_duk_callback_transformer_class_init (GumDukCallbackTransformerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_duk_callback_transformer_dispose;
}

static void
gum_duk_callback_transformer_iface_init (gpointer g_iface,
                                         gpointer iface_data)
{
  GumStalkerTransformerInterface * iface = g_iface;

  iface->transform_block = gum_duk_callback_transformer_transform_block;
}

static void
gum_duk_callback_transformer_init (GumDukCallbackTransformer * self)
{
}

static void
gum_duk_callback_transformer_dispose (GObject * object)
{
  GumDukCallbackTransformer * self = GUM_DUK_CALLBACK_TRANSFORMER_CAST (object);
  GumDukCore * core = self->module->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);

  if (self->callback != NULL)
  {
    _gum_duk_unprotect (ctx, self->callback);
    self->callback = NULL;
  }

  _gum_duk_scope_leave (&scope);

  G_OBJECT_CLASS (gum_duk_callback_transformer_parent_class)->dispose (object);
}

static void
gum_duk_call_probe_free (GumDukCallProbe * probe)
{
  GumDukCore * core = probe->module->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);

  _gum_duk_unprotect (ctx, probe->callback);

  _gum_duk_scope_leave (&scope);

  g_slice_free (GumDukCallProbe, probe);
}

static void
gum_duk_call_probe_on_fire (GumCallSite * site,
                            GumDukCallProbe * self)
{
  GumDukStalker * module = self->module;
  duk_context * ctx;
  GumDukScope scope;
  GumDukProbeArgs * args;

  ctx = _gum_duk_scope_enter (&scope, module->core);

  args = gum_duk_stalker_obtain_probe_args (module);
  gum_duk_probe_args_reset (args, site);

  duk_push_heapptr (ctx, self->callback);
  duk_push_heapptr (ctx, args->object);
  _gum_duk_scope_call (&scope, 1);
  duk_pop (ctx);

  gum_duk_probe_args_reset (args, NULL);
  gum_duk_stalker_release_probe_args (module, args);

  _gum_duk_scope_leave (&scope);
}

static GumDukStalkerIterator *
gum_duk_stalker_iterator_new (GumDukStalker * parent)
{
  GumDukCore * core = parent->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;
  GumDukStalkerIterator * iter;
  GumDukNativeWriter * writer;

  iter = g_slice_new (GumDukStalkerIterator);

  writer = &iter->parent;
  _gum_duk_native_writer_init (writer, parent->writer);

  iter->handle = NULL;
  iter->instruction = NULL;
  iter->module = parent;

  duk_push_heapptr (ctx, parent->iterator);
  duk_new (ctx, 0);
  _gum_duk_put_data (ctx, -1, iter);
  writer->object = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  return iter;
}

static void
gum_duk_stalker_iterator_release (GumDukStalkerIterator * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->module->core);

  _gum_duk_release_heapptr (scope.ctx, self->parent.object);
}

static void
gum_duk_stalker_iterator_reset (GumDukStalkerIterator * self,
                                GumStalkerIterator * handle)
{
  GumDukStalker * module = self->module;

  self->handle = handle;

  if (self->instruction != NULL)
  {
    self->instruction->insn = NULL;
    gum_duk_stalker_release_instruction (module, self->instruction);
  }
  self->instruction = (handle != NULL)
      ? gum_duk_stalker_obtain_instruction (module)
      : NULL;
}

static GumDukStalkerIterator *
gumjs_stalker_iterator_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumDukStalkerIterator * self;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  if (self->handle == NULL)
    _gum_duk_throw (ctx, "invalid operation");
  duk_pop (ctx);

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_stalker_iterator_construct)
{
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_stalker_iterator_finalize)
{
  GumDukStalkerIterator * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  _gum_duk_native_writer_finalize (&self->parent);

  g_slice_free (GumDukStalkerIterator, self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_iterator_next)
{
  GumDukStalkerIterator * self;

  self = gumjs_stalker_iterator_from_args (args);

  if (gum_stalker_iterator_next (self->handle, &self->instruction->insn))
    duk_push_heapptr (ctx, self->instruction->object);
  else
    duk_push_null (ctx);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_iterator_keep)
{
  GumDukStalkerIterator * self;

  self = gumjs_stalker_iterator_from_args (args);

  gum_stalker_iterator_keep (self->handle);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_iterator_put_callout)
{
  GumDukStalkerIterator * self;
  GumDukHeapPtr callback;
  GumDukCallout * callout;

  self = gumjs_stalker_iterator_from_args (args);

  _gum_duk_args_parse (args, "F", &callback);

  callout = g_slice_new (GumDukCallout);
  _gum_duk_protect (ctx, callback);
  callout->callback = callback;
  callout->module = self->module;

  gum_stalker_iterator_put_callout (self->handle,
      (GumStalkerCallout) gum_duk_callout_on_invoke, callout,
      (GDestroyNotify) gum_duk_callout_free);

  return 0;
}

static void
gum_duk_callout_free (GumDukCallout * callout)
{
  GumDukCore * core = callout->module->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);

  _gum_duk_unprotect (ctx, callout->callback);

  _gum_duk_scope_leave (&scope);

  g_slice_free (GumDukCallout, callout);
}

static void
gum_duk_callout_on_invoke (GumCpuContext * cpu_context,
                           GumDukCallout * self)
{
  GumDukStalker * module = self->module;
  duk_context * ctx;
  GumDukScope scope;
  GumDukCpuContext * cpu_context_value;

  ctx = _gum_duk_scope_enter (&scope, module->core);

  cpu_context_value = gum_duk_stalker_obtain_cpu_context (module);
  _gum_duk_cpu_context_reset (cpu_context_value, cpu_context,
      GUM_CPU_CONTEXT_READWRITE);

  duk_push_heapptr (ctx, self->callback);
  duk_push_heapptr (ctx, cpu_context_value->object);
  _gum_duk_scope_call (&scope, 1);
  duk_pop (ctx);

  _gum_duk_cpu_context_reset (cpu_context_value, NULL,
      GUM_CPU_CONTEXT_READWRITE);
  gum_duk_stalker_release_cpu_context (module, cpu_context_value);

  _gum_duk_scope_leave (&scope);
}

static GumDukProbeArgs *
gum_duk_probe_args_new (GumDukStalker * parent)
{
  GumDukCore * core = parent->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;
  GumDukProbeArgs * args;

  args = g_slice_new (GumDukProbeArgs);

  duk_push_heapptr (ctx, parent->probe_args);
  duk_new (ctx, 0);
  _gum_duk_put_data (ctx, -1, args);
  args->object = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  args->site = NULL;
  args->core = core;

  return args;
}

static void
gum_duk_probe_args_release (GumDukProbeArgs * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);

  _gum_duk_release_heapptr (scope.ctx, self->object);
}

static void
gum_duk_probe_args_reset (GumDukProbeArgs * self,
                          GumCallSite * site)
{
  self->site = site;
}

static GumCallSite *
gumjs_probe_args_require_call_site (duk_context * ctx,
                                    duk_idx_t index)
{
  GumDukProbeArgs * self = _gum_duk_require_data (ctx, index);

  if (self->site == NULL)
    _gum_duk_throw (ctx, "invalid operation");

  return self->site;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_probe_args_construct)
{
  duk_push_this (ctx);
  _gum_duk_push_proxy (ctx, -1, gumjs_probe_args_get_property,
      gumjs_probe_args_set_property);
  return 1;
}

GUMJS_DEFINE_FINALIZER (gumjs_probe_args_finalize)
{
  GumDukProbeArgs * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_slice_free (GumDukProbeArgs, self);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_probe_args_get_property)
{
  GumCallSite * site;
  guint n;

  if (duk_is_string (ctx, 1) &&
      strcmp (duk_require_string (ctx, 1), "toJSON") == 0)
  {
    duk_push_string (ctx, "probe-args");
    return 1;
  }

  site = gumjs_probe_args_require_call_site (ctx, 0);
  n = _gum_duk_require_index (ctx, 1);

  _gum_duk_push_native_pointer (ctx, gum_call_site_get_nth_argument (site, n),
      args->core);
  return 1;
}

GUMJS_DEFINE_SETTER (gumjs_probe_args_set_property)
{
  GumCallSite * site;
  guint n;
  gpointer value;

  site = gumjs_probe_args_require_call_site (ctx, 0);
  n = _gum_duk_require_index (ctx, 1);
  if (!_gum_duk_get_pointer (ctx, 2, args->core, &value))
  {
    duk_push_false (ctx);
    return 1;
  }

  gum_call_site_replace_nth_argument (site, n, value);

  duk_push_true (ctx);
  return 1;
}

static GumDukStalkerIterator *
gum_duk_stalker_obtain_iterator (GumDukStalker * self)
{
  GumDukStalkerIterator * iterator;

  if (!self->cached_iterator_in_use)
  {
    iterator = self->cached_iterator;
    self->cached_iterator_in_use = TRUE;
  }
  else
  {
    iterator = gum_duk_stalker_iterator_new (self);
  }

  return iterator;
}

static void
gum_duk_stalker_release_iterator (GumDukStalker * self,
                                  GumDukStalkerIterator * iterator)
{
  if (iterator == self->cached_iterator)
  {
    self->cached_iterator_in_use = FALSE;
  }
  else
  {
    gum_duk_stalker_iterator_release (iterator);
  }
}

static GumDukInstructionValue *
gum_duk_stalker_obtain_instruction (GumDukStalker * self)
{
  GumDukInstructionValue * value;

  if (!self->cached_instruction_in_use)
  {
    value = self->cached_instruction;
    self->cached_instruction_in_use = TRUE;
  }
  else
  {
    value = _gum_duk_instruction_new (self->instruction);
  }

  return value;
}

static void
gum_duk_stalker_release_instruction (GumDukStalker * self,
                                     GumDukInstructionValue * value)
{
  if (value == self->cached_instruction)
  {
    self->cached_instruction_in_use = FALSE;
  }
  else
  {
    _gum_duk_instruction_release (value);
  }
}

static GumDukCpuContext *
gum_duk_stalker_obtain_cpu_context (GumDukStalker * self)
{
  GumDukCpuContext * cpu_context;

  if (!self->cached_cpu_context_in_use)
  {
    cpu_context = self->cached_cpu_context;
    self->cached_cpu_context_in_use = TRUE;
  }
  else
  {
    cpu_context = _gum_duk_cpu_context_new (self->core);
  }

  return cpu_context;
}

static void
gum_duk_stalker_release_cpu_context (GumDukStalker * self,
                                     GumDukCpuContext * cpu_context)
{
  if (cpu_context == self->cached_cpu_context)
  {
    self->cached_cpu_context_in_use = FALSE;
  }
  else
  {
    _gum_duk_cpu_context_release (cpu_context);
  }
}

static GumDukProbeArgs *
gum_duk_stalker_obtain_probe_args (GumDukStalker * self)
{
  GumDukProbeArgs * args;

  if (!self->cached_probe_args_in_use)
  {
    args = self->cached_probe_args;
    self->cached_probe_args_in_use = TRUE;
  }
  else
  {
    args = gum_duk_probe_args_new (self);
  }

  return args;
}

static void
gum_duk_stalker_release_probe_args (GumDukStalker * self,
                                    GumDukProbeArgs * args)
{
  if (args == self->cached_probe_args)
    self->cached_probe_args_in_use = FALSE;
  else
    gum_duk_probe_args_release (args);
}

static void
gum_push_pointer (duk_context * ctx,
                  gpointer value,
                  gboolean stringify,
                  GumDukCore * core)
{
  if (stringify)
  {
    gchar str[32];

    sprintf (str, "0x%" G_GSIZE_MODIFIER "x", GPOINTER_TO_SIZE (value));
    duk_push_string (ctx, str);
  }
  else
  {
    _gum_duk_push_native_pointer (ctx, value, core);
  }
}
