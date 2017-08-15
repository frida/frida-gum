/*
 * Copyright (C) 2010-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8stalker.h"

#include "gumv8eventsink.h"
#include "gumv8macros.h"
#include "gumv8scope.h"

#define GUMJS_MODULE_NAME Stalker

using namespace v8;

struct GumV8CallProbe
{
  GumPersistent<Function>::type * callback;

  GumV8Stalker * module;
};

GUMJS_DECLARE_GETTER (gumjs_stalker_get_trust_threshold)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_trust_threshold)

GUMJS_DECLARE_GETTER (gumjs_stalker_get_queue_capacity)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_queue_capacity)

GUMJS_DECLARE_GETTER (gumjs_stalker_get_queue_drain_interval)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_queue_drain_interval)

GUMJS_DECLARE_FUNCTION (gumjs_stalker_garbage_collect)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_follow)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_unfollow)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_add_call_probe)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_remove_call_probe)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_parse)

static void gum_v8_call_probe_free (GumV8CallProbe * probe);
static void gum_v8_call_probe_on_fire (GumCallSite * site,
    GumV8CallProbe * self);

static void gumjs_probe_args_get_nth (uint32_t index,
    const PropertyCallbackInfo<Value> & info);
static void gumjs_probe_args_set_nth (uint32_t index, Local<Value> value,
    const PropertyCallbackInfo<Value> & info);

static Local<Value> gum_make_pointer (gpointer value, gboolean stringify,
    GumV8Core * core);

static const GumV8Property gumjs_stalker_values[] =
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

static const GumV8Function gumjs_stalker_functions[] =
{
  { "garbageCollect", gumjs_stalker_garbage_collect },
  { "_follow", gumjs_stalker_follow },
  { "unfollow", gumjs_stalker_unfollow },
  { "addCallProbe", gumjs_stalker_add_call_probe },
  { "removeCallProbe", gumjs_stalker_remove_call_probe },
  { "_parse", gumjs_stalker_parse },

  { NULL, NULL }
};

void
_gum_v8_stalker_init (GumV8Stalker * self,
                      GumV8Core * core,
                      Handle<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;
  self->stalker = NULL;
  self->queue_capacity = 16384;
  self->queue_drain_interval = 250;

  auto module = External::New (isolate, self);

  auto stalker = _gum_v8_create_module ("Stalker", scope, isolate);
  _gum_v8_module_add (module, stalker, gumjs_stalker_values, isolate);
  _gum_v8_module_add (module, stalker, gumjs_stalker_functions, isolate);
}

void
_gum_v8_stalker_realize (GumV8Stalker * self)
{
  auto isolate = self->core->isolate;

  auto args_templ = ObjectTemplate::New (isolate);
  args_templ->SetInternalFieldCount (2);
  args_templ->SetIndexedPropertyHandler (gumjs_probe_args_get_nth,
      gumjs_probe_args_set_nth);
  self->probe_args =
      new GumPersistent<ObjectTemplate>::type(isolate, args_templ);
}

void
_gum_v8_stalker_flush (GumV8Stalker * self)
{
  auto isolate = self->core->isolate;

  auto stalker = (GumStalker *) g_steal_pointer (&self->stalker);
  if (stalker != NULL)
  {
    isolate->Exit ();
    {
      Unlocker ul (isolate);

      gum_stalker_stop (stalker);
      g_object_unref (stalker);
    }
    isolate->Enter ();
  }
}

void
_gum_v8_stalker_dispose (GumV8Stalker * self)
{
  delete self->probe_args;
  self->probe_args = nullptr;
}

void
_gum_v8_stalker_finalize (GumV8Stalker * self)
{
  (void) self;
}

GumStalker *
_gum_v8_stalker_get (GumV8Stalker * self)
{
  if (self->stalker == NULL)
    self->stalker = gum_stalker_new ();

  return self->stalker;
}

void
_gum_v8_stalker_process_pending (GumV8Stalker * self,
                                 ScriptStalkerScope * scope)
{
  if (scope->pending_level > 0)
  {
    gum_stalker_follow_me (_gum_v8_stalker_get (self), scope->sink);
  }
  else if (scope->pending_level < 0)
  {
    gum_stalker_unfollow_me (_gum_v8_stalker_get (self));
  }
  scope->pending_level = 0;

  g_clear_object (&scope->sink);
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_trust_threshold)
{
  auto stalker = _gum_v8_stalker_get (module);

  info.GetReturnValue ().Set (gum_stalker_get_trust_threshold (stalker));
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_trust_threshold)
{
  auto stalker = _gum_v8_stalker_get (module);

  gint threshold;
  if (!_gum_v8_int_get (value, &threshold, core))
    return;

  gum_stalker_set_trust_threshold (stalker, threshold);
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_capacity)
{
  info.GetReturnValue ().Set (module->queue_capacity);
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_capacity)
{
  guint capacity;
  if (!_gum_v8_uint_get (value, &capacity, core))
    return;

  module->queue_capacity = capacity;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_drain_interval)
{
  info.GetReturnValue ().Set (module->queue_drain_interval);
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_drain_interval)
{
  guint interval;
  if (!_gum_v8_uint_get (value, &interval, core))
    return;

  module->queue_drain_interval = interval;
}

/*
 * Prototype:
 * Stalker.garbageCollect()
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_stalker_garbage_collect)
{
  auto stalker = _gum_v8_stalker_get (module);

  gum_stalker_garbage_collect (stalker);
}

/*
 * Prototype:
 * TBW
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_stalker_follow)
{
  GumStalker * stalker;
  GumThreadId thread_id;

  stalker = _gum_v8_stalker_get (module);

  GumV8EventSinkOptions so;
  so.core = core;
  so.main_context = gum_script_scheduler_get_js_context (core->scheduler);
  so.queue_capacity = module->queue_capacity;
  so.queue_drain_interval = module->queue_drain_interval;

  if (!_gum_v8_args_parse (args, "ZuF?F?", &thread_id, &so.event_mask,
      &so.on_receive, &so.on_call_summary))
    return;

  auto sink = gum_v8_event_sink_new (&so);
  if (thread_id == gum_process_get_current_thread_id ())
  {
    ScriptStalkerScope * scope = &core->current_scope->stalker_scope;

    scope->pending_level = 1;

    g_clear_object (&scope->sink);
    scope->sink = sink;
  }
  else
  {
    gum_stalker_follow (stalker, thread_id, sink);
    g_object_unref (sink);
  }
}

/*
 * Prototype:
 * Stalker.unfollow(thread_id)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_stalker_unfollow)
{
  GumStalker * stalker;
  GumThreadId current_thread_id = gum_process_get_current_thread_id ();

  stalker = _gum_v8_stalker_get (module);

  GumThreadId thread_id = current_thread_id;
  if (!_gum_v8_args_parse (args, "|Z", &thread_id))
    return;

  if (thread_id == current_thread_id)
    core->current_scope->stalker_scope.pending_level--;
  else
    gum_stalker_unfollow (stalker, thread_id);
}

/*
 * Prototype:
 * Stalker.addCallProbe(target_address, callback)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_stalker_add_call_probe)
{
  gpointer target_address;
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "pF", &target_address, &callback))
    return;

  auto probe = g_slice_new (GumV8CallProbe);
  probe->callback = new GumPersistent<Function>::type (isolate, callback);
  probe->module = module;

  auto id = gum_stalker_add_call_probe (_gum_v8_stalker_get (module),
      target_address, (GumCallProbeCallback) gum_v8_call_probe_on_fire, probe,
      (GDestroyNotify) gum_v8_call_probe_free);

  info.GetReturnValue ().Set (id);
}

/*
 * Prototype:
 * Stalker.removeCallProbe(id)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
GUMJS_DEFINE_FUNCTION (gumjs_stalker_remove_call_probe)
{
  GumProbeId id;
  if (!_gum_v8_args_parse (args, "u", &id))
    return;

  gum_stalker_remove_call_probe (_gum_v8_stalker_get (module), id);
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_parse)
{
  Local<Value> events_value;
  gboolean annotate, stringify;
  if (!_gum_v8_args_parse (args, "Vtt", &events_value, &annotate, &stringify))
    return;

  if (!events_value->IsArrayBuffer ())
  {
    _gum_v8_throw_ascii_literal (isolate, "expected an ArrayBuffer");
    return;
  }

  auto events_contents = events_value.As<ArrayBuffer> ()->GetContents ();
  const GumEvent * events = (const GumEvent *) events_contents.Data ();
  size_t size = events_contents.ByteLength ();
  if (size % sizeof (GumEvent) != 0)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid buffer shape");
    return;
  }

  size_t count = size / sizeof (GumEvent);

  auto rows = Array::New (isolate, (int) count);

  const GumEvent * ev;
  size_t row_index;
  for (ev = events, row_index = 0;
      row_index != count;
      ev++, row_index++)
  {
    Local<Array> row;
    guint column_index = 0;

    switch (ev->type)
    {
      case GUM_CALL:
      {
        const GumCallEvent * call = &ev->call;

        if (annotate)
        {
          row = Array::New (isolate, 4);
          row->Set (column_index++, _gum_v8_string_new_ascii (isolate, "call"));
        }
        else
        {
          row = Array::New (isolate, 3);
        }

        row->Set (column_index++,
            gum_make_pointer (call->location, stringify, core));
        row->Set (column_index++,
            gum_make_pointer (call->target, stringify, core));
        row->Set (column_index++, Integer::New (isolate, call->depth));

        break;
      }
      case GUM_RET:
      {
        const GumRetEvent * ret = &ev->ret;

        if (annotate)
        {
          row = Array::New (isolate, 4);
          row->Set (column_index++, _gum_v8_string_new_ascii (isolate, "ret"));
        }
        else
        {
          row = Array::New (isolate, 3);
        }

        row->Set (column_index++,
            gum_make_pointer (ret->location, stringify, core));
        row->Set (column_index++,
            gum_make_pointer (ret->target, stringify, core));
        row->Set (column_index++, Integer::New (isolate, ret->depth));

        break;
      }
      case GUM_EXEC:
      {
        const GumExecEvent * exec = &ev->exec;

        if (annotate)
        {
          row = Array::New (isolate, 2);
          row->Set (column_index++, _gum_v8_string_new_ascii (isolate, "exec"));
        }
        else
        {
          row = Array::New (isolate, 1);
        }

        row->Set (column_index++,
            gum_make_pointer (exec->location, stringify, core));

        break;
      }
      case GUM_BLOCK:
      {
        const GumBlockEvent * block = &ev->block;

        if (annotate)
        {
          row = Array::New (isolate, 3);
          row->Set (column_index++,
              _gum_v8_string_new_ascii (isolate, "block"));
        }
        else
        {
          row = Array::New (isolate, 2);
        }

        row->Set (column_index++,
            gum_make_pointer (block->begin, stringify, core));
        row->Set (column_index++,
            gum_make_pointer (block->end, stringify, core));

        break;
      }
      case GUM_COMPILE:
      {
        const GumCompileEvent * compile = &ev->compile;

        if (annotate)
        {
          row = Array::New (isolate, 3);
          row->Set (column_index++,
              _gum_v8_string_new_ascii (isolate, "compile"));
        }
        else
        {
          row = Array::New (isolate, 2);
        }

        row->Set (column_index++,
            gum_make_pointer (compile->begin, stringify, core));
        row->Set (column_index++,
            gum_make_pointer (compile->end, stringify, core));

        break;
      }
      default:
        g_assert_not_reached ();
        break;
    }

    rows->Set ((uint32_t) row_index, row);
  }

  info.GetReturnValue ().Set (rows);
}

static void
gum_v8_call_probe_free (GumV8CallProbe * probe)
{
  ScriptScope scope (probe->module->core->script);

  delete probe->callback;

  g_slice_free (GumV8CallProbe, probe);
}

static void
gum_v8_call_probe_on_fire (GumCallSite * site,
                           GumV8CallProbe * self)
{
  auto core = self->module->core;
  ScriptScope scope (core->script);
  Isolate * isolate = core->isolate;

  auto probe_args =
      Local<ObjectTemplate>::New (isolate, *self->module->probe_args);
  auto args = probe_args->NewInstance ();
  args->SetAlignedPointerInInternalField (0, self);
  args->SetAlignedPointerInInternalField (1, site);

  auto callback (Local<Function>::New (isolate, *self->callback));
  Handle<Value> argv[] = { args };
  callback->Call (Undefined (isolate), G_N_ELEMENTS (argv), argv);

  args->SetAlignedPointerInInternalField (0, nullptr);
  args->SetAlignedPointerInInternalField (1, nullptr);
}

static void
gumjs_probe_args_get_nth (uint32_t index,
                          const PropertyCallbackInfo<Value> & info)
{
  auto wrapper = info.This ();
  auto self =
      (GumV8CallProbe *) wrapper->GetAlignedPointerFromInternalField (0);
  auto site =
      (GumCallSite *) wrapper->GetAlignedPointerFromInternalField (1);
  auto core = self->module->core;

  if (site == nullptr)
  {
    _gum_v8_throw_ascii_literal (core->isolate, "invalid operation");
    return;
  }

  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (gum_call_site_get_nth_argument (site, index),
          core));
}

static void
gumjs_probe_args_set_nth (uint32_t index,
                          Local<Value> value,
                          const PropertyCallbackInfo<Value> & info)
{
  auto wrapper = info.This ();
  auto self =
      (GumV8CallProbe *) wrapper->GetAlignedPointerFromInternalField (0);
  auto site =
      (GumCallSite *) wrapper->GetAlignedPointerFromInternalField (1);
  auto core = self->module->core;

  if (site == nullptr)
  {
    _gum_v8_throw_ascii_literal (core->isolate, "invalid operation");
    return;
  }

  info.GetReturnValue ().Set (value);

  gpointer raw_value;
  if (!_gum_v8_native_pointer_get (value, &raw_value, core))
    return;

  gum_call_site_replace_nth_argument (site, index, raw_value);
}

static Local<Value>
gum_make_pointer (gpointer value,
                  gboolean stringify,
                  GumV8Core * core)
{
  if (stringify)
  {
    gchar str[32];

    sprintf (str, "0x%" G_GSIZE_MODIFIER "x", GPOINTER_TO_SIZE (value));

    return _gum_v8_string_new_ascii (core->isolate, str);
  }
  else
  {
    return _gum_v8_native_pointer_new (value, core);
  }
}
