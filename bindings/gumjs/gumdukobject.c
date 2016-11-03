/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukobject.h"

#include "gumdukmacros.h"

typedef struct _GumDukTryScheduleIfIdleOperation
    GumDukTryScheduleIfIdleOperation;

struct _GumDukTryScheduleIfIdleOperation
{
  GumDukObjectOperation parent;
  GumDukObjectOperation * blocked_operation;
};

GUMJS_DECLARE_FINALIZER (gumjs_object_finalize)
static void gum_duk_object_free (GumDukObject * self);

static void gum_duk_object_operation_free (GumDukObjectOperation * self);
static void gum_duk_object_operation_try_schedule_when_idle (
    GumDukObjectOperation * self);
static void gum_duk_try_schedule_if_idle_operation_perform (
    GumDukTryScheduleIfIdleOperation * self);

static void gum_duk_module_operation_free (GumDukModuleOperation * self);

void
_gum_duk_object_manager_init (GumDukObjectManager * self,
                              gpointer module,
                              GumDukCore * core)
{
  self->module = module;
  self->core = core;
  self->object_by_handle = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  self->cancellable = g_cancellable_new ();
}

void
_gum_duk_object_manager_flush (GumDukObjectManager * self)
{
  GPtrArray * cancellables;
  GHashTableIter iter;
  GumDukObject * object;

  cancellables = g_ptr_array_new_full (
      g_hash_table_size (self->object_by_handle), g_object_unref);
  g_hash_table_iter_init (&iter, self->object_by_handle);
  while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &object))
  {
    g_ptr_array_add (cancellables, g_object_ref (object->cancellable));
  }
  g_ptr_array_foreach (cancellables, (GFunc) g_cancellable_cancel, NULL);
  g_ptr_array_unref (cancellables);

  g_cancellable_cancel (self->cancellable);
}

void
_gum_duk_object_manager_free (GumDukObjectManager * self)
{
  GHashTableIter iter;
  GumDukObject * object;

  g_hash_table_iter_init (&iter, self->object_by_handle);
  while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &object))
  {
    object->manager = NULL;
  }
  g_hash_table_remove_all (self->object_by_handle);

  g_object_unref (self->cancellable);
  g_hash_table_unref (self->object_by_handle);
}

gpointer
_gum_duk_object_manager_add (GumDukObjectManager * self,
                             duk_context * ctx,
                             duk_idx_t index,
                             gpointer handle)
{
  GumDukObject * object;

  duk_dup (ctx, index);

  object = g_slice_new (GumDukObject);
  object->wrapper = duk_get_heapptr (ctx, -1);
  object->handle = handle;
  object->cancellable = g_cancellable_new ();

  object->core = self->core;
  object->module = self->module;

  object->manager = self;
  object->num_active_operations = 0;
  object->pending_operations = g_queue_new ();

  _gum_duk_put_data (ctx, -1, object);
  duk_push_c_function (ctx, gumjs_object_finalize, 1);
  duk_set_finalizer (ctx, -2);

  g_hash_table_insert (self->object_by_handle, handle, object);

  duk_pop (ctx);

  return object;
}

gpointer
_gum_duk_object_manager_lookup (GumDukObjectManager * self,
                                gpointer handle)
{
  return g_hash_table_lookup (self->object_by_handle, handle);
}

GUMJS_DEFINE_FINALIZER (gumjs_object_finalize)
{
  GumDukObject * self;

  (void) args;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  if (self->manager != NULL)
  {
    g_hash_table_remove (self->manager->object_by_handle, self->handle);
  }

  gum_duk_object_free (self);

  return 0;
}

static void
gum_duk_object_free (GumDukObject * self)
{
  g_assert_cmpuint (self->num_active_operations, ==, 0);
  g_assert (g_queue_is_empty (self->pending_operations));
  g_queue_free (self->pending_operations);

  g_object_unref (self->cancellable);
  g_object_unref (self->handle);

  g_slice_free (GumDukObject, self);
}

gpointer
_gum_duk_object_get (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  gpointer object;

  duk_push_this (ctx);
  object = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  return object;
}

gpointer
_gum_duk_object_operation_alloc (gsize size,
                                 GumDukObject * object,
                                 GumDukHeapPtr callback,
                                 GumDukObjectOperationFunc perform,
                                 GumDukObjectOperationFunc dispose)
{
  GumDukCore * core = object->core;
  duk_context * ctx = core->current_ctx;
  GumDukObjectOperation * op;

  op = g_slice_alloc (size);

  op->object = object;
  _gum_duk_protect (ctx, callback);
  op->callback = callback;

  op->core = core;

  _gum_duk_protect (ctx, object->wrapper);
  op->wrapper = object->wrapper;
  op->job = gum_script_job_new (core->scheduler, (GumScriptJobFunc) perform, op,
      (GDestroyNotify) gum_duk_object_operation_free);
  op->pending_dependencies = NULL;
  op->size = size;
  op->dispose = dispose;

  _gum_duk_core_pin (core);

  return op;
}

static void
gum_duk_object_operation_free (GumDukObjectOperation * self)
{
  GumDukObject * object = self->object;
  GumDukCore * core = object->core;
  GumDukScope scope;
  duk_context * ctx;

  g_assert (self->pending_dependencies == NULL);

  if (self->dispose != NULL)
    self->dispose (self);

  ctx = _gum_duk_scope_enter (&scope, core);

  _gum_duk_unprotect (ctx, self->wrapper);
  _gum_duk_unprotect (ctx, self->callback);

  if (--object->num_active_operations == 0)
  {
    gpointer next;

    next = g_queue_pop_head (object->pending_operations);
    if (next != NULL)
      _gum_duk_object_operation_schedule (next);
  }

  _gum_duk_core_unpin (core);

  _gum_duk_scope_leave (&scope);

  g_slice_free1 (self->size, self);
}

void
_gum_duk_object_operation_schedule (gpointer self)
{
  GumDukObjectOperation * op = self;

  op->object->num_active_operations++;
  gum_script_job_start_on_js_thread (op->job);
}

void
_gum_duk_object_operation_schedule_when_idle (gpointer self,
                                              GPtrArray * dependencies)
{
  GumDukObjectOperation * op = self;

  if (dependencies != NULL)
  {
    guint i;

    for (i = 0; i != dependencies->len; i++)
    {
      GumDukObject * dependency = g_ptr_array_index (dependencies, i);

      if (dependency->num_active_operations > 0)
      {
        GumDukTryScheduleIfIdleOperation * try_schedule;

        try_schedule = _gum_duk_object_operation_new (
            GumDukTryScheduleIfIdleOperation, dependency, NULL,
            gum_duk_try_schedule_if_idle_operation_perform, NULL);
        try_schedule->blocked_operation = op;
        op->pending_dependencies =
            g_slist_prepend (op->pending_dependencies, try_schedule);
        _gum_duk_object_operation_schedule_when_idle (try_schedule, NULL);
      }
    }
  }

  gum_duk_object_operation_try_schedule_when_idle (op);
}

static void
gum_duk_object_operation_try_schedule_when_idle (GumDukObjectOperation * self)
{
  GumDukObject * object = self->object;

  if (self->pending_dependencies != NULL)
    return;

  if (object->num_active_operations == 0)
    _gum_duk_object_operation_schedule (self);
  else
    g_queue_push_tail (object->pending_operations, self);
}

static void
gum_duk_try_schedule_if_idle_operation_perform (
    GumDukTryScheduleIfIdleOperation * self)
{
  GumDukObjectOperation * op = GUM_DUK_OBJECT_OPERATION (self);
  GumDukObjectOperation * blocked = self->blocked_operation;
  GumDukScope scope;

  _gum_duk_scope_enter (&scope, op->core);

  blocked->pending_dependencies =
      g_slist_remove (blocked->pending_dependencies, self);
  gum_duk_object_operation_try_schedule_when_idle (blocked);

  _gum_duk_scope_leave (&scope);

  _gum_duk_object_operation_finish (op);
}

void
_gum_duk_object_operation_finish (GumDukObjectOperation * self)
{
  gum_script_job_free (self->job);
}

gpointer
_gum_duk_module_operation_alloc (gsize size,
                                 gpointer module,
                                 GumDukObjectManager * manager,
                                 GumDukHeapPtr callback,
                                 GumDukModuleOperationFunc perform,
                                 GumDukModuleOperationFunc dispose)
{
  GumDukCore * core = manager->core;
  duk_context * ctx = core->current_ctx;
  GumDukModuleOperation * op;

  op = g_slice_alloc (size);

  op->module = module;
  op->cancellable = manager->cancellable;
  _gum_duk_protect (ctx, callback);
  op->callback = callback;

  op->core = core;

  op->job = gum_script_job_new (core->scheduler, (GumScriptJobFunc) perform, op,
      (GDestroyNotify) gum_duk_module_operation_free);
  op->size = size;
  op->dispose = dispose;

  _gum_duk_core_pin (core);

  return op;
}

static void
gum_duk_module_operation_free (GumDukModuleOperation * self)
{
  GumDukCore * core = self->core;
  GumDukScope scope;
  duk_context * ctx;

  if (self->dispose != NULL)
    self->dispose (self);

  ctx = _gum_duk_scope_enter (&scope, core);

  _gum_duk_unprotect (ctx, self->callback);
  _gum_duk_core_unpin (core);

  _gum_duk_scope_leave (&scope);

  g_slice_free1 (self->size, self);
}

void
_gum_duk_module_operation_schedule (gpointer self)
{
  GumDukObjectOperation * op = self;

  gum_script_job_start_on_js_thread (op->job);
}

void
_gum_duk_module_operation_finish (GumDukModuleOperation * self)
{
  gum_script_job_free (self->job);
}
