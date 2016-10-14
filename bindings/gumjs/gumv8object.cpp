/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8object.h"

#include "gumv8scope.h"

using namespace v8;

typedef GumV8Object<void, void> GumV8AnyObject;
typedef GumV8ObjectOperation<void, void> GumV8AnyObjectOperation;
typedef GumV8ModuleOperation<void> GumV8AnyModuleOperation;

static void gum_v8_object_on_weak_notify (
    const WeakCallbackInfo<GumV8AnyObject> & info);
static void gum_v8_object_free (GumV8AnyObject * obj);

static void gum_v8_object_operation_free (GumV8AnyObjectOperation * op);

static void gum_v8_module_operation_free (GumV8AnyModuleOperation * op);

void
gum_v8_object_manager_init (GumV8ObjectManager * manager)
{
  manager->cancellable = g_cancellable_new ();

  manager->object_by_handle = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_object_free);
}

void
gum_v8_object_manager_flush (GumV8ObjectManager * manager)
{
  GHashTableIter iter;
  GumV8AnyObject * object;

  g_hash_table_iter_init (&iter, manager->object_by_handle);
  while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &object))
  {
    g_cancellable_cancel (object->cancellable);
  }

  g_cancellable_cancel (manager->cancellable);
}

void
gum_v8_object_manager_free (GumV8ObjectManager * manager)
{
  g_hash_table_remove_all (manager->object_by_handle);
  g_hash_table_unref (manager->object_by_handle);

  g_object_unref (manager->cancellable);
}

gpointer
_gum_v8_object_manager_add (GumV8ObjectManager * self,
                            Handle<Object> wrapper,
                            gpointer handle,
                            gpointer module,
                            GumV8Core * core)
{
  GumV8AnyObject * object;

  object = g_slice_new (GumV8AnyObject);
  GumPersistent<Object>::type * w = new GumPersistent<Object>::type (
      core->isolate, wrapper);
  w->MarkIndependent ();
  w->SetWeak (object, gum_v8_object_on_weak_notify,
      WeakCallbackType::kParameter);
  object->wrapper = w;
  object->handle = handle;
  object->cancellable = g_cancellable_new ();

  object->core = core;
  object->module = module;

  wrapper->SetAlignedPointerInInternalField (0, object);

  g_hash_table_insert (self->object_by_handle, handle, object);

  return object;
}

gboolean
gum_v8_object_manager_cancel (GumV8ObjectManager * manager,
                              gpointer handle)
{
  GumV8AnyObject * object = (GumV8AnyObject *)
      g_hash_table_lookup (manager->object_by_handle, handle);
  if (object == NULL)
    return FALSE;

  g_cancellable_cancel (object->cancellable);
  return TRUE;
}

static void
gum_v8_object_on_weak_notify (
    const WeakCallbackInfo<GumV8AnyObject> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  GumV8AnyObject * object = info.GetParameter ();
  g_hash_table_remove (object->manager->object_by_handle, object->handle);
}

static void
gum_v8_object_free (GumV8AnyObject * object)
{
  g_object_unref (object->cancellable);
  g_object_unref (object->handle);
  delete object->wrapper;

  g_slice_free (GumV8AnyObject, object);
}

gpointer
_gum_v8_object_operation_new (gsize size,
                              gpointer opaque_parent,
                              Handle<Value> callback,
                              GCallback perform,
                              GCallback cleanup,
                              GumV8Core * core)
{
  GumV8AnyObject * parent = (GumV8AnyObject *) opaque_parent;
  Isolate * isolate = core->isolate;

  GumV8AnyObjectOperation * op =
      (GumV8AnyObjectOperation *) g_slice_alloc (size);

  op->wrapper = new GumPersistent<Object>::type (isolate,
      *parent->wrapper);
  op->handle = parent->handle;
  op->cancellable = parent->cancellable;
  op->callback = new GumPersistent<Function>::type (isolate,
      callback.As<Function> ());

  op->core = core;
  op->module = parent->module;

  op->job = gum_script_job_new (core->scheduler, (GumScriptJobFunc) perform, op,
      (GDestroyNotify) gum_v8_object_operation_free);
  op->size = size;
  op->cleanup = (void (*) (GumV8AnyObjectOperation * op)) cleanup;

  _gum_v8_core_pin (core);

  return op;
}

static void
gum_v8_object_operation_free (GumV8AnyObjectOperation * op)
{
  GumV8Core * core = op->core;

  if (op->cleanup != NULL)
    op->cleanup (op);

  {
    ScriptScope scope (core->script);

    delete op->callback;
    delete op->wrapper;

    _gum_v8_core_unpin (core);
  }

  g_slice_free1 (op->size, op);
}

gpointer
_gum_v8_module_operation_new (gsize size,
                              gpointer module,
                              GumV8ObjectManager * manager,
                              Handle<Value> callback,
                              GCallback perform,
                              GCallback cleanup,
                              GumV8Core * core)
{
  Isolate * isolate = core->isolate;

  GumV8AnyModuleOperation * op =
      (GumV8AnyModuleOperation *) g_slice_alloc (size);

  op->module = module;
  op->cancellable = manager->cancellable;
  op->callback = new GumPersistent<Function>::type (isolate,
      callback.As<Function> ());

  op->core = core;

  op->job = gum_script_job_new (core->scheduler, (GumScriptJobFunc) perform, op,
      (GDestroyNotify) gum_v8_module_operation_free);
  op->size = size;
  op->cleanup = (void (*) (GumV8AnyModuleOperation * op)) cleanup;

  _gum_v8_core_pin (core);

  return op;
}

static void
gum_v8_module_operation_free (GumV8AnyModuleOperation * op)
{
  GumV8Core * core = op->core;

  if (op->cleanup != NULL)
    op->cleanup (op);

  {
    ScriptScope scope (core->script);

    delete op->callback;

    _gum_v8_core_unpin (core);
  }

  g_slice_free1 (op->size, op);
}
