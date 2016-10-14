/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_OBJECT_H__
#define __GUM_V8_OBJECT_H__

#include "gumv8core.h"

#include <v8.h>

struct GumV8ObjectManager
{
  GCancellable * cancellable;

  GHashTable * object_by_handle;
};

template<typename O, typename M>
struct GumV8Object
{
  GumPersistent<v8::Object>::type * wrapper;
  O * handle;
  GCancellable * cancellable;

  GumV8Core * core;
  M * module;

  GumV8ObjectManager * manager;
};

template<typename O, typename M>
struct GumV8ObjectOperation
{
  GumPersistent<v8::Object>::type * wrapper;
  O * handle;
  GCancellable * cancellable;
  GumPersistent<v8::Function>::type * callback;

  GumV8Core * core;
  M * module;

  GumScriptJob * job;
  gsize size;
  void (* cleanup) (GumV8ObjectOperation<O, M> * op);
};

template<typename M>
struct GumV8ModuleOperation
{
  M * module;
  GCancellable * cancellable;
  GumPersistent<v8::Function>::type * callback;

  GumV8Core * core;

  GumScriptJob * job;
  gsize size;
  void (* cleanup) (GumV8ModuleOperation<M> * op);
};

G_GNUC_INTERNAL void gum_v8_object_manager_init (GumV8ObjectManager * manager);
G_GNUC_INTERNAL void gum_v8_object_manager_flush (GumV8ObjectManager * manager);
G_GNUC_INTERNAL void gum_v8_object_manager_free (GumV8ObjectManager * manager);
G_GNUC_INTERNAL gpointer _gum_v8_object_manager_add (GumV8ObjectManager * self,
    v8::Handle<v8::Object> wrapper, gpointer handle, gpointer module,
    GumV8Core * core);
G_GNUC_INTERNAL gboolean gum_v8_object_manager_cancel (
    GumV8ObjectManager * self, gpointer handle);

template<typename T>
T *
gum_v8_object_get (const v8::FunctionCallbackInfo<v8::Value> & info)
{
  return (T *) info.Holder ()->GetAlignedPointerFromInternalField (0);
}

G_GNUC_INTERNAL gpointer _gum_v8_object_operation_new (gsize size,
    gpointer opaque_parent, v8::Handle<v8::Value> callback, GCallback perform,
    GCallback cleanup, GumV8Core * core);

G_GNUC_INTERNAL gpointer _gum_v8_module_operation_new (gsize size,
    gpointer module, GumV8ObjectManager * manager,
    v8::Handle<v8::Value> callback, GCallback perform, GCallback cleanup,
    GumV8Core * core);

template<typename O, typename M>
GumV8Object<O, M> *
gum_v8_object_manager_add (GumV8ObjectManager * self,
                           v8::Handle<v8::Object> wrapper,
                           O * handle,
                           M * module)
{
  return (GumV8Object<O, M> *) _gum_v8_object_manager_add (self, wrapper,
      handle, module, module->core);
}

template<typename T, typename O, typename M>
T *
gum_v8_object_operation_new (GumV8Object<O, M> * parent,
                             v8::Handle<v8::Value> callback,
                             void (* perform) (T * operation),
                             void (* cleanup) (T * operation) = nullptr)
{
  return (T *) _gum_v8_object_operation_new (sizeof (T), parent, callback,
      (GCallback) perform, (GCallback) cleanup, parent->module->core);
}

template<typename O, typename M>
void
gum_v8_object_operation_schedule (GumV8ObjectOperation<O, M> * self)
{
  gum_script_job_start_on_js_thread (self->job);
}

template<typename O, typename M>
void
gum_v8_object_operation_finish (GumV8ObjectOperation<O, M> * self)
{
  gum_script_job_free (self->job);
}

template<typename T, typename M>
T *
gum_v8_module_operation_new (M * module,
                             v8::Handle<v8::Value> callback,
                             void (* perform) (T * operation),
                             void (* cleanup) (T * operation) = nullptr)
{
  return (T *) _gum_v8_module_operation_new (sizeof (T), module,
      &module->objects, callback, (GCallback) perform, (GCallback) cleanup,
      module->core);
}

template<typename M>
void
gum_v8_module_operation_schedule (GumV8ModuleOperation<M> * self)
{
  gum_script_job_start_on_js_thread (self->job);
}

template<typename M>
void
gum_v8_module_operation_finish (GumV8ModuleOperation<M> * self)
{
  gum_script_job_free (self->job);
}

#endif
