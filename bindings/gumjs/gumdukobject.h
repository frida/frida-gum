/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_OBJECT_H__
#define __GUM_DUK_OBJECT_H__

#include "gumdukvalue.h"

#define GUM_DUK_OBJECT_OPERATION(o) ((GumDukObjectOperation *) (o))
#define GUM_DUK_MODULE_OPERATION(o) ((GumDukModuleOperation *) (o))

G_BEGIN_DECLS

typedef struct _GumDukObjectManager GumDukObjectManager;
typedef struct _GumDukObject GumDukObject;
typedef struct _GumDukObjectOperation GumDukObjectOperation;
typedef struct _GumDukModuleOperation GumDukModuleOperation;

typedef void (* GumDukObjectOperationFunc) (GumDukObjectOperation * op);
typedef void (* GumDukModuleOperationFunc) (GumDukModuleOperation * op);

struct _GumDukObjectManager
{
  gpointer module;
  GumDukCore * core;
  GHashTable * object_by_handle;
  GCancellable * cancellable;
};

struct _GumDukObject
{
  GumDukHeapPtr wrapper;
  gpointer handle;
  GCancellable * cancellable;

  GumDukCore * core;
  gpointer module;

  GumDukObjectManager * manager;
  guint num_active_operations;
  GQueue * pending_operations;
};

struct _GumDukObjectOperation
{
  GumDukObject * object;
  GumDukHeapPtr callback;

  GumDukCore * core;

  GumDukHeapPtr wrapper;
  GumScriptJob * job;
  GSList * pending_dependencies;
  gsize size;
  GumDukObjectOperationFunc dispose;
};

struct _GumDukModuleOperation
{
  gpointer module;
  GCancellable * cancellable;
  GumDukHeapPtr callback;

  GumDukCore * core;

  GumScriptJob * job;
  gsize size;
  GumDukModuleOperationFunc dispose;
};

G_GNUC_INTERNAL void _gum_duk_object_manager_init (GumDukObjectManager * self,
    gpointer module, GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_object_manager_flush (GumDukObjectManager * self);
G_GNUC_INTERNAL void _gum_duk_object_manager_free (GumDukObjectManager * self);
G_GNUC_INTERNAL gpointer _gum_duk_object_manager_add (
    GumDukObjectManager * self, duk_context * ctx, duk_idx_t index,
    gpointer handle);
G_GNUC_INTERNAL gpointer _gum_duk_object_manager_lookup (
    GumDukObjectManager * self, gpointer handle);

G_GNUC_INTERNAL gpointer _gum_duk_object_get (const GumDukArgs * args);

#define _gum_duk_object_operation_new(type, object, callback, perform, \
    dispose) _gum_duk_object_operation_alloc (sizeof (type), object, callback, \
        (GumDukObjectOperationFunc) perform, \
        (GumDukObjectOperationFunc) dispose)
G_GNUC_INTERNAL gpointer _gum_duk_object_operation_alloc (gsize size,
    GumDukObject * object, GumDukHeapPtr callback,
    GumDukObjectOperationFunc perform, GumDukObjectOperationFunc dispose);
G_GNUC_INTERNAL void _gum_duk_object_operation_schedule (gpointer self);
G_GNUC_INTERNAL void _gum_duk_object_operation_schedule_when_idle (
    gpointer self, GPtrArray * dependencies);
G_GNUC_INTERNAL void _gum_duk_object_operation_finish (
    GumDukObjectOperation * self);

#define _gum_duk_module_operation_new(type, module, callback, perform, \
    dispose) _gum_duk_module_operation_alloc (sizeof (type), module, \
        &(module)->objects, callback, (GumDukModuleOperationFunc) perform, \
        (GumDukModuleOperationFunc) dispose)
G_GNUC_INTERNAL gpointer _gum_duk_module_operation_alloc (gsize size,
    gpointer module, GumDukObjectManager * manager, GumDukHeapPtr callback,
    GumDukModuleOperationFunc perform, GumDukModuleOperationFunc dispose);
G_GNUC_INTERNAL void _gum_duk_module_operation_schedule (gpointer self);
G_GNUC_INTERNAL void _gum_duk_module_operation_finish (
    GumDukModuleOperation * self);

G_END_DECLS

#endif
