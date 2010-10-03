/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumcobjecttracker.h"
#include "gumcobject.h"
#include "guminterceptor.h"
#include "gumhash.h"
#include <stdlib.h>
#include <string.h>

static void gum_cobject_tracker_listener_iface_init (gpointer g_iface,
    gpointer iface_data);

G_DEFINE_TYPE_EXTENDED (GumCObjectTracker,
                        gum_cobject_tracker,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                                               gum_cobject_tracker_listener_iface_init))

enum
{
  PROP_0,
  PROP_BACKTRACER,
};

typedef struct _ObjectType             ObjectType;
typedef struct _CObjectFunctionContext CObjectFunctionContext;
typedef struct _CObjectThreadContext   CObjectThreadContext;
typedef struct _CObjectHandlers        CObjectHandlers;

typedef void (* CObjectEnterHandler) (GumCObjectTracker * self,
    gpointer handler_context, CObjectThreadContext * thread_context,
    GumInvocationContext * invocation_context);
typedef void (* CObjectLeaveHandler) (GumCObjectTracker * self,
    gpointer handler_context, CObjectThreadContext * thread_context,
    GumInvocationContext * invocation_context);

struct _GumCObjectTrackerPrivate
{
  gboolean disposed;
  GMutex * mutex;
  GumHashTable * types_ht;
  GumHashTable * objects_ht;
  GumInterceptor * interceptor;
  GPtrArray * function_contexts;

  GumBacktracerIface * backtracer_interface;
  GumBacktracer * backtracer_instance;
};

struct _ObjectType
{
  gchar * name;
  guint count;
};

struct _CObjectHandlers
{
  CObjectEnterHandler enter_handler;
  CObjectLeaveHandler leave_handler;
};

struct _CObjectThreadContext
{
  gpointer data;
};

struct _CObjectFunctionContext
{
  CObjectHandlers handlers;
  gpointer context;

  CObjectThreadContext thread_contexts[GUM_MAX_THREADS];
  volatile gint thread_context_count;
};

#define GUM_COBJECT_TRACKER_GET_PRIVATE(o) ((o)->priv)

#define GUM_COBJECT_TRACKER_LOCK()   g_mutex_lock   (priv->mutex)
#define GUM_COBJECT_TRACKER_UNLOCK() g_mutex_unlock (priv->mutex)

static void gum_cobject_tracker_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);
static void gum_cobject_tracker_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_cobject_tracker_dispose (GObject * object);
static void gum_cobject_tracker_finalize (GObject * object);

static ObjectType * object_type_new (const gchar * name);
static void object_type_free (ObjectType * t);

static void gum_cobject_tracker_add_object (GumCObjectTracker * self,
    GumCObject * cobject);
static void gum_cobject_tracker_maybe_remove_object (GumCObjectTracker * self,
    gpointer address);

static void gum_cobject_tracker_attach_to_function (GumCObjectTracker * self,
    gpointer function_address, const CObjectHandlers * handlers,
    gpointer context);

static void gum_cobject_tracker_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_cobject_tracker_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);
static gpointer gum_cobject_tracker_provide_thread_data (
    GumInvocationListener * listener, gpointer function_instance_data,
    guint thread_id);

static void on_constructor_enter_handler (GumCObjectTracker * self,
    ObjectType * object_type, CObjectThreadContext * thread_context,
    GumInvocationContext * invocation_context);
static void on_constructor_leave_handler (GumCObjectTracker * self,
    ObjectType * object_type, CObjectThreadContext * thread_context,
    GumInvocationContext * invocation_context);
static void on_free_enter_handler (GumCObjectTracker * self,
    gpointer handler_context, CObjectThreadContext * thread_context,
    GumInvocationContext * invocation_context);
static void on_g_slice_free1_enter_handler (GumCObjectTracker * self,
    gpointer handler_context, CObjectThreadContext * thread_context,
    GumInvocationContext * invocation_context);

static void
gum_cobject_tracker_class_init (GumCObjectTrackerClass * klass)
{
  GObjectClass * gobject_class = G_OBJECT_CLASS (klass);
  GParamSpec * pspec;

  g_type_class_add_private (klass, sizeof (GumCObjectTrackerPrivate));

  gobject_class->set_property = gum_cobject_tracker_set_property;
  gobject_class->get_property = gum_cobject_tracker_get_property;
  gobject_class->dispose = gum_cobject_tracker_dispose;
  gobject_class->finalize = gum_cobject_tracker_finalize;

  pspec = g_param_spec_object ("backtracer", "Backtracer",
      "Backtracer Implementation", GUM_TYPE_BACKTRACER,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS |
      G_PARAM_CONSTRUCT_ONLY));
  g_object_class_install_property (gobject_class, PROP_BACKTRACER, pspec);
}

static void
gum_cobject_tracker_listener_iface_init (gpointer g_iface,
                                         gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = gum_cobject_tracker_on_enter;
  iface->on_leave = gum_cobject_tracker_on_leave;
  iface->provide_thread_data = gum_cobject_tracker_provide_thread_data;
}

static const CObjectHandlers free_cobject_handlers =
{
  on_free_enter_handler, NULL
};

static const CObjectHandlers g_slice_free1_cobject_handlers =
{
  on_g_slice_free1_enter_handler, NULL
};

static void
gum_cobject_tracker_init (GumCObjectTracker * self)
{
  GumCObjectTrackerPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_COBJECT_TRACKER, GumCObjectTrackerPrivate);

  priv = GUM_COBJECT_TRACKER_GET_PRIVATE (self);

  priv->mutex = g_mutex_new ();

  priv->types_ht = gum_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) object_type_free);

  priv->objects_ht = gum_hash_table_new_full (g_direct_hash, g_direct_equal,
      NULL, (GDestroyNotify) gum_cobject_free);

  priv->interceptor = gum_interceptor_obtain ();

  priv->function_contexts = g_ptr_array_new ();

  gum_cobject_tracker_attach_to_function (self,
      GUM_FUNCPTR_TO_POINTER (free),
      &free_cobject_handlers, NULL);
  gum_cobject_tracker_attach_to_function (self,
      GUM_FUNCPTR_TO_POINTER (g_slice_free1),
      &g_slice_free1_cobject_handlers, NULL);
}

static void
gum_cobject_tracker_set_property (GObject * object,
                                  guint property_id,
                                  const GValue * value,
                                  GParamSpec * pspec)
{
  GumCObjectTracker * self = GUM_COBJECT_TRACKER (object);
  GumCObjectTrackerPrivate * priv = GUM_COBJECT_TRACKER_GET_PRIVATE (self);

  switch (property_id)
  {
    case PROP_BACKTRACER:
      if (priv->backtracer_instance != NULL)
        g_object_unref (priv->backtracer_instance);
      priv->backtracer_instance = g_value_dup_object (value);

      if (priv->backtracer_instance != NULL)
      {
        priv->backtracer_interface =
            GUM_BACKTRACER_GET_INTERFACE (priv->backtracer_instance);
      }
      else
      {
        priv->backtracer_interface = NULL;
      }

      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_cobject_tracker_get_property (GObject * object,
                                  guint property_id,
                                  GValue * value,
                                  GParamSpec * pspec)
{
  GumCObjectTracker * self = GUM_COBJECT_TRACKER (object);
  GumCObjectTrackerPrivate * priv = GUM_COBJECT_TRACKER_GET_PRIVATE (self);

  switch (property_id)
  {
    case PROP_BACKTRACER:
      g_value_set_object (value, priv->backtracer_instance);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_cobject_tracker_dispose (GObject * object)
{
  GumCObjectTracker * self = GUM_COBJECT_TRACKER (object);
  GumCObjectTrackerPrivate * priv = GUM_COBJECT_TRACKER_GET_PRIVATE (self);

  if (!priv->disposed)
  {
    priv->disposed = TRUE;

    gum_interceptor_detach_listener (priv->interceptor,
        GUM_INVOCATION_LISTENER (self));
    g_object_unref (priv->interceptor);

    if (priv->backtracer_instance != NULL)
    {
      g_object_unref (priv->backtracer_instance);
      priv->backtracer_instance = NULL;
    }
    priv->backtracer_interface = NULL;

    gum_hash_table_unref (priv->objects_ht);
    priv->objects_ht = NULL;

    gum_hash_table_unref (priv->types_ht);
    priv->types_ht = NULL;
  }

  G_OBJECT_CLASS (gum_cobject_tracker_parent_class)->dispose (object);
}

static void
gum_cobject_tracker_finalize (GObject * object)
{
  GumCObjectTracker * self = GUM_COBJECT_TRACKER (object);
  GumCObjectTrackerPrivate * priv =
      GUM_COBJECT_TRACKER_GET_PRIVATE (self);

  g_ptr_array_foreach (priv->function_contexts, (GFunc) g_free, NULL);
  g_ptr_array_free (priv->function_contexts, TRUE);

  g_mutex_free (priv->mutex);

  G_OBJECT_CLASS (gum_cobject_tracker_parent_class)->finalize (object);
}

GumCObjectTracker *
gum_cobject_tracker_new (void)
{
  return GUM_COBJECT_TRACKER (g_object_new (GUM_TYPE_COBJECT_TRACKER, NULL));
}

GumCObjectTracker *
gum_cobject_tracker_new_with_backtracer (GumBacktracer * backtracer)
{
  return GUM_COBJECT_TRACKER (g_object_new (GUM_TYPE_COBJECT_TRACKER,
      "backtracer", backtracer, NULL));
}

static const CObjectHandlers object_type_cobject_handlers =
{
  (CObjectEnterHandler) on_constructor_enter_handler,
  (CObjectLeaveHandler) on_constructor_leave_handler
};

void
gum_cobject_tracker_track (GumCObjectTracker * self,
                           const gchar * type_name,
                           gpointer type_constructor)
{
  GumCObjectTrackerPrivate * priv = GUM_COBJECT_TRACKER_GET_PRIVATE (self);
  ObjectType * t;

  g_assert (strlen (type_name) <= GUM_MAX_TYPE_NAME);

  t = object_type_new (type_name);
  gum_hash_table_insert (priv->types_ht, g_strdup (type_name), t);

  gum_cobject_tracker_attach_to_function (self, type_constructor,
      &object_type_cobject_handlers, t);
}

void
gum_cobject_tracker_begin (GumCObjectTracker * self)
{
  (void) self;
}

void
gum_cobject_tracker_end (GumCObjectTracker * self)
{
  (void) self;
}

guint
gum_cobject_tracker_peek_total_count (GumCObjectTracker * self,
                                      const gchar * type_name)
{
  GumCObjectTrackerPrivate * priv = GUM_COBJECT_TRACKER_GET_PRIVATE (self);
  guint result;

  GUM_COBJECT_TRACKER_LOCK ();
  gum_interceptor_ignore_caller (priv->interceptor);

  if (type_name != NULL)
  {
    ObjectType * object_type;

    object_type = gum_hash_table_lookup (priv->types_ht, type_name);
    g_assert (object_type != NULL);

    result = object_type->count;
  }
  else
  {
    result = gum_hash_table_size (priv->objects_ht);
  }

  gum_interceptor_unignore_caller (priv->interceptor);
  GUM_COBJECT_TRACKER_UNLOCK ();

  return result;
}

GumList *
gum_cobject_tracker_peek_object_list (GumCObjectTracker * self)
{
  GumCObjectTrackerPrivate * priv = GUM_COBJECT_TRACKER_GET_PRIVATE (self);
  GumList * result = NULL, * walk;

  GUM_COBJECT_TRACKER_LOCK ();
  gum_interceptor_ignore_caller (priv->interceptor);

  result = gum_hash_table_get_values (priv->objects_ht);
  for (walk = result; walk != NULL; walk = walk->next)
  {
    GumCObject * cobject = walk->data;
    gum_return_address_array_load_symbols (&cobject->return_addresses);
    walk->data = gum_cobject_copy (cobject);
  }

  gum_interceptor_unignore_caller (priv->interceptor);
  GUM_COBJECT_TRACKER_UNLOCK ();

  return result;
}

static ObjectType *
object_type_new (const gchar * name)
{
  ObjectType * t;

  t = g_new0 (ObjectType, 1);
  t->name = g_strdup (name);

  return t;
}

static void
object_type_free (ObjectType * t)
{
  g_free (t->name);
  g_free (t);
}

static void
gum_cobject_tracker_add_object (GumCObjectTracker * self,
                                GumCObject * cobject)
{
  GumCObjectTrackerPrivate * priv = GUM_COBJECT_TRACKER_GET_PRIVATE (self);
  ObjectType * object_type = cobject->data;

  GUM_COBJECT_TRACKER_LOCK ();

  gum_hash_table_insert (priv->objects_ht, cobject->address, cobject);
  object_type->count++;

  GUM_COBJECT_TRACKER_UNLOCK ();
}

static void
gum_cobject_tracker_maybe_remove_object (GumCObjectTracker * self,
                                         gpointer address)
{
  GumCObjectTrackerPrivate * priv = GUM_COBJECT_TRACKER_GET_PRIVATE (self);
  GumCObject * cobject;

  GUM_COBJECT_TRACKER_LOCK ();

  cobject = gum_hash_table_lookup (priv->objects_ht, address);
  if (cobject != NULL)
  {
    ObjectType * object_type = cobject->data;
    object_type->count--;
    gum_hash_table_remove (priv->objects_ht, address);
  }

  GUM_COBJECT_TRACKER_UNLOCK ();
}

static void
gum_cobject_tracker_attach_to_function (GumCObjectTracker * self,
                                        gpointer function_address,
                                        const CObjectHandlers * handlers,
                                        gpointer context)
{
  GumCObjectTrackerPrivate * priv = GUM_COBJECT_TRACKER_GET_PRIVATE (self);
  CObjectFunctionContext * function_ctx;
  GumAttachReturn attach_ret;

  function_ctx = g_new (CObjectFunctionContext, 1);
  function_ctx->handlers = *handlers;
  function_ctx->context = context;
  function_ctx->thread_context_count = 0;
  g_ptr_array_add (priv->function_contexts, function_ctx);

  attach_ret = gum_interceptor_attach_listener (priv->interceptor,
      function_address, GUM_INVOCATION_LISTENER (self), function_ctx);
  g_assert_cmpint (attach_ret, ==, GUM_ATTACH_OK);
}

static void
gum_cobject_tracker_on_enter (GumInvocationListener * listener,
                              GumInvocationContext * context)
{
  GumCObjectTracker * self = GUM_COBJECT_TRACKER_CAST (listener);
  CObjectFunctionContext * function_ctx =
      (CObjectFunctionContext *) context->instance_data;

  if (function_ctx->handlers.enter_handler != NULL)
  {
    function_ctx->handlers.enter_handler (self, function_ctx->context,
        (CObjectThreadContext *) context->thread_data, context);
  }
}

static void
gum_cobject_tracker_on_leave (GumInvocationListener * listener,
                              GumInvocationContext * context)
{
  GumCObjectTracker * self = GUM_COBJECT_TRACKER_CAST (listener);
  CObjectFunctionContext * function_ctx =
      (CObjectFunctionContext *) context->instance_data;

  if (function_ctx->handlers.leave_handler != NULL)
  {
    function_ctx->handlers.leave_handler (self, function_ctx->context,
        (CObjectThreadContext *) context->thread_data, context);
  }
}

static gpointer
gum_cobject_tracker_provide_thread_data (GumInvocationListener * listener,
                                         gpointer function_instance_data,
                                         guint thread_id)
{
  CObjectFunctionContext * function_ctx =
      (CObjectFunctionContext *) function_instance_data;
  guint i;

  (void) listener;
  (void) thread_id;

  i = g_atomic_int_exchange_and_add (&function_ctx->thread_context_count, 1);
  g_assert (i < G_N_ELEMENTS (function_ctx->thread_contexts));

  return &function_ctx->thread_contexts[i];
}

static void
on_constructor_enter_handler (GumCObjectTracker * self,
                              ObjectType * object_type,
                              CObjectThreadContext * thread_context,
                              GumInvocationContext * invocation_context)
{
  GumCObjectTrackerPrivate * priv = GUM_COBJECT_TRACKER_GET_PRIVATE (self);
  GumCObject * cobject;

  cobject = gum_cobject_new (NULL, object_type->name);
  cobject->data = object_type;

  if (priv->backtracer_instance != NULL)
  {
    priv->backtracer_interface->generate (priv->backtracer_instance,
        invocation_context->cpu_context, &cobject->return_addresses);
  }

  thread_context->data = cobject;
}

static void
on_constructor_leave_handler (GumCObjectTracker * self,
                              ObjectType * object_type,
                              CObjectThreadContext * thread_context,
                              GumInvocationContext * invocation_context)
{
  GumCObject * cobject = (GumCObject *) thread_context->data;

  (void) object_type;

  cobject->address =
      gum_invocation_context_get_return_value (invocation_context);
  gum_cobject_tracker_add_object (self, cobject);
}

static void
on_free_enter_handler (GumCObjectTracker * self,
                       gpointer handler_context,
                       CObjectThreadContext * thread_context,
                       GumInvocationContext * invocation_context)
{
  gpointer address;

  (void) handler_context;
  (void) thread_context;

  address = gum_invocation_context_get_nth_argument (invocation_context, 0);

  gum_cobject_tracker_maybe_remove_object (self, address);
}

static void
on_g_slice_free1_enter_handler (GumCObjectTracker * self,
                                gpointer handler_context,
                                CObjectThreadContext * thread_context,
                                GumInvocationContext * invocation_context)
{
  gpointer mem_block;

  (void) handler_context;
  (void) thread_context;

  mem_block = gum_invocation_context_get_nth_argument (invocation_context, 1);

  gum_cobject_tracker_maybe_remove_object (self, mem_block);
}
