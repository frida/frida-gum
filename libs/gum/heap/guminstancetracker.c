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

#include "guminstancetracker.h"
#include "guminterceptor.h"
#include "gumhash.h"

static void gum_instance_tracker_listener_iface_init (gpointer g_iface,
    gpointer iface_data);

G_DEFINE_TYPE_EXTENDED (GumInstanceTracker,
                        gum_instance_tracker,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                                               gum_instance_tracker_listener_iface_init))

typedef enum _FunctionId FunctionId;

struct _GumInstanceTrackerPrivate
{
  gboolean disposed;

  GMutex * mutex;
  GumHashTable * counter_ht;
  GumHashTable * instances_ht;
  GumInterceptor * interceptor;

  gboolean is_active;
  GumInstanceVTable vtable;

  GumInstanceTrackerTypeFilterFunction type_filter_func;
  gpointer type_filter_func_user_data;
};

enum _FunctionId
{
  FUNCTION_ID_CREATE_INSTANCE,
  FUNCTION_ID_FREE_INSTANCE
};

#define GUM_INSTANCE_TRACKER_GET_PRIVATE(o) ((o)->priv)

#define GUM_INSTANCE_TRACKER_LOCK()   g_mutex_lock   (priv->mutex)
#define GUM_INSTANCE_TRACKER_UNLOCK() g_mutex_unlock (priv->mutex)

#define COUNTER_TABLE_GET(gtype) GPOINTER_TO_UINT (gum_hash_table_lookup (\
    priv->counter_ht, GUINT_TO_POINTER (gtype)))
#define COUNTER_TABLE_SET(gtype, count) gum_hash_table_insert (\
    priv->counter_ht, GUINT_TO_POINTER (gtype), GUINT_TO_POINTER (count))

static void gum_instance_tracker_dispose (GObject * object);
static void gum_instance_tracker_finalize (GObject * object);

static void gum_instance_tracker_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_instance_tracker_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);

static GPrivate * _gum_instance_tracker_tls = NULL;

static void
gum_instance_tracker_class_init (GumInstanceTrackerClass * klass)
{
  GObjectClass * gobject_class = G_OBJECT_CLASS (klass);

  _gum_instance_tracker_tls = g_private_new (g_free);

  g_type_class_add_private (klass, sizeof (GumInstanceTrackerPrivate));

  gobject_class->dispose = gum_instance_tracker_dispose;
  gobject_class->finalize = gum_instance_tracker_finalize;
}

static void
gum_instance_tracker_listener_iface_init (gpointer g_iface,
                                              gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  iface->on_enter = gum_instance_tracker_on_enter;
  iface->on_leave = gum_instance_tracker_on_leave;
}

static void
gum_instance_tracker_init (GumInstanceTracker * self)
{
  GumInstanceTrackerPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_INSTANCE_TRACKER, GumInstanceTrackerPrivate);

  priv = GUM_INSTANCE_TRACKER_GET_PRIVATE (self);

  priv->mutex = g_mutex_new ();

  priv->counter_ht = gum_hash_table_new_full (g_direct_hash,
      g_direct_equal, NULL, NULL);
  g_assert (priv->counter_ht != NULL);

  priv->instances_ht = gum_hash_table_new_full (g_direct_hash,
      g_direct_equal, NULL, NULL);

  priv->interceptor = gum_interceptor_obtain ();
}

static void
gum_instance_tracker_dispose (GObject * object)
{
  GumInstanceTracker * self = GUM_INSTANCE_TRACKER (object);
  GumInstanceTrackerPrivate * priv = GUM_INSTANCE_TRACKER_GET_PRIVATE (self);

  if (!priv->disposed)
  {
    priv->disposed = TRUE;

    if (priv->is_active)
      gum_instance_tracker_end (self);

    g_object_unref (priv->interceptor);

    gum_hash_table_unref (priv->counter_ht);
    priv->counter_ht = NULL;

    gum_hash_table_unref (priv->instances_ht);
    priv->instances_ht = NULL;
  }

  G_OBJECT_CLASS (gum_instance_tracker_parent_class)->dispose (object);
}

static void
gum_instance_tracker_finalize (GObject * object)
{
  GumInstanceTracker * self = GUM_INSTANCE_TRACKER (object);
  GumInstanceTrackerPrivate * priv =
      GUM_INSTANCE_TRACKER_GET_PRIVATE (self);

  g_mutex_free (priv->mutex);

  G_OBJECT_CLASS (gum_instance_tracker_parent_class)->finalize (object);
}

GumInstanceTracker *
gum_instance_tracker_new (void)
{
  return GUM_INSTANCE_TRACKER (g_object_new (GUM_TYPE_INSTANCE_TRACKER, NULL));
}

void
gum_instance_tracker_begin (GumInstanceTracker * self,
                            GumInstanceVTable * vtable)
{
  GumInstanceTrackerPrivate * priv = GUM_INSTANCE_TRACKER_GET_PRIVATE (self);
  GumAttachReturn attach_ret;

  g_assert (!priv->is_active);

  if (vtable != NULL)
  {
    priv->vtable = *vtable;
  }
  else
  {
    priv->vtable.create_instance = g_type_create_instance;
    priv->vtable.free_instance = g_type_free_instance;
    priv->vtable.type_id_to_name = g_type_name;
  }

  attach_ret = gum_interceptor_attach_listener (priv->interceptor,
      priv->vtable.create_instance, GUM_INVOCATION_LISTENER (self),
      GUINT_TO_POINTER (FUNCTION_ID_CREATE_INSTANCE));
  g_assert (attach_ret == GUM_ATTACH_OK);

  attach_ret = gum_interceptor_attach_listener (priv->interceptor,
      priv->vtable.free_instance, GUM_INVOCATION_LISTENER (self),
      GUINT_TO_POINTER (FUNCTION_ID_FREE_INSTANCE));
  g_assert (attach_ret == GUM_ATTACH_OK);

  priv->is_active = TRUE;
}

void
gum_instance_tracker_end (GumInstanceTracker * self)
{
  GumInstanceTrackerPrivate * priv = GUM_INSTANCE_TRACKER_GET_PRIVATE (self);

  g_assert (priv->is_active);

  gum_interceptor_detach_listener (priv->interceptor,
      GUM_INVOCATION_LISTENER (self));

  priv->is_active = FALSE;
}

void
gum_instance_tracker_set_type_filter_function (GumInstanceTracker * self,
                                               GumInstanceTrackerTypeFilterFunction filter,
                                               gpointer user_data)
{
  GumInstanceTrackerPrivate * priv = GUM_INSTANCE_TRACKER_GET_PRIVATE (self);

  priv->type_filter_func = filter;
  priv->type_filter_func_user_data = user_data;
}

guint
gum_instance_tracker_peek_total_count (GumInstanceTracker * self,
                                       const gchar * type_name)
{
  GumInstanceTrackerPrivate * priv = GUM_INSTANCE_TRACKER_GET_PRIVATE (self);
  guint result = 0;

  if (type_name != NULL)
  {
    GType gtype = g_type_from_name (type_name);

    if (gtype != 0)
    {
      GUM_INSTANCE_TRACKER_LOCK ();
      result = COUNTER_TABLE_GET (gtype);
      GUM_INSTANCE_TRACKER_UNLOCK ();
    }
  }
  else
  {
    GUM_INSTANCE_TRACKER_LOCK ();
    result = gum_hash_table_size (priv->instances_ht);
    GUM_INSTANCE_TRACKER_UNLOCK ();
  }

  return result;
}

GumList *
gum_instance_tracker_peek_instances (GumInstanceTracker * self)
{
  GumInstanceTrackerPrivate * priv = GUM_INSTANCE_TRACKER_GET_PRIVATE (self);
  GumList * result;

  GUM_INSTANCE_TRACKER_LOCK ();
  result = gum_hash_table_get_keys (priv->instances_ht);
  GUM_INSTANCE_TRACKER_UNLOCK ();

  return result;
}

void
gum_instance_tracker_walk_instances (GumInstanceTracker * self,
                                     GumWalkInstanceFunc func,
                                     gpointer user_data)
{
  GumInstanceTrackerPrivate * priv = GUM_INSTANCE_TRACKER_GET_PRIVATE (self);
  GumHashTableIter iter;
  gpointer key, value;
  GType gobject_type;

  gobject_type = G_TYPE_OBJECT;

  GUM_INSTANCE_TRACKER_LOCK ();

  gum_hash_table_iter_init (&iter, priv->instances_ht);
  while (gum_hash_table_iter_next (&iter, &key, &value))
  {
    const GTypeInstance * instance = (const GTypeInstance *) key;
    GType type;
    GumInstanceDetails details;

    type = G_TYPE_FROM_INSTANCE (instance);

    details.address = instance;
    if (g_type_is_a (type, gobject_type))
      details.ref_count = ((const GObject *) instance)->ref_count;
    else
      details.ref_count = 1;
    details.type_name = priv->vtable.type_id_to_name (type);

    func (&details, user_data);
  }

  GUM_INSTANCE_TRACKER_UNLOCK ();
}

void
gum_instance_tracker_add_instance (GumInstanceTracker * self,
                                   gpointer instance,
                                   GType instance_type)
{
  GumInstanceTrackerPrivate * priv = GUM_INSTANCE_TRACKER_GET_PRIVATE (self);
  guint count;

  if (instance_type == G_TYPE_FROM_INSTANCE (self))
    return;

  if (priv->type_filter_func != NULL)
  {
    if (!priv->type_filter_func (self, instance_type,
        priv->type_filter_func_user_data))
    {
      return;
    }
  }

  GUM_INSTANCE_TRACKER_LOCK ();

  g_assert (gum_hash_table_lookup (priv->instances_ht, instance) == NULL);
  gum_hash_table_insert (priv->instances_ht, instance, instance);

  count = COUNTER_TABLE_GET (instance_type);
  COUNTER_TABLE_SET (instance_type, count + 1);

  GUM_INSTANCE_TRACKER_UNLOCK ();
}

void
gum_instance_tracker_remove_instance (GumInstanceTracker * self,
                                      gpointer instance,
                                      GType instance_type)
{
  GumInstanceTrackerPrivate * priv = GUM_INSTANCE_TRACKER_GET_PRIVATE (self);
  guint count;

  GUM_INSTANCE_TRACKER_LOCK ();

  if (gum_hash_table_remove (priv->instances_ht, instance))
  {
    count = COUNTER_TABLE_GET (instance_type);
    if (count > 0)
      COUNTER_TABLE_SET (instance_type, count - 1);
  }

  GUM_INSTANCE_TRACKER_UNLOCK ();
}

static void
gum_instance_tracker_on_enter (GumInvocationListener * listener,
                               GumInvocationContext * context)
{
  GumInstanceTracker * self = GUM_INSTANCE_TRACKER_CAST (listener);
  FunctionId function_id =
      (FunctionId) GPOINTER_TO_INT (context->instance_data);

  if (function_id == FUNCTION_ID_FREE_INSTANCE)
  {
    GTypeInstance * instance;
    GType gtype;

    instance = (GTypeInstance *)
        gum_invocation_context_get_nth_argument (context, 0);
    gtype = G_TYPE_FROM_INSTANCE (instance);

    gum_instance_tracker_remove_instance (self, instance, gtype);
  }
}

static void
gum_instance_tracker_on_leave (GumInvocationListener * listener,
                               GumInvocationContext * context)
{
  GumInstanceTracker * self = GUM_INSTANCE_TRACKER_CAST (listener);
  FunctionId function_id =
      (FunctionId) GPOINTER_TO_INT (context->instance_data);

  if (function_id == FUNCTION_ID_CREATE_INSTANCE)
  {
    GTypeInstance * instance;
    GType gtype;

    instance = (GTypeInstance *)
        gum_invocation_context_get_return_value (context);
    gtype = G_TYPE_FROM_INSTANCE (instance);

    gum_instance_tracker_add_instance (self, instance, gtype);
  }
}
