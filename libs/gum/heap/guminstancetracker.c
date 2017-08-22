/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminstancetracker.h"

#include "guminterceptor.h"
#include "gumprocess.h"

#include <gmodule.h>

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

  GMutex mutex;
  GHashTable * counter_ht;
  GHashTable * instances_ht;
  GumInterceptor * interceptor;

  gboolean is_active;
  GumInstanceVTable vtable;

  GumFilterInstanceTypeFunc type_filter_func;
  gpointer type_filter_func_user_data;
};

enum _FunctionId
{
  FUNCTION_ID_CREATE_INSTANCE,
  FUNCTION_ID_FREE_INSTANCE
};

#define GUM_INSTANCE_TRACKER_LOCK()   g_mutex_lock   (&priv->mutex)
#define GUM_INSTANCE_TRACKER_UNLOCK() g_mutex_unlock (&priv->mutex)

#define COUNTER_TABLE_GET(gtype) GPOINTER_TO_UINT (g_hash_table_lookup (\
    priv->counter_ht, GUINT_TO_POINTER (gtype)))
#define COUNTER_TABLE_SET(gtype, count) g_hash_table_insert (\
    priv->counter_ht, GUINT_TO_POINTER (gtype), GUINT_TO_POINTER (count))

static void gum_instance_tracker_dispose (GObject * object);
static void gum_instance_tracker_finalize (GObject * object);

static void gum_instance_tracker_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_instance_tracker_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);

static void
gum_instance_tracker_class_init (GumInstanceTrackerClass * klass)
{
  GObjectClass * gobject_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumInstanceTrackerPrivate));

  gobject_class->dispose = gum_instance_tracker_dispose;
  gobject_class->finalize = gum_instance_tracker_finalize;
}

static void
gum_instance_tracker_listener_iface_init (gpointer g_iface,
                                          gpointer iface_data)
{
  GumInvocationListenerIface * iface = (GumInvocationListenerIface *) g_iface;

  (void) iface_data;

  iface->on_enter = gum_instance_tracker_on_enter;
  iface->on_leave = gum_instance_tracker_on_leave;
}

static void
gum_instance_tracker_init (GumInstanceTracker * self)
{
  GumInstanceTrackerPrivate * priv;

  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
      GUM_TYPE_INSTANCE_TRACKER, GumInstanceTrackerPrivate);

  priv = self->priv;

  g_mutex_init (&priv->mutex);

  priv->counter_ht = g_hash_table_new_full (g_direct_hash, g_direct_equal,
      NULL, NULL);
  g_assert (priv->counter_ht != NULL);

  priv->instances_ht = g_hash_table_new_full (g_direct_hash, g_direct_equal,
      NULL, NULL);

  priv->interceptor = gum_interceptor_obtain ();
}

static void
gum_instance_tracker_dispose (GObject * object)
{
  GumInstanceTracker * self = GUM_INSTANCE_TRACKER (object);
  GumInstanceTrackerPrivate * priv = self->priv;

  if (!priv->disposed)
  {
    priv->disposed = TRUE;

    if (priv->is_active)
      gum_instance_tracker_end (self);

    g_object_unref (priv->interceptor);

    g_hash_table_unref (priv->counter_ht);
    priv->counter_ht = NULL;

    g_hash_table_unref (priv->instances_ht);
    priv->instances_ht = NULL;
  }

  G_OBJECT_CLASS (gum_instance_tracker_parent_class)->dispose (object);
}

static void
gum_instance_tracker_finalize (GObject * object)
{
  GumInstanceTracker * self = GUM_INSTANCE_TRACKER (object);
  GumInstanceTrackerPrivate * priv =
      self->priv;

  g_mutex_clear (&priv->mutex);

  G_OBJECT_CLASS (gum_instance_tracker_parent_class)->finalize (object);
}

GumInstanceTracker *
gum_instance_tracker_new (void)
{
  return GUM_INSTANCE_TRACKER (g_object_new (GUM_TYPE_INSTANCE_TRACKER, NULL));
}

static gboolean
gum_instance_tracker_fill_vtable_if_module_is_gobject (
    const GumModuleDetails * details,
    gpointer user_data)
{
  GumInstanceTracker * self = GUM_INSTANCE_TRACKER_CAST (user_data);
  GumInstanceVTable * vtable = &self->priv->vtable;
  gchar * name_lowercase;

  name_lowercase = g_ascii_strdown (details->name, -1);

  if (g_strstr_len (name_lowercase, -1, "gobject-2.0") != NULL)
  {
    GModule * module;
    gboolean found;

    module = g_module_open (details->path, (GModuleFlags) 0);

    found = g_module_symbol (module, "g_type_create_instance",
        (gpointer *) &vtable->create_instance);
    g_assert (found);

    found = g_module_symbol (module, "g_type_free_instance",
        (gpointer *) &vtable->free_instance);
    g_assert (found);

    found = g_module_symbol (module, "g_type_name",
        (gpointer *) &vtable->type_id_to_name);
    g_assert (found);

    g_module_close (module);
  }

  g_free (name_lowercase);

  return TRUE;
}

void
gum_instance_tracker_begin (GumInstanceTracker * self,
                            GumInstanceVTable * vtable)
{
  GumInstanceTrackerPrivate * priv = self->priv;
  GumAttachReturn attach_ret;

  g_assert (!priv->is_active);

  if (vtable != NULL)
  {
    priv->vtable = *vtable;
  }
  else
  {
    gum_process_enumerate_modules (
        gum_instance_tracker_fill_vtable_if_module_is_gobject, self);

    if (priv->vtable.create_instance == NULL)
    {
      priv->vtable.create_instance = g_type_create_instance;
      priv->vtable.free_instance = g_type_free_instance;
      priv->vtable.type_id_to_name = g_type_name;
    }
  }

  gum_interceptor_begin_transaction (priv->interceptor);

  attach_ret = gum_interceptor_attach_listener (priv->interceptor,
      GUM_FUNCPTR_TO_POINTER (priv->vtable.create_instance),
      GUM_INVOCATION_LISTENER (self),
      GUINT_TO_POINTER (FUNCTION_ID_CREATE_INSTANCE));
  g_assert (attach_ret == GUM_ATTACH_OK);

  attach_ret = gum_interceptor_attach_listener (priv->interceptor,
      GUM_FUNCPTR_TO_POINTER (priv->vtable.free_instance),
      GUM_INVOCATION_LISTENER (self),
      GUINT_TO_POINTER (FUNCTION_ID_FREE_INSTANCE));
  g_assert (attach_ret == GUM_ATTACH_OK);

  gum_interceptor_end_transaction (priv->interceptor);

  priv->is_active = TRUE;
}

void
gum_instance_tracker_end (GumInstanceTracker * self)
{
  GumInstanceTrackerPrivate * priv = self->priv;

  g_assert (priv->is_active);

  gum_interceptor_detach_listener (priv->interceptor,
      GUM_INVOCATION_LISTENER (self));

  priv->is_active = FALSE;
}

const GumInstanceVTable *
gum_instance_tracker_get_current_vtable (GumInstanceTracker * self)
{
  return &self->priv->vtable;
}

void
gum_instance_tracker_set_type_filter_function (GumInstanceTracker * self,
                                               GumFilterInstanceTypeFunc filter,
                                               gpointer user_data)
{
  GumInstanceTrackerPrivate * priv = self->priv;

  priv->type_filter_func = filter;
  priv->type_filter_func_user_data = user_data;
}

guint
gum_instance_tracker_peek_total_count (GumInstanceTracker * self,
                                       const gchar * type_name)
{
  GumInstanceTrackerPrivate * priv = self->priv;
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
    result = g_hash_table_size (priv->instances_ht);
    GUM_INSTANCE_TRACKER_UNLOCK ();
  }

  return result;
}

GList *
gum_instance_tracker_peek_instances (GumInstanceTracker * self)
{
  GumInstanceTrackerPrivate * priv = self->priv;
  GList * result;

  GUM_INSTANCE_TRACKER_LOCK ();
  result = g_hash_table_get_keys (priv->instances_ht);
  GUM_INSTANCE_TRACKER_UNLOCK ();

  return result;
}

void
gum_instance_tracker_walk_instances (GumInstanceTracker * self,
                                     GumWalkInstanceFunc func,
                                     gpointer user_data)
{
  GumInstanceTrackerPrivate * priv = self->priv;
  GHashTableIter iter;
  gpointer key, value;
  GType gobject_type;

  gobject_type = G_TYPE_OBJECT;

  GUM_INSTANCE_TRACKER_LOCK ();

  g_hash_table_iter_init (&iter, priv->instances_ht);
  while (g_hash_table_iter_next (&iter, &key, &value))
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
  GumInstanceTrackerPrivate * priv = self->priv;
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

  g_assert (g_hash_table_lookup (priv->instances_ht, instance) == NULL);
  g_hash_table_add (priv->instances_ht, instance);

  count = COUNTER_TABLE_GET (instance_type);
  COUNTER_TABLE_SET (instance_type, count + 1);

  GUM_INSTANCE_TRACKER_UNLOCK ();
}

void
gum_instance_tracker_remove_instance (GumInstanceTracker * self,
                                      gpointer instance,
                                      GType instance_type)
{
  GumInstanceTrackerPrivate * priv = self->priv;
  guint count;

  GUM_INSTANCE_TRACKER_LOCK ();

  if (g_hash_table_remove (priv->instances_ht, instance))
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
  FunctionId function_id;

  function_id = (FunctionId) GPOINTER_TO_INT (
      gum_invocation_context_get_listener_function_data (context));

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
  FunctionId function_id;

  function_id = (FunctionId) GPOINTER_TO_INT (
      gum_invocation_context_get_listener_function_data (context));

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
