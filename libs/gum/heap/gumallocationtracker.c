/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#include "gumallocationtracker.h"

#include <string.h>
#include "gumallocationblock.h"
#include "gumallocationgroup.h"
#include "gumreturnaddress.h"
#include "gumbacktracer.h"
#include "gumhash.h"

G_DEFINE_TYPE (GumAllocationTracker, gum_allocation_tracker, G_TYPE_OBJECT);

enum
{
  PROP_0,
  PROP_BACKTRACER,
};

struct _GumAllocationTrackerPrivate
{
  gboolean disposed;

  GMutex * mutex;

  volatile gint enabled;

  GumAllocationTrackerFilterFunction filter_func;
  gpointer filter_func_user_data;

  guint block_count;
  guint block_total_size;
  GumHashTable * known_blocks_ht;
  GumHashTable * block_groups_ht;

  GumBacktracerIface * backtracer_interface;
  GumBacktracer * backtracer_instance;
};

#define GUM_ALLOCATION_TRACKER_GET_PRIVATE(o) ((o)->priv)

#define GUM_ALLOCATION_TRACKER_LOCK(priv) g_mutex_lock (priv->mutex)
#define GUM_ALLOCATION_TRACKER_UNLOCK(priv) g_mutex_unlock (priv->mutex)

static void gum_allocation_tracker_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);
static void gum_allocation_tracker_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_allocation_tracker_dispose (GObject * object);
static void gum_allocation_tracker_finalize (GObject * object);

static void gum_allocation_tracker_size_stats_add_block (
    GumAllocationTracker * self, guint size);
static void gum_allocation_tracker_size_stats_remove_block (
    GumAllocationTracker * self, guint size);

static void
gum_allocation_tracker_class_init (GumAllocationTrackerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);
  GParamSpec * pspec;

  g_type_class_add_private (klass, sizeof (GumAllocationTrackerPrivate));

  object_class->set_property = gum_allocation_tracker_set_property;
  object_class->get_property = gum_allocation_tracker_get_property;
  object_class->dispose = gum_allocation_tracker_dispose;
  object_class->finalize = gum_allocation_tracker_finalize;

  pspec = g_param_spec_object ("backtracer", "Backtracer",
      "Backtracer Implementation", GUM_TYPE_BACKTRACER,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | G_PARAM_CONSTRUCT_ONLY);
  g_object_class_install_property (object_class, PROP_BACKTRACER, pspec);
}

static void
gum_allocation_tracker_init (GumAllocationTracker * self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_ALLOCATION_TRACKER,
      GumAllocationTrackerPrivate);

  self->priv->mutex = g_mutex_new ();
  self->priv->known_blocks_ht = gum_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_allocation_block_free);
  self->priv->block_groups_ht = gum_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_allocation_group_free);
}

static void
gum_allocation_tracker_set_property (GObject * object,
                                     guint property_id,
                                     const GValue * value,
                                     GParamSpec * pspec)
{
  GumAllocationTracker * self = GUM_ALLOCATION_TRACKER (object);
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);

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
gum_allocation_tracker_get_property (GObject * object,
                                     guint property_id,
                                     GValue * value,
                                     GParamSpec * pspec)
{
  GumAllocationTracker * self = GUM_ALLOCATION_TRACKER (object);
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);

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
gum_allocation_tracker_dispose (GObject * object)
{
  GumAllocationTracker * self = GUM_ALLOCATION_TRACKER (object);
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);

  if (!priv->disposed)
  {
    priv->disposed = TRUE;

    if (priv->backtracer_instance != NULL)
    {
      g_object_unref (priv->backtracer_instance);
      priv->backtracer_instance = NULL;
    }
    priv->backtracer_interface = NULL;

    gum_hash_table_unref (priv->known_blocks_ht);
    priv->known_blocks_ht = NULL;

    gum_hash_table_unref (priv->block_groups_ht);
    priv->block_groups_ht = NULL;
  }

  G_OBJECT_CLASS (gum_allocation_tracker_parent_class)->dispose (object);
}

static void
gum_allocation_tracker_finalize (GObject * object)
{
  GumAllocationTracker * self = GUM_ALLOCATION_TRACKER (object);
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);

  g_mutex_free (priv->mutex);
  priv->mutex = NULL;

  G_OBJECT_CLASS (gum_allocation_tracker_parent_class)->finalize (object);
}

GumAllocationTracker *
gum_allocation_tracker_new (void)
{
  return gum_allocation_tracker_new_with_backtracer (NULL);
}

GumAllocationTracker *
gum_allocation_tracker_new_with_backtracer (GumBacktracer * backtracer)
{
  return g_object_new (GUM_TYPE_ALLOCATION_TRACKER,
      "backtracer", backtracer,
      NULL);
}

void
gum_allocation_tracker_set_filter_function (GumAllocationTracker * self,
                                            GumAllocationTrackerFilterFunction filter,
                                            gpointer user_data)
{
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);

  g_assert (g_atomic_int_get (&priv->enabled) == FALSE);

  priv->filter_func = filter;
  priv->filter_func_user_data = user_data;
}

void
gum_allocation_tracker_begin (GumAllocationTracker * self)
{
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);

  GUM_ALLOCATION_TRACKER_LOCK (priv);
  priv->block_count = 0;
  priv->block_total_size = 0;
  gum_hash_table_remove_all (priv->known_blocks_ht);
  GUM_ALLOCATION_TRACKER_UNLOCK (priv);

  g_atomic_int_set (&priv->enabled, TRUE);
}

void
gum_allocation_tracker_end (GumAllocationTracker * self)
{
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);

  g_atomic_int_set (&priv->enabled, FALSE);

  GUM_ALLOCATION_TRACKER_LOCK (priv);
  priv->block_count = 0;
  priv->block_total_size = 0;
  gum_hash_table_remove_all (priv->known_blocks_ht);
  gum_hash_table_remove_all (priv->block_groups_ht);
  GUM_ALLOCATION_TRACKER_UNLOCK (priv);
}

guint
gum_allocation_tracker_peek_block_count (GumAllocationTracker * self)
{
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);

  return priv->block_count;
}

guint
gum_allocation_tracker_peek_block_total_size (GumAllocationTracker * self)
{
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);

  return priv->block_total_size;
}

GumList *
gum_allocation_tracker_peek_block_list (GumAllocationTracker * self)
{
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);
  GumList * blocks, * cur;

  GUM_ALLOCATION_TRACKER_LOCK (priv);
  blocks = gum_hash_table_get_values (priv->known_blocks_ht);
  for (cur = blocks; cur != NULL; cur = cur->next)
  {
    GumAllocationBlock * block = (GumAllocationBlock *) cur->data;
    gum_return_address_array_load_symbols (&block->return_addresses);
    cur->data = gum_allocation_block_copy (block);
  }
  GUM_ALLOCATION_TRACKER_UNLOCK (priv);

  return blocks;
}

GumList *
gum_allocation_tracker_peek_block_groups (GumAllocationTracker * self)
{
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);
  GumList * groups, * cur;

  GUM_ALLOCATION_TRACKER_LOCK (priv);
  groups = gum_hash_table_get_values (priv->block_groups_ht);
  for (cur = groups; cur != NULL; cur = cur->next)
    cur->data = gum_allocation_group_copy (cur->data);
  GUM_ALLOCATION_TRACKER_UNLOCK (priv);

  return groups;
}

void
gum_allocation_tracker_on_malloc (GumAllocationTracker * self,
                                  gpointer address,
                                  guint size)
{
  gum_allocation_tracker_on_malloc_full (self, address, size, NULL);
}

void
gum_allocation_tracker_on_free (GumAllocationTracker * self,
                                gpointer address)
{
  gum_allocation_tracker_on_free_full (self, address, NULL);
}

void
gum_allocation_tracker_on_realloc (GumAllocationTracker * self,
                                   gpointer old_address,
                                   gpointer new_address,
                                   guint new_size)
{
  gum_allocation_tracker_on_realloc_full (self, old_address, new_address,
      new_size, NULL);
}

void
gum_allocation_tracker_on_malloc_full (GumAllocationTracker * self,
                                       gpointer address,
                                       guint size,
                                       const GumCpuContext * cpu_context)
{
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);
  GumAllocationBlock * block;

  if (!g_atomic_int_get (&priv->enabled))
    return;

  if (priv->filter_func != NULL)
  {
    if (!priv->filter_func (self, address, size, priv->filter_func_user_data))
      return;
  }

  block = gum_allocation_block_new (address, size);

  if (priv->backtracer_instance != NULL)
    priv->backtracer_interface->generate (priv->backtracer_instance,
        cpu_context, &block->return_addresses);

  GUM_ALLOCATION_TRACKER_LOCK (priv);

  gum_hash_table_insert (priv->known_blocks_ht, address, block);

  gum_allocation_tracker_size_stats_add_block (self, size);

  GUM_ALLOCATION_TRACKER_UNLOCK (priv);
}

void
gum_allocation_tracker_on_free_full (GumAllocationTracker * self,
                                     gpointer address,
                                     const GumCpuContext * cpu_context)
{
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);
  GumAllocationBlock * block;

  (void) cpu_context;

  if (!g_atomic_int_get (&priv->enabled))
    return;

  GUM_ALLOCATION_TRACKER_LOCK (priv);

  block = gum_hash_table_lookup (priv->known_blocks_ht, address);
  if (block != NULL)
  {
    gum_allocation_tracker_size_stats_remove_block (self, block->size);

    gum_hash_table_remove (priv->known_blocks_ht, address);
  }

  GUM_ALLOCATION_TRACKER_UNLOCK (priv);
}

void
gum_allocation_tracker_on_realloc_full (GumAllocationTracker * self,
                                        gpointer old_address,
                                        gpointer new_address,
                                        guint new_size,
                                        const GumCpuContext * cpu_context)
{
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);
  GumAllocationBlock * block;

  if (!g_atomic_int_get (&priv->enabled))
    return;

  if (priv->filter_func != NULL)
  {
    if (!priv->filter_func (self, new_address, new_size,
        priv->filter_func_user_data))
      return;
  }

  if (old_address != NULL)
  {
    if (new_size != 0)
    {
      GUM_ALLOCATION_TRACKER_LOCK (priv);

      block = gum_hash_table_lookup (priv->known_blocks_ht, old_address);
      if (block != NULL)
      {
        gum_hash_table_steal (priv->known_blocks_ht, old_address);
        gum_hash_table_insert (priv->known_blocks_ht, new_address, block);

        gum_allocation_tracker_size_stats_remove_block (self, block->size);
        block->size = new_size;
        gum_allocation_tracker_size_stats_add_block (self, new_size);
      }

      GUM_ALLOCATION_TRACKER_UNLOCK (priv);
    }
    else
    {
      gum_allocation_tracker_on_free_full (self, old_address, cpu_context);
    }
  }
  else
  {
    gum_allocation_tracker_on_malloc_full (self, new_address, new_size,
        cpu_context);
  }
}

static void
gum_allocation_tracker_size_stats_add_block (GumAllocationTracker * self,
                                             guint size)
{
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);
  GumAllocationGroup * group;

  priv->block_count++;
  priv->block_total_size += size;

  group = gum_hash_table_lookup (priv->block_groups_ht, GUINT_TO_POINTER (size));

  if (group == NULL)
  {
    group = gum_allocation_group_new (size);
    gum_hash_table_insert (priv->block_groups_ht, GUINT_TO_POINTER (size),
        group);
  }

  group->alive_now++;
  if (group->alive_now > group->alive_peak)
    group->alive_peak = group->alive_now;
  group->total_peak++;
}

static void
gum_allocation_tracker_size_stats_remove_block (GumAllocationTracker * self,
                                                guint size)
{
  GumAllocationTrackerPrivate * priv =
      GUM_ALLOCATION_TRACKER_GET_PRIVATE (self);
  GumAllocationGroup * group;

  priv->block_count--;
  priv->block_total_size -= size;

  group = gum_hash_table_lookup (priv->block_groups_ht,
      GUINT_TO_POINTER (size));
  group->alive_now--;
}
