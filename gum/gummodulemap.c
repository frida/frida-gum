/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gummodulemap.h"

#include <stdlib.h>

struct _GumModuleMap
{
  GObject parent;

  GArray * modules;

  GumModuleMapFilterFunc filter_func;
  gpointer filter_data;
  GDestroyNotify filter_data_destroy;
};

static void gum_module_map_dispose (GObject * object);
static void gum_module_map_finalize (GObject * object);

static void gum_module_map_clear (GumModuleMap * self);
static gboolean gum_add_module (const GumModuleDetails * details,
    gpointer user_data);

static gint gum_module_details_compare_base (
    const GumModuleDetails * lhs_module, const GumModuleDetails * rhs_module);
static gint gum_module_details_compare_to_key (const GumAddress * key_ptr,
    const GumModuleDetails * member);

G_DEFINE_TYPE (GumModuleMap, gum_module_map, G_TYPE_OBJECT)

static void
gum_module_map_class_init (GumModuleMapClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_module_map_dispose;
  object_class->finalize = gum_module_map_finalize;
}

static void
gum_module_map_init (GumModuleMap * self)
{
  self->modules = g_array_new (FALSE, FALSE, sizeof (GumModuleDetails));
}

static void
gum_module_map_dispose (GObject * object)
{
  GumModuleMap * self = GUM_MODULE_MAP (object);

  if (self->filter_data_destroy != NULL)
    self->filter_data_destroy (self->filter_data);

  self->filter_func = NULL;
  self->filter_data = NULL;
  self->filter_data_destroy = NULL;

  G_OBJECT_CLASS (gum_module_map_parent_class)->dispose (object);
}

static void
gum_module_map_finalize (GObject * object)
{
  GumModuleMap * self = GUM_MODULE_MAP (object);

  gum_module_map_clear (self);
  g_array_free (self->modules, TRUE);

  G_OBJECT_CLASS (gum_module_map_parent_class)->finalize (object);
}

GumModuleMap *
gum_module_map_new (void)
{
  GumModuleMap * map;

  map = g_object_new (GUM_TYPE_MODULE_MAP, NULL);

  gum_module_map_update (map);

  return map;
}

GumModuleMap *
gum_module_map_new_filtered (GumModuleMapFilterFunc func,
                             gpointer data,
                             GDestroyNotify data_destroy)
{
  GumModuleMap * map;

  map = g_object_new (GUM_TYPE_MODULE_MAP, NULL);
  map->filter_func = func;
  map->filter_data = data;
  map->filter_data_destroy = data_destroy;

  gum_module_map_update (map);

  return map;
}

const GumModuleDetails *
gum_module_map_find (GumModuleMap * self,
                     GumAddress address)
{
  return bsearch (&address, self->modules->data, self->modules->len,
      sizeof (GumModuleDetails),
      (GCompareFunc) gum_module_details_compare_to_key);
}

void
gum_module_map_update (GumModuleMap * self)
{
  gum_module_map_clear (self);
  gum_process_enumerate_modules (gum_add_module, self);
  g_array_sort (self->modules, (GCompareFunc) gum_module_details_compare_base);
}

GArray *
gum_module_map_get_values (GumModuleMap * self)
{
  return self->modules;
}

static void
gum_module_map_clear (GumModuleMap * self)
{
  guint i;

  for (i = 0; i < self->modules->len; i++)
  {
    GumModuleDetails * d = &g_array_index (self->modules, GumModuleDetails, i);
    g_free ((gchar *) d->name);
    g_slice_free (GumMemoryRange, (GumMemoryRange *) d->range);
    g_free ((gchar *) d->path);
  }
  g_array_set_size (self->modules, 0);
}

static gboolean
gum_add_module (const GumModuleDetails * details,
                gpointer user_data)
{
  GumModuleMap * self = user_data;
  GumModuleDetails copy;

  if (self->filter_func != NULL)
  {
    if (!self->filter_func (details, self->filter_data))
      return TRUE;
  }

  copy.name = g_strdup (details->name);
  copy.range = g_slice_dup (GumMemoryRange, details->range);
  copy.path = g_strdup (details->path);

  g_array_append_val (self->modules, copy);

  return TRUE;
}

static gint
gum_module_details_compare_base (const GumModuleDetails * lhs_module,
                                 const GumModuleDetails * rhs_module)
{
  GumAddress lhs = lhs_module->range->base_address;
  GumAddress rhs = rhs_module->range->base_address;

  if (lhs < rhs)
    return -1;

  if (lhs > rhs)
    return 1;

  return 0;
}

static gint
gum_module_details_compare_to_key (const GumAddress * key_ptr,
                                   const GumModuleDetails * member)
{
  GumAddress key = *key_ptr;
  const GumMemoryRange * m = member->range;

  if (key < m->base_address)
    return -1;

  if (key >= m->base_address + m->size)
    return 1;

  return 0;
}

#endif
