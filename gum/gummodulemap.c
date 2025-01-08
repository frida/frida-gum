/*
 * Copyright (C) 2015-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummodulemap.h"

#include <stdlib.h>

struct _GumModuleMap
{
  GObject parent;

  GPtrArray * modules;

  GumModuleMapFilterFunc filter_func;
  gpointer filter_data;
  GDestroyNotify filter_data_destroy;
};

static void gum_module_map_dispose (GObject * object);

static gboolean gum_add_module (GumModule * module, gpointer user_data);
static gint gum_module_compare_base (GumModule ** lhs_module,
    GumModule ** rhs_module);
static gint gum_module_compare_to_key (const GumAddress * key_ptr,
    GumModule ** member);

G_DEFINE_TYPE (GumModuleMap, gum_module_map, G_TYPE_OBJECT)

static void
gum_module_map_class_init (GumModuleMapClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_module_map_dispose;
}

static void
gum_module_map_init (GumModuleMap * self)
{
  self->modules = g_ptr_array_new_full (0, g_object_unref);
}

static void
gum_module_map_dispose (GObject * object)
{
  GumModuleMap * self = GUM_MODULE_MAP (object);

  g_clear_pointer (&self->modules, g_ptr_array_unref);

  if (self->filter_data_destroy != NULL)
    self->filter_data_destroy (self->filter_data);

  self->filter_func = NULL;
  self->filter_data = NULL;
  self->filter_data_destroy = NULL;

  G_OBJECT_CLASS (gum_module_map_parent_class)->dispose (object);
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

GumModule *
gum_module_map_find (GumModuleMap * self,
                     GumAddress address)
{
  GumModule ** entry;
  GumAddress bare_address;

  bare_address = gum_strip_code_address (address);

  entry = bsearch (&bare_address, self->modules->pdata, self->modules->len,
      sizeof (GumModule *), (GCompareFunc) gum_module_compare_to_key);
  if (entry == NULL)
    return NULL;

  return *entry;
}

void
gum_module_map_update (GumModuleMap * self)
{
  g_ptr_array_set_size (self->modules, 0);
  gum_process_enumerate_modules (gum_add_module, self);
  g_ptr_array_sort (self->modules, (GCompareFunc) gum_module_compare_base);
}

GPtrArray *
gum_module_map_get_values (GumModuleMap * self)
{
  return self->modules;
}

static gboolean
gum_add_module (GumModule * module,
                gpointer user_data)
{
  GumModuleMap * self = user_data;

  if (self->filter_func != NULL)
  {
    if (!self->filter_func (module, self->filter_data))
      return TRUE;
  }

  g_ptr_array_add (self->modules, g_object_ref (module));

  return TRUE;
}

static gint
gum_module_compare_base (GumModule ** lhs_module,
                         GumModule ** rhs_module)
{
  GumAddress lhs;
  GumAddress rhs;

  lhs = gum_module_get_range (*lhs_module)->base_address;
  rhs = gum_module_get_range (*rhs_module)->base_address;

  if (lhs < rhs)
    return -1;

  if (lhs > rhs)
    return 1;

  return 0;
}

static gint
gum_module_compare_to_key (const GumAddress * key_ptr,
                           GumModule ** member)
{
  GumAddress key = *key_ptr;
  const GumMemoryRange * r;

  r = gum_module_get_range (*member);

  if (key < r->base_address)
    return -1;

  if (key >= r->base_address + r->size)
    return 1;

  return 0;
}
