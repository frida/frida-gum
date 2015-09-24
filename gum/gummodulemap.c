/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummodulemap.h"

struct _GumModuleMapPrivate
{
  GArray * modules;
};

static void gum_module_map_finalize (GObject * object);

static void gum_module_map_clear (GumModuleMap * self);
static gboolean gum_add_module (const GumModuleDetails * details,
    gpointer user_data);

G_DEFINE_TYPE (GumModuleMap, gum_module_map, G_TYPE_OBJECT);

static void
gum_module_map_class_init (GumModuleMapClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GumModuleMapPrivate));

  object_class->finalize = gum_module_map_finalize;
}

static void
gum_module_map_init (GumModuleMap * self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, GUM_TYPE_MODULE_MAP,
      GumModuleMapPrivate);

  self->priv->modules = g_array_new (FALSE, FALSE, sizeof (GumModuleDetails));
}

static void
gum_module_map_finalize (GObject * object)
{
  GumModuleMap * self = GUM_MODULE_MAP (object);

  gum_module_map_clear (self);
  g_array_free (self->priv->modules, TRUE);

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

const GumModuleDetails *
gum_module_map_find (GumModuleMap * self,
                     GumAddress address)
{
  GumModuleMapPrivate * priv = self->priv;
  guint i;

  for (i = 0; i < priv->modules->len; i++)
  {
    GumModuleDetails * d = &g_array_index (priv->modules, GumModuleDetails, i);
    if (GUM_MEMORY_RANGE_INCLUDES (d->range, address))
      return d;
  }

  return NULL;
}

void
gum_module_map_update (GumModuleMap * self)
{
  gum_module_map_clear (self);
  gum_process_enumerate_modules (gum_add_module, self->priv);
}

static void
gum_module_map_clear (GumModuleMap * self)
{
  GumModuleMapPrivate * priv = self->priv;
  guint i;

  for (i = 0; i < priv->modules->len; i++)
  {
    GumModuleDetails * d = &g_array_index (priv->modules, GumModuleDetails, i);
    g_free ((gchar *) d->name);
    g_slice_free (GumMemoryRange, (GumMemoryRange *) d->range);
    g_free ((gchar *) d->path);
  }
  g_array_set_size (priv->modules, 0);
}

static gboolean
gum_add_module (const GumModuleDetails * details,
                gpointer user_data)
{
  GumModuleMapPrivate * priv = user_data;
  GumModuleDetails copy;

  copy.name = g_strdup (details->name);
  copy.range = g_slice_dup (GumMemoryRange, details->range);
  copy.path = g_strdup (details->path);

  g_array_append_val (priv->modules, copy);

  return TRUE;
}
