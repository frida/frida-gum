/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummapper.h"

G_DEFINE_INTERFACE (GumMapper, gum_mapper, G_TYPE_OBJECT)

static void
gum_mapper_default_init (GumMapperInterface * iface)
{
}

void
gum_mapper_set_target (GumMapper * self,
                       GumProcessMemory * target)
{
  GumMapperInterface * iface = GUM_MAPPER_GET_IFACE (self);

  if (iface->set_target != NULL)
    iface->set_target (self, target);
}

void
gum_mapper_add_apple_parameter (GumMapper * self,
                                const gchar * key,
                                const gchar * value)
{
  GumMapperInterface * iface = GUM_MAPPER_GET_IFACE (self);

  if (iface->add_apple_parameter != NULL)
    iface->add_apple_parameter (self, key, value);
}

gboolean
gum_mapper_map (GumMapper * self,
                gsize extra_size,
                GumAddress * extra_address,
                GError ** error)
{
  return GUM_MAPPER_GET_IFACE (self)->map (self, extra_size, extra_address,
      error);
}

void
gum_mapper_unmap (GumMapper * self)
{
  GUM_MAPPER_GET_IFACE (self)->unmap (self);
}

const GumMemoryRange *
gum_mapper_get_range (GumMapper * self)
{
  return GUM_MAPPER_GET_IFACE (self)->get_range (self);
}

GumAddress
gum_mapper_constructor (GumMapper * self)
{
  return GUM_MAPPER_GET_IFACE (self)->constructor (self);
}

GumAddress
gum_mapper_destructor (GumMapper * self)
{
  return GUM_MAPPER_GET_IFACE (self)->destructor (self);
}

GumAddress
gum_mapper_resolve (GumMapper * self,
                    const gchar * symbol)
{
  return GUM_MAPPER_GET_IFACE (self)->resolve (self, symbol);
}

void
gum_mapper_enumerate_exports (GumMapper * self,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  GUM_MAPPER_GET_IFACE (self)->enumerate_exports (self, func, user_data);
}
