/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MAPPER_H__
#define __GUM_MAPPER_H__

#include <gum/gummoduleresolver.h>
#include <gum/gumprocessmemory.h>

G_BEGIN_DECLS

#define GUM_TYPE_MAPPER (gum_mapper_get_type ())
G_DECLARE_INTERFACE (GumMapper, gum_mapper, GUM, MAPPER, GObject)

typedef void (* GumMapperConstructor) (void);
typedef void (* GumMapperDestructor) (void);

struct _GumMapperInterface
{
  GTypeInterface parent;

  void (* set_target) (GumMapper * self, GumProcessMemory * target);
  void (* add_apple_parameter) (GumMapper * self, const gchar * key,
      const gchar * value);
  gboolean (* map) (GumMapper * self, gsize extra_size,
      GumAddress * extra_address, GError ** error);
  void (* unmap) (GumMapper * self);
  const GumMemoryRange * (* get_range) (GumMapper * self);
  GumAddress (* constructor) (GumMapper * self);
  GumAddress (* destructor) (GumMapper * self);
  GumAddress (* resolve) (GumMapper * self, const gchar * symbol);
  void (* enumerate_exports) (GumMapper * self, GumFoundExportFunc func,
      gpointer user_data);
};

GUM_API GumMapper * gum_mapper_new_from_file (const gchar * path,
    GumModuleResolver * resolver, GError ** error);
GUM_API GumMapper * gum_mapper_new_take_blob (const gchar * name,
    GBytes * blob, GumModuleResolver * resolver, GError ** error);

GUM_API void gum_mapper_set_target (GumMapper * self,
    GumProcessMemory * target);
GUM_API void gum_mapper_add_apple_parameter (GumMapper * self,
    const gchar * key, const gchar * value);

GUM_API gboolean gum_mapper_map (GumMapper * self, gsize extra_size,
    GumAddress * extra_address, GError ** error);
GUM_API void gum_mapper_unmap (GumMapper * self);
GUM_API const GumMemoryRange * gum_mapper_get_range (GumMapper * self);

GUM_API GumAddress gum_mapper_constructor (GumMapper * self);
GUM_API GumAddress gum_mapper_destructor (GumMapper * self);
GUM_API GumAddress gum_mapper_resolve (GumMapper * self, const gchar * symbol);
GUM_API void gum_mapper_enumerate_exports (GumMapper * self,
    GumFoundExportFunc func, gpointer user_data);

G_END_DECLS

#endif
