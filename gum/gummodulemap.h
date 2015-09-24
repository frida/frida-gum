/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_MODULE_MAP_H__
#define __GUM_MODULE_MAP_H__

#include <glib-object.h>
#include <gum/gumprocess.h>

#define GUM_TYPE_MODULE_MAP (gum_module_map_get_type ())
#define GUM_MODULE_MAP(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_MODULE_MAP, GumModuleMap))
#define GUM_MODULE_MAP_CAST(obj) ((GumModuleMap *) (obj))
#define GUM_MODULE_MAP_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_MODULE_MAP, GumModuleMapClass))
#define GUM_IS_MODULE_MAP(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_MODULE_MAP))
#define GUM_IS_MODULE_MAP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_MODULE_MAP))
#define GUM_MODULE_MAP_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_MODULE_MAP, GumModuleMapClass))

typedef struct _GumModuleMap GumModuleMap;
typedef struct _GumModuleMapClass GumModuleMapClass;

typedef struct _GumModuleMapPrivate GumModuleMapPrivate;

struct _GumModuleMap
{
  GObject parent;

  GumModuleMapPrivate * priv;
};

struct _GumModuleMapClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_module_map_get_type (void) G_GNUC_CONST;

GUM_API GumModuleMap * gum_module_map_new (void);

GUM_API const GumModuleDetails * gum_module_map_find (GumModuleMap * self,
    GumAddress address);

GUM_API void gum_module_map_update (GumModuleMap * self);

G_END_DECLS

#endif
