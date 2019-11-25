#ifndef __GUM_MODULE_MAP_H__
#define __GUM_MODULE_MAP_H__

#include "gumdefs.h"

typedef struct _GumModuleMap GumModuleMap;
typedef struct _GumModuleDetails GumModuleDetails;

typedef gboolean (* GumModuleMapFilterFunc) (const GumModuleDetails * details,
    gpointer user_data);

struct _GumModuleDetails
{
  const gchar * name;
  const GumMemoryRange * range;
  const gchar * path;
};

GumModuleMap * gum_module_map_new (void);
GumModuleMap * gum_module_map_new_filtered (GumModuleMapFilterFunc func,
    gpointer data, GDestroyNotify data_destroy);

const GumModuleDetails * gum_module_map_find (GumModuleMap * self,
    GumAddress address);

void gum_module_map_update (GumModuleMap * self);

GArray * gum_module_map_get_values (GumModuleMap * self);

#endif
