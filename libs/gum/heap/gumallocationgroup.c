/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumallocationgroup.h"
#include "gummemory.h"

GumAllocationGroup *
gum_allocation_group_new (guint size)
{
  GumAllocationGroup * group;

  group = gum_malloc0 (sizeof (GumAllocationGroup));
  group->size = size;

  return group;
}

GumAllocationGroup *
gum_allocation_group_copy (const GumAllocationGroup * group)
{
  return gum_memdup (group, sizeof (GumAllocationGroup));
}

void
gum_allocation_group_free (GumAllocationGroup * group)
{
  gum_free (group);
}

void
gum_allocation_group_list_free (GList * groups)
{
  GList * cur;

  for (cur = groups; cur != NULL; cur = cur->next)
    gum_allocation_group_free (cur->data);

  g_list_free (groups);
}
