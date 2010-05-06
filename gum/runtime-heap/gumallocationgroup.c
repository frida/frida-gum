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
gum_allocation_group_list_free (GumList * groups)
{
  GumList * cur;

  for (cur = groups; cur != NULL; cur = cur->next)
    gum_allocation_group_free (cur->data);

  gum_list_free (groups);
}
