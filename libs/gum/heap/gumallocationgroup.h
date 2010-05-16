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

#ifndef __GUM_ALLOCATION_GROUP_H__
#define __GUM_ALLOCATION_GROUP_H__

#include <gum/gumdefs.h>
#include <gum/gumlist.h>

typedef struct _GumAllocationGroup GumAllocationGroup;

struct _GumAllocationGroup
{
  guint size;
  guint alive_now;
  guint alive_peak;
  guint total_peak;
};

G_BEGIN_DECLS

GUM_API GumAllocationGroup * gum_allocation_group_new (guint size);
GUM_API GumAllocationGroup * gum_allocation_group_copy (
    const GumAllocationGroup * group);
GUM_API void gum_allocation_group_free (GumAllocationGroup * group);

GUM_API void gum_allocation_group_list_free (GumList * groups);

G_END_DECLS

#endif
