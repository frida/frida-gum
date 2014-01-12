/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#ifndef __GUM_ALLOCATION_BLOCK_H__
#define __GUM_ALLOCATION_BLOCK_H__

#include <gum/gumdefs.h>
#include <gum/gumlist.h>
#include <gum/gumreturnaddress.h>

typedef struct _GumAllocationBlock GumAllocationBlock;

struct _GumAllocationBlock
{
  gpointer address;
  guint size;
  GumReturnAddressArray return_addresses;
};

#define GUM_ALLOCATION_BLOCK(b) ((GumAllocationBlock *) (b))

G_BEGIN_DECLS

GUM_API GumAllocationBlock * gum_allocation_block_new (gpointer address,
    guint size);
GUM_API GumAllocationBlock * gum_allocation_block_copy (
    const GumAllocationBlock * block);
GUM_API void gum_allocation_block_free (GumAllocationBlock * block);

GUM_API void gum_allocation_block_list_free (GumList * block_list);

G_END_DECLS

#endif
