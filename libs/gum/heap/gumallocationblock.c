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

#include "gumallocationblock.h"

#include "gummemory.h"
#include "gumreturnaddress.h"

#include <string.h>

GumAllocationBlock *
gum_allocation_block_new (gpointer address,
                          guint size)
{
  GumAllocationBlock * block;

  block = gum_malloc (sizeof (GumAllocationBlock));
  block->address = address;
  block->size = size;
  block->return_addresses.len = 0;

  return block;
}

GumAllocationBlock *
gum_allocation_block_copy (const GumAllocationBlock * block)
{
  GumAllocationBlock * copy;

  copy = gum_malloc (sizeof (GumAllocationBlock));
  memcpy (copy, block, sizeof (GumAllocationBlock));

  return copy;
}

void
gum_allocation_block_free (GumAllocationBlock * block)
{
  gum_free (block);
}

void
gum_allocation_block_list_free (GumList * block_list)
{
  GumList * cur;

  for (cur = block_list; cur != NULL; cur = cur->next)
  {
    GumAllocationBlock * block = cur->data;
    gum_allocation_block_free (block);
  }

  gum_list_free (block_list);
}
