/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
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
