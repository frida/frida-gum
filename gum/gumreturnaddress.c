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

#include "gumreturnaddress.h"
#include "gumsymbolutil.h"

#include <string.h>

static gboolean gum_return_address_has_symbols_loaded (
    const GumReturnAddress * addr);

gboolean
gum_return_address_array_is_equal (const GumReturnAddressArray * array1,
                                   const GumReturnAddressArray * array2)
{
  guint i;

  if (array1->len != array2->len)
    return FALSE;

  for (i = 0; i < array1->len; i++)
  {
    if (!gum_return_address_is_equal (&array1->items[i], &array2->items[i]))
      return FALSE;
  }

  return TRUE;
}

void
gum_return_address_array_load_symbols (GumReturnAddressArray * array)
{
  guint i;

  for (i = 0; i < array->len; i++)
    gum_return_address_load_symbols (&array->items[i]);
}

gboolean
gum_return_address_is_equal (const GumReturnAddress * addr1,
                             const GumReturnAddress * addr2)
{
  if (addr1->address != addr2->address)
    return FALSE;

  if (strcmp (addr1->module_name, addr2->module_name) != 0)
    return FALSE;

  if (strcmp (addr1->function_name, addr2->function_name) != 0)
    return FALSE;

  if (strcmp (addr1->file_name, addr2->file_name) != 0)
    return FALSE;

  if (addr1->line_number != addr2->line_number)
    return FALSE;

  return TRUE;
}

void
gum_return_address_load_symbols (GumReturnAddress * addr)
{
  GumSymbolDetails details;

  if (gum_return_address_has_symbols_loaded (addr))
    return;

  if (gum_symbol_details_from_address (addr->address, &details))
  {
    strcpy (addr->module_name, details.module_name);
    strcpy (addr->function_name, details.symbol_name);
    strcpy (addr->file_name, details.file_name);
    addr->line_number = details.line_number;
  }
}

gboolean
gum_return_address_has_symbols_loaded (const GumReturnAddress * addr)
{
  return (*addr->module_name != '\0' && *addr->function_name != '\0'
      && *addr->file_name != '\0' && addr->line_number != 0);
}
