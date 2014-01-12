/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

gboolean
gum_return_address_details_from_address (GumReturnAddress address,
                                         GumReturnAddressDetails * details)
{
  GumSymbolDetails sd;

  if (gum_symbol_details_from_address (address, &sd))
  {
    details->address = address;

    strcpy (details->module_name, sd.module_name);
    strcpy (details->function_name, sd.symbol_name);
    strcpy (details->file_name, sd.file_name);
    details->line_number = sd.line_number;

    return TRUE;
  }

  return FALSE;
}

gboolean
gum_return_address_array_is_equal (const GumReturnAddressArray * array1,
                                   const GumReturnAddressArray * array2)
{
  guint i;

  if (array1->len != array2->len)
    return FALSE;

  for (i = 0; i < array1->len; i++)
  {
    if (array1->items[i] != array2->items[i])
      return FALSE;
  }

  return TRUE;
}
