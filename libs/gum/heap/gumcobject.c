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

#include "gumcobject.h"
#include "gummemory.h"
#include "gumreturnaddress.h"

#include <string.h>

GumCObject *
gum_cobject_new (gpointer address,
                 const gchar * type_name)
{
  GumCObject * cobject;

  cobject = gum_malloc (sizeof (GumCObject));
  cobject->address = address;
  g_strlcpy (cobject->type_name, type_name, sizeof (cobject->type_name));
  cobject->return_addresses.len = 0;
  cobject->data = NULL;

  return cobject;
}

GumCObject *
gum_cobject_copy (const GumCObject * cobject)
{
  GumCObject * copy;

  copy = gum_malloc (sizeof (GumCObject));
  memcpy (copy, cobject, sizeof (GumCObject));

  return copy;
}

void
gum_cobject_free (GumCObject * cobject)
{
  gum_free (cobject);
}

void
gum_cobject_list_free (GumList * cobject_list)
{
  GumList * walk;

  for (walk = cobject_list; walk != NULL; walk = walk->next)
  {
    GumCObject * cobject = walk->data;
    gum_cobject_free (cobject);
  }

  gum_list_free (cobject_list);
}
