/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
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
