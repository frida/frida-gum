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

#ifndef __GUM_COBJECT_H__
#define __GUM_COBJECT_H__

#include <gum/gumdefs.h>
#include <gum/gumlist.h>
#include <gum/gumreturnaddress.h>

typedef struct _GumCObject GumCObject;

struct _GumCObject
{
  gpointer address;
  gchar type_name[GUM_MAX_TYPE_NAME + 1];
  GumReturnAddressArray return_addresses;

  /*< private */
  gpointer data;
};

#define GUM_COBJECT(b) ((GumCObject *) (b))

G_BEGIN_DECLS

GUM_API GumCObject * gum_cobject_new (gpointer address,
    const gchar * type_name);
GUM_API GumCObject * gum_cobject_copy (
    const GumCObject * cobject);
GUM_API void gum_cobject_free (GumCObject * cobject);

GUM_API void gum_cobject_list_free (GumList * cobject_list);

G_END_DECLS

#endif
