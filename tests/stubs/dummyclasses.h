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

#ifndef __DUMMY_CLASSES_H__
#define __DUMMY_CLASSES_H__

#include <glib-object.h>

typedef struct _MyPonyClass MyPonyClass;
typedef struct _MyPony MyPony;

typedef struct _ZooZebraClass ZooZebraClass;
typedef struct _ZooZebra ZooZebra;

struct _MyPonyClass
{
  GObjectClass parent_class;
};

struct _MyPony
{
  GObject parent;
};

struct _ZooZebraClass
{
  GObjectClass parent_class;
};

struct _ZooZebra
{
  GObject parent;
};

#define MY_TYPE_PONY      (my_pony_get_type ())
#define MY_PONY(object)   (G_TYPE_CHECK_INSTANCE_CAST ((object), MY_TYPE_PONY,\
    MyPony))

#define ZOO_TYPE_ZEBRA    (zoo_zebra_get_type ())
#define ZOO_ZEBRA(object) (G_TYPE_CHECK_INSTANCE_CAST ((object),\
    ZOO_TYPE_ZEBRA, ZooZebra))

G_BEGIN_DECLS

GType my_pony_get_type (void) G_GNUC_CONST;
GType zoo_zebra_get_type (void) G_GNUC_CONST;

G_END_DECLS

#endif
