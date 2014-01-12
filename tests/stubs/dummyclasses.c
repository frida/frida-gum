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

#include "dummyclasses.h"

G_DEFINE_TYPE (MyPony,   my_pony,   G_TYPE_OBJECT);
G_DEFINE_TYPE (ZooZebra, zoo_zebra, G_TYPE_OBJECT);

static void
my_pony_class_init (MyPonyClass * klass)
{
}

static void
my_pony_init (MyPony * self)
{
}

static void
zoo_zebra_class_init (ZooZebraClass * klass)
{
}

static void
zoo_zebra_init (ZooZebra * self)
{
}
