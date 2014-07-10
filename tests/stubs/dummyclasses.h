/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
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
