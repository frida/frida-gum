/*
 * Copyright (C) 2011 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#ifndef __GUM_GCC_BACKTRACER_H__
#define __GUM_GCC_BACKTRACER_H__

#include <glib-object.h>
#include <gum/gumbacktracer.h>

#define GUM_TYPE_GCC_BACKTRACER (gum_gcc_backtracer_get_type ())
#define GUM_GCC_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_GCC_BACKTRACER, GumGccBacktracer))
#define GUM_GCC_BACKTRACER_CAST(obj) ((GumGccBacktracer *) (obj))
#define GUM_GCC_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass),\
    GUM_TYPE_GCC_BACKTRACER, GumGccBacktracerClass))
#define GUM_IS_GCC_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_GCC_BACKTRACER))
#define GUM_IS_GCC_BACKTRACER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE (\
    (klass), GUM_TYPE_GCC_BACKTRACER))
#define GUM_GCC_BACKTRACER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS (\
    (obj), GUM_TYPE_GCC_BACKTRACER, GumGccBacktracerClass))

typedef struct _GumGccBacktracer GumGccBacktracer;
typedef struct _GumGccBacktracerClass GumGccBacktracerClass;

typedef struct _GumGccBacktracerPrivate GumGccBacktracerPrivate;

struct _GumGccBacktracer
{
  GObject parent;
};

struct _GumGccBacktracerClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType gum_gcc_backtracer_get_type (void) G_GNUC_CONST;

GumBacktracer * gum_gcc_backtracer_new (void);

G_END_DECLS

#endif
