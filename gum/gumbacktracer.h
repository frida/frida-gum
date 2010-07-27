/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#ifndef __GUM_BACKTRACER_H__
#define __GUM_BACKTRACER_H__

#include <glib-object.h>
#include <gum/gumdefs.h>
#include <gum/gumreturnaddress.h>

#define GUM_TYPE_BACKTRACER (gum_backtracer_get_type ())
#define GUM_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_BACKTRACER, GumBacktracer))
#define GUM_BACKTRACER_CAST(obj) ((GumBacktracer *) (obj))
#define GUM_IS_BACKTRACER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_BACKTRACER))
#define GUM_BACKTRACER_GET_INTERFACE(inst) (G_TYPE_INSTANCE_GET_INTERFACE (\
    (inst), GUM_TYPE_BACKTRACER, GumBacktracerIface))

typedef struct _GumBacktracer GumBacktracer;
typedef struct _GumBacktracerIface GumBacktracerIface;

struct _GumBacktracerIface
{
  GTypeInterface parent;

  void (*generate) (GumBacktracer * self, const GumCpuContext * cpu_context,
      GumReturnAddressArray * return_addresses);
};

G_BEGIN_DECLS

GType gum_backtracer_get_type (void);

GUM_API GumBacktracer * gum_backtracer_make_default (void);

GUM_API void gum_backtracer_generate (GumBacktracer * self,
    const GumCpuContext * cpu_context,
    GumReturnAddressArray * return_addresses);

G_END_DECLS

#endif
