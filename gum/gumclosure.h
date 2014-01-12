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

#ifndef __GUM_CLOSURE_H__
#define __GUM_CLOSURE_H__

#include <glib-object.h>
#include <gum/gumdefs.h>

G_BEGIN_DECLS

typedef struct _GumClosure GumClosure;

typedef void (* GumClosureTarget) (void);
#define GUM_CLOSURE_TARGET(f) ((GumClosureTarget) f)

GUM_API GumClosure * gum_closure_new (GumCallingConvention conv,
    GumClosureTarget target, GVariant * args);
GUM_API void gum_closure_free (GumClosure * closure);

GUM_API void gum_closure_invoke (GumClosure * closure);

G_END_DECLS

#endif
