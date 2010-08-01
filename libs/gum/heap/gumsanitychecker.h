/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#ifndef __GUM_SANITY_CHECKER_H__
#define __GUM_SANITY_CHECKER_H__

#include <gum/gumdefs.h>

typedef struct _GumSanityChecker GumSanityChecker;
typedef struct _GumSanityCheckerPrivate GumSanityCheckerPrivate;

typedef void (* GumSanityOutputFunc) (const gchar * text, gpointer user_data);
typedef void (* GumSanitySequenceFunc) (gpointer user_data);

struct _GumSanityChecker
{
  GumSanityCheckerPrivate * priv;
};

G_BEGIN_DECLS

GUM_API GumSanityChecker * gum_sanity_checker_new (GumSanityOutputFunc func,
    gpointer user_data);
GUM_API void gum_sanity_checker_destroy (GumSanityChecker * checker);

GUM_API gboolean gum_sanity_checker_run (GumSanityChecker * self,
    GumSanitySequenceFunc func, gpointer user_data);

G_END_DECLS

#endif
