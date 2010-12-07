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

#include "gumheapapi.h"

typedef enum _GumSanityCheckFlags GumSanityCheckFlags;

typedef struct _GumSanityChecker GumSanityChecker;
typedef struct _GumSanityCheckerPrivate GumSanityCheckerPrivate;

typedef void (* GumSanityOutputFunc) (const gchar * text, gpointer user_data);
typedef void (* GumSanitySequenceFunc) (gpointer user_data);

enum _GumSanityCheckFlags
{
  GUM_CHECK_INSTANCE_LEAKS  = (1 << 0),
  GUM_CHECK_BLOCK_LEAKS     = (1 << 1),
  GUM_CHECK_BOUNDS          = (1 << 2)
};

struct _GumSanityChecker
{
  GumSanityCheckerPrivate * priv;
};

G_BEGIN_DECLS

GUM_API GumSanityChecker * gum_sanity_checker_new (GumSanityOutputFunc func,
    gpointer user_data);
GUM_API GumSanityChecker * gum_sanity_checker_new_with_heap_apis (
    const GumHeapApiList * heap_apis, GumSanityOutputFunc func,
    gpointer user_data);
GUM_API void gum_sanity_checker_destroy (GumSanityChecker * checker);

GUM_API void gum_sanity_checker_enable_backtraces_for_blocks_of_size (
    GumSanityChecker * checker, gint size);

GUM_API gboolean gum_sanity_checker_run (GumSanityChecker * self,
    GumSanitySequenceFunc func, gpointer user_data);

GUM_API void gum_sanity_checker_begin (GumSanityChecker * self, guint flags);
GUM_API gboolean gum_sanity_checker_end (GumSanityChecker * self);

G_END_DECLS

#endif
