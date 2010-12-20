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

#ifndef __GUM_MEMORY_PRIV_H__
#define __GUM_MEMORY_PRIV_H__

#include <gum/gumdefs.h>

typedef struct _GumMatchToken GumMatchToken;
typedef enum _GumMatchType GumMatchType;

struct _GumMatchPattern
{
  GPtrArray * tokens;
  guint size;
};

enum _GumMatchType
{
  GUM_MATCH_EXACT,
  GUM_MATCH_WILDCARD
};

struct _GumMatchToken
{
  GumMatchType type;
  GArray * bytes;
  guint offset;
};

G_BEGIN_DECLS

G_GNUC_INTERNAL void _gum_memory_init (void);
G_GNUC_INTERNAL void _gum_memory_deinit (void);

G_END_DECLS

#endif
