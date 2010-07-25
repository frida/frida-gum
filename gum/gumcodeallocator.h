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

#ifndef __GUM_CODE_ALLOCATOR_H__
#define __GUM_CODE_ALLOCATOR_H__

#include "gumlist.h"

typedef struct _GumCodeAllocator GumCodeAllocator;
typedef struct _GumCodeSlice GumCodeSlice;

struct _GumCodeAllocator
{
  GumList * pages;
  gsize page_size;
  guint header_size;
  guint slice_size;
  guint slices_per_page;
};

struct _GumCodeSlice
{
  gpointer data;
  guint size;
};

void gum_code_allocator_init (GumCodeAllocator * allocator, guint slice_size);
void gum_code_allocator_free (GumCodeAllocator * allocator);

GumCodeSlice * gum_code_allocator_new_slice_near (GumCodeAllocator * self, gpointer address);
void gum_code_allocator_free_slice (GumCodeAllocator * self, GumCodeSlice * slice);

#endif
