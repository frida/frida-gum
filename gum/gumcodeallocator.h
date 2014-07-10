/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
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
