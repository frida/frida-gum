/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_CODE_ALLOCATOR_H__
#define __GUM_CODE_ALLOCATOR_H__

#include "gummemory.h"

typedef struct _GumCodeAllocator GumCodeAllocator;
typedef struct _GumCodeSlice GumCodeSlice;
typedef struct _GumCodeDeflector GumCodeDeflector;

struct _GumCodeAllocator
{
  gsize slice_size;
  gsize slices_per_page;
  gsize pages_metadata_size;

  GSList * uncommitted_pages;
  GList * free_slices;

  GSList * dispatchers;
};

struct _GumCodeSlice
{
  gpointer data;
  gsize size;
};

struct _GumCodeDeflector
{
  gpointer return_address;
  gpointer target;
  gpointer trampoline;
};

void gum_code_allocator_init (GumCodeAllocator * allocator, gsize slice_size);
void gum_code_allocator_free (GumCodeAllocator * allocator);

GumCodeSlice * gum_code_allocator_alloc_slice (GumCodeAllocator * self);
GumCodeSlice * gum_code_allocator_try_alloc_slice_near (GumCodeAllocator * self,
    const GumAddressSpec * spec, gsize alignment);
void gum_code_slice_free (GumCodeSlice * slice);
void gum_code_allocator_commit (GumCodeAllocator * self);

GumCodeDeflector * gum_code_allocator_alloc_deflector (GumCodeAllocator * self,
    const GumAddressSpec * caller, gpointer return_address, gpointer target);
void gum_code_allocator_free_deflector (GumCodeAllocator * self,
    GumCodeDeflector * deflector);

#endif
