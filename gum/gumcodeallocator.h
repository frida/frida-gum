/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_CODE_ALLOCATOR_H__
#define __GUM_CODE_ALLOCATOR_H__

#include "gumlist.h"
#include "gummemory.h"

typedef struct _GumCodeAllocator GumCodeAllocator;
typedef struct _GumCodeSlice GumCodeSlice;
typedef struct _GumCodeDeflector GumCodeDeflector;

struct _GumCodeAllocator
{
  GumList * pages;
  GumList * dispatchers;
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

struct _GumCodeDeflector
{
  gpointer return_address;
  gpointer target;
  gpointer trampoline;
};

void gum_code_allocator_init (GumCodeAllocator * allocator, guint slice_size);
void gum_code_allocator_free (GumCodeAllocator * allocator);

GumCodeSlice * gum_code_allocator_alloc_slice (GumCodeAllocator * self);
GumCodeSlice * gum_code_allocator_try_alloc_slice_near (GumCodeAllocator * self,
    const GumAddressSpec * spec, gsize alignment);
void gum_code_allocator_free_slice (GumCodeAllocator * self,
    GumCodeSlice * slice);

GumCodeDeflector * gum_code_allocator_alloc_deflector (GumCodeAllocator * self,
    const GumAddressSpec * caller, gpointer return_address, gpointer target);
void gum_code_allocator_free_deflector (GumCodeAllocator * self,
    GumCodeDeflector * deflector);

#endif
