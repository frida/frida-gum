/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummetalarray.h"

#include "gumlibc.h"
#include "gummemory.h"

#include <string.h>

void
gum_metal_array_init (GumMetalArray * array,
                      guint element_size)
{
  array->data = gum_alloc_n_pages (1, GUM_PAGE_RW);
  array->length = 0;
  array->capacity = gum_query_page_size () / element_size;

  array->element_size = element_size;
}

void
gum_metal_array_free (GumMetalArray * array)
{
  array->element_size = 0;

  array->capacity = 0;
  array->length = 0;
  gum_free_pages (array->data);
  array->data = NULL;
}

gpointer
gum_metal_array_element_at (GumMetalArray * self,
                            guint index_)
{
  return ((guint8 *) self->data) + (index_ * self->element_size);
}

gpointer
gum_metal_array_insert_at (GumMetalArray * self,
                           guint index_)
{
  gpointer element;

  gum_metal_array_ensure_capacity (self, self->length + 1);

  element = gum_metal_array_element_at (self, index_);

  gum_memmove (gum_metal_array_element_at (self, index_ + 1), element,
      (self->length - index_) * self->element_size);

  self->length++;

  return element;
}

void
gum_metal_array_remove_at (GumMetalArray * self,
                           guint index_)
{
  if (index_ != self->length - 1)
  {
    gum_memmove (gum_metal_array_element_at (self, index_),
        gum_metal_array_element_at (self, index_ + 1),
        (self->length - index_ - 1) * self->element_size);
  }
  self->length--;
}

gpointer
gum_metal_array_append (GumMetalArray * self)
{
  gum_metal_array_ensure_capacity (self, self->length + 1);

  return gum_metal_array_element_at (self, self->length++);
}

void
gum_metal_array_get_extents (GumMetalArray * self,
                             gpointer * start,
                             gpointer * end)
{
  *start = self->data;
  *end = gum_metal_array_element_at (self, self->capacity);
}

void
gum_metal_array_ensure_capacity (GumMetalArray * self,
                                 guint capacity)
{
  guint size_in_bytes, page_size, size_in_pages;
  gpointer new_data;

  if (self->capacity >= capacity)
    return;

  size_in_bytes = capacity * self->element_size;
  page_size = gum_query_page_size ();
  size_in_pages = size_in_bytes / page_size;
  if (size_in_bytes % page_size != 0)
    size_in_pages++;

  new_data = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  gum_memcpy (new_data, self->data, self->length * self->element_size);

  gum_free_pages (self->data);
  self->data = new_data;
  self->capacity = (size_in_pages * page_size) / self->element_size;
}
