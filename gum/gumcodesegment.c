/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcodesegment.h"

#ifndef HAVE_DARWIN

GumCodeSegment *
gum_code_segment_new (gsize size,
                      const GumAddressSpec * spec)
{
  (void) size;
  (void) spec;

  return NULL;
}

void
gum_code_segment_free (GumCodeSegment * segment)
{
  (void) segment;
}

gpointer
gum_code_segment_get_address (GumCodeSegment * self)
{
  (void) self;

  return NULL;
}

gsize
gum_code_segment_get_size (GumCodeSegment * self)
{
  (void) self;

  return 0;
}

gsize
gum_code_segment_get_virtual_size (GumCodeSegment * self)
{
  (void) self;

  return 0;
}

void
gum_code_segment_realize (GumCodeSegment * self)
{
  (void) self;
}

void
gum_code_segment_map (GumCodeSegment * self,
                      gsize source_offset,
                      gsize source_size,
                      gpointer target_address)
{
  (void) self;
  (void) source_offset;
  (void) source_size;
  (void) target_address;
}

#endif
