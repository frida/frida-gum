/*
 * Copyright (C) 2016-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcodesegment.h"

#ifndef HAVE_DARWIN

#include <gio/gio.h>

gboolean
gum_code_segment_is_supported (void)
{
  return FALSE;
}

GumCodeSegment *
gum_code_segment_new (gsize size,
                      const GumAddressSpec * spec)
{
  return NULL;
}

void
gum_code_segment_free (GumCodeSegment * segment)
{
}

gpointer
gum_code_segment_get_address (GumCodeSegment * self)
{
  return NULL;
}

gsize
gum_code_segment_get_size (GumCodeSegment * self)
{
  return 0;
}

gsize
gum_code_segment_get_virtual_size (GumCodeSegment * self)
{
  return 0;
}

void
gum_code_segment_realize (GumCodeSegment * self)
{
}

void
gum_code_segment_map (GumCodeSegment * self,
                      gsize source_offset,
                      gsize source_size,
                      gpointer target_address)
{
}

gboolean
gum_code_segment_mark (gpointer code,
                       gsize size,
                       GError ** error)
{
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, "Not supported");
  return FALSE;
}

#endif
