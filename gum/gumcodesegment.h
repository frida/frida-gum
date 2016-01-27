/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_CODE_SEGMENT_H__
#define __GUM_CODE_SEGMENT_H__

#include <gum/gum.h>

G_BEGIN_DECLS

typedef struct _GumCodeSegment GumCodeSegment;

GumCodeSegment * gum_code_segment_new (gsize size, const GumAddressSpec * spec);
void gum_code_segment_free (GumCodeSegment * segment);

gpointer gum_code_segment_get_address (GumCodeSegment * self);
gsize gum_code_segment_get_size (GumCodeSegment * self);
gsize gum_code_segment_get_virtual_size (GumCodeSegment * self);

void gum_code_segment_realize (GumCodeSegment * self);
void gum_code_segment_map (GumCodeSegment * self, gsize source_offset,
    gsize source_size, gpointer target_address);

G_END_DECLS

#endif
