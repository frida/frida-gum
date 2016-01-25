/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DARWIN_JIT_H__
#define __GUM_DARWIN_JIT_H__

#include <gum/gum.h>

G_BEGIN_DECLS

typedef struct _GumDarwinCodeSegment GumDarwinCodeSegment;

GumDarwinCodeSegment * gum_darwin_code_segment_new (gsize size);
GumDarwinCodeSegment * gum_darwin_code_segment_ref (
    GumDarwinCodeSegment * segment);
void gum_darwin_code_segment_unref (GumDarwinCodeSegment * segment);

gpointer gum_darwin_code_segment_get_address (GumDarwinCodeSegment * self);

void gum_darwin_code_segment_realize (GumDarwinCodeSegment * self);

G_END_DECLS

#endif
