/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_STREAM_H__
#define __GUM_DUK_STREAM_H__

#include "gumdukobject.h"

G_BEGIN_DECLS

typedef struct _GumDukStream GumDukStream;

struct _GumDukStream
{
  GumDukCore * core;

  GumDukObjectManager objects;

  GumDukHeapPtr io_stream;
  GumDukHeapPtr input_stream;
  GumDukHeapPtr output_stream;
};

G_GNUC_INTERNAL void _gum_duk_stream_init (GumDukStream * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_stream_flush (GumDukStream * self);
G_GNUC_INTERNAL void _gum_duk_stream_dispose (GumDukStream * self);
G_GNUC_INTERNAL void _gum_duk_stream_finalize (GumDukStream * self);

G_END_DECLS

#endif
