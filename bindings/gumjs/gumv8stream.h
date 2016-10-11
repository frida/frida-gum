/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_V8_STREAM_H__
#define __GUM_V8_STREAM_H__

#include "gumv8core.h"

#include <v8.h>

typedef struct _GumV8Stream GumV8Stream;

struct _GumV8Stream
{
  GumV8Core * core;

  GHashTable * streams;
  GCancellable * cancellable;

  GumPersistent<v8::FunctionTemplate>::type * io_stream;
  GumPersistent<v8::FunctionTemplate>::type * input_stream;
  GumPersistent<v8::FunctionTemplate>::type * output_stream;
};

G_GNUC_INTERNAL void _gum_v8_stream_init (GumV8Stream * self, GumV8Core * core,
    v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_stream_realize (GumV8Stream * self);
G_GNUC_INTERNAL void _gum_v8_stream_flush (GumV8Stream * self);
G_GNUC_INTERNAL void _gum_v8_stream_dispose (GumV8Stream * self);
G_GNUC_INTERNAL void _gum_v8_stream_finalize (GumV8Stream * self);

#endif
