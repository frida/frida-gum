/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_CODE_WRITER_H__
#define __GUM_DUK_CODE_WRITER_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukCodeWriter GumDukCodeWriter;

struct _GumDukCodeWriter
{
  GumDukCore * core;

#include "gumdukcodewriter-fields.inc"
};

G_GNUC_INTERNAL void _gum_duk_code_writer_init (GumDukCodeWriter * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_code_writer_dispose (GumDukCodeWriter * self);
G_GNUC_INTERNAL void _gum_duk_code_writer_finalize (GumDukCodeWriter * self);

#include "gumdukcodewriter-methods.inc"

G_END_DECLS

#endif
