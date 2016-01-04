/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUKRIPT_FILE_H__
#define __GUM_DUKRIPT_FILE_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukFile GumDukFile;

struct _GumDukFile
{
  GumDukCore * core;

  GumDukHeapPtr file;
};

G_GNUC_INTERNAL void _gum_duk_file_init (GumDukFile * self,
    GumDukCore * core);
G_GNUC_INTERNAL void _gum_duk_file_dispose (GumDukFile * self);
G_GNUC_INTERNAL void _gum_duk_file_finalize (GumDukFile * self);

G_END_DECLS

#endif
