/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_FILE_H__
#define __GUM_JSCRIPT_FILE_H__

#include "gumjsccore.h"

G_BEGIN_DECLS

typedef struct _GumJscFile GumJscFile;

struct _GumJscFile
{
  GumJscCore * core;

  JSClassRef file;
};

G_GNUC_INTERNAL void _gum_jsc_file_init (GumJscFile * self,
    GumJscCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_jsc_file_dispose (GumJscFile * self);
G_GNUC_INTERNAL void _gum_jsc_file_finalize (GumJscFile * self);

G_END_DECLS

#endif
