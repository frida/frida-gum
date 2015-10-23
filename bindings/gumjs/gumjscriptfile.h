/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_FILE_H__
#define __GUM_JSCRIPT_FILE_H__

#include "gumjscriptcore.h"

G_BEGIN_DECLS

typedef struct _GumScriptFile GumScriptFile;

struct _GumScriptFile
{
  GumScriptCore * core;

  JSClassRef file;
};

G_GNUC_INTERNAL void _gum_script_file_init (GumScriptFile * self,
    GumScriptCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_file_dispose (GumScriptFile * self);
G_GNUC_INTERNAL void _gum_script_file_finalize (GumScriptFile * self);

G_END_DECLS

#endif
