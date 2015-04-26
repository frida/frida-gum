/*
 * Copyright (C) 2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_FILE_H__
#define __GUM_SCRIPT_FILE_H__

#include "gumscriptcore.h"

#include <v8.h>

typedef struct _GumScriptFile GumScriptFile;

struct _GumScriptFile
{
  GumScriptCore * core;

  GHashTable * files;
};

G_GNUC_INTERNAL void _gum_script_file_init (GumScriptFile * self,
    GumScriptCore * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_file_realize (GumScriptFile * self);
G_GNUC_INTERNAL void _gum_script_file_dispose (GumScriptFile * self);
G_GNUC_INTERNAL void _gum_script_file_finalize (GumScriptFile * self);

#endif
