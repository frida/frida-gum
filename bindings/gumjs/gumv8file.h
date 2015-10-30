/*
 * Copyright (C) 2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_FILE_H__
#define __GUM_SCRIPT_FILE_H__

#include "gumv8core.h"

#include <v8.h>

typedef struct _GumV8File GumV8File;

struct _GumV8File
{
  GumV8Core * core;

  GHashTable * files;
};

G_GNUC_INTERNAL void _gum_v8_file_init (GumV8File * self,
    GumV8Core * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_v8_file_realize (GumV8File * self);
G_GNUC_INTERNAL void _gum_v8_file_dispose (GumV8File * self);
G_GNUC_INTERNAL void _gum_v8_file_finalize (GumV8File * self);

#endif
