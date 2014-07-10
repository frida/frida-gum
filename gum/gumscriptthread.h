/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_THREAD_H__
#define __GUM_SCRIPT_THREAD_H__

#include "gumscriptcore.h"

#include <v8.h>

typedef struct _GumScriptThread GumScriptThread;

struct _GumScriptThread
{
  GumScriptCore * core;
};

G_GNUC_INTERNAL void _gum_script_thread_init (GumScriptThread * self,
    GumScriptCore * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_thread_realize (GumScriptThread * self);
G_GNUC_INTERNAL void _gum_script_thread_dispose (GumScriptThread * self);
G_GNUC_INTERNAL void _gum_script_thread_finalize (GumScriptThread * self);

#endif
