/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SCRIPT_PROCESS_H__
#define __GUM_SCRIPT_PROCESS_H__

#include "gumscriptcore.h"

#include <v8.h>

typedef struct _GumScriptProcess GumScriptProcess;
typedef struct _GumScriptExceptionHandler GumScriptExceptionHandler;

struct _GumScriptProcess
{
  GumScriptCore * core;

  GumScriptExceptionHandler * exception_handler;
};

G_GNUC_INTERNAL void _gum_script_process_init (GumScriptProcess * self,
    GumScriptCore * core, v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_process_realize (GumScriptProcess * self);
G_GNUC_INTERNAL void _gum_script_process_dispose (GumScriptProcess * self);
G_GNUC_INTERNAL void _gum_script_process_finalize (GumScriptProcess * self);

#endif
