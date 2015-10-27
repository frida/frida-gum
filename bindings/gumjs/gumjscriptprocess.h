/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_PROCESS_H__
#define __GUM_JSCRIPT_PROCESS_H__

#include "gumjscriptcore.h"

G_BEGIN_DECLS

typedef struct _GumScriptProcess GumScriptProcess;
typedef struct _GumScriptExceptionHandler GumScriptExceptionHandler;

struct _GumScriptProcess
{
  GumScriptCore * core;

  GumScriptExceptionHandler * exception_handler;
};

G_GNUC_INTERNAL void _gum_script_process_init (GumScriptProcess * self,
    GumScriptCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_script_process_dispose (GumScriptProcess * self);
G_GNUC_INTERNAL void _gum_script_process_finalize (GumScriptProcess * self);

G_END_DECLS

#endif
