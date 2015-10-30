/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_JSCRIPT_PROCESS_H__
#define __GUM_JSCRIPT_PROCESS_H__

#include "gumjsccore.h"

G_BEGIN_DECLS

typedef struct _GumJscProcess GumJscProcess;
typedef struct _GumJscExceptionHandler GumJscExceptionHandler;

struct _GumJscProcess
{
  GumJscCore * core;

  GumJscExceptionHandler * exception_handler;
};

G_GNUC_INTERNAL void _gum_jsc_process_init (GumJscProcess * self,
    GumJscCore * core, JSObjectRef scope);
G_GNUC_INTERNAL void _gum_jsc_process_dispose (GumJscProcess * self);
G_GNUC_INTERNAL void _gum_jsc_process_finalize (GumJscProcess * self);

G_END_DECLS

#endif
