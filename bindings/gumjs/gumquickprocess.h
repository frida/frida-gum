/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_PROCESS_H__
#define __GUM_QUICK_PROCESS_H__

#include "gumquickcore.h"
#include "gumquickmodule.h"

G_BEGIN_DECLS

typedef struct _GumQuickProcess GumQuickProcess;
typedef struct _GumQuickExceptionHandler GumQuickExceptionHandler;

struct _GumQuickProcess
{
  GumQuickModule * module;
  GumQuickCore * core;

  GumQuickExceptionHandler * exception_handler;
};

G_GNUC_INTERNAL void _gum_quick_process_init (GumQuickProcess * self,
    JSValue ns, GumQuickModule * module, GumQuickCore * core);
G_GNUC_INTERNAL void _gum_quick_process_flush (GumQuickProcess * self);
G_GNUC_INTERNAL void _gum_quick_process_dispose (GumQuickProcess * self);
G_GNUC_INTERNAL void _gum_quick_process_finalize (GumQuickProcess * self);

G_END_DECLS

#endif
